#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public class VirusTotalClient : IDisposable
    {
        private static readonly TimeSpan RequestDelay = TimeSpan.FromSeconds(16);
        private static readonly TimeSpan PollDelay = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan CacheExpiry = TimeSpan.FromHours(24);
        private const int MaxPollAttempts = 12;
        private const long MaxUploadBytes = 32 * 1024 * 1024;

        private readonly HttpClient _http;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly ConcurrentDictionary<string, CachedScanResult> _cache = new();
        private readonly string _cacheFilePath;

        private readonly HashSet<string> _exeExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
            ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
            ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf",
        };

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = true,
        };

        // Cache file uses default naming (PascalCase) since it's our own format.
        private static readonly JsonSerializerOptions _cacheJsonOpts = new()
        {
            WriteIndented = true,
        };

        public VirusTotalClient(string cacheFilePath, string apiKey = "")
        {
            _cacheFilePath = cacheFilePath;
            _http = new HttpClient
            {
                BaseAddress = new Uri("https://www.virustotal.com/api/v3/"),
                Timeout = TimeSpan.FromMinutes(10),
            };
            ApplyKey(apiKey);
        }

        public void SetApiKey(string key)
        {
            _http.DefaultRequestHeaders.Remove("x-apikey");
            ApplyKey(key);
        }

        private void ApplyKey(string key)
        {
            if (!string.IsNullOrWhiteSpace(key))
                _http.DefaultRequestHeaders.Add("x-apikey", key);
        }

        public bool IsExecutable(string filePath) =>
            _exeExtensions.Contains(Path.GetExtension(filePath));

        // ── Public API ────────────────────────────────────────────────────────

        /// <param name="trustedEngines">
        ///   Engines considered authoritative. A single detection from any of these
        ///   forces IsInfected=true and sets FlaggedByTrustedEngine regardless of
        ///   minDetectionsToFlag. Pass null to skip trusted-engine logic.
        /// </param>
        /// <param name="trustStore">
        ///   If supplied and the file hash is in the store, returns Clean immediately
        ///   without hitting the VT API (user-trusted false positive).
        /// </param>
        public async Task<VirusScanResult> ScanFileAsync(
            string filePath,
            string apiKey,
            bool onlyScanExecutables = true,
            int minDetectionsToFlag = 3,
            CancellationToken ct = default,
            IReadOnlyList<string>? trustedEngines = null,
            TrustStore? trustStore = null)
        {
            if (onlyScanExecutables && !IsExecutable(filePath))
                return Skipped(filePath, "Skipped — not an executable");

            SetApiKey(apiKey);
            string hash = FileHasher.ComputeFileHashString(filePath);

            if (trustStore != null && trustStore.IsTrusted(hash))
                return TrustedFalsePositive(hash);

            if (_cache.TryGetValue(hash, out var cached) &&
                DateTime.UtcNow - cached.CachedAt < CacheExpiry)
            {
                return ApplyThreshold(cached.Result, minDetectionsToFlag, trustedEngines);
            }

            var result = await ScanInternalAsync(filePath, hash, ct);
            _cache[hash] = new CachedScanResult { Result = result, CachedAt = DateTime.UtcNow };
            return ApplyThreshold(result, minDetectionsToFlag, trustedEngines);
        }

        // ── Core scan logic ───────────────────────────────────────────────────

        private async Task<VirusScanResult> ScanInternalAsync(
            string filePath, string hash, CancellationToken ct)
        {
            var hashResult = await TryHashLookupAsync(hash, ct);
            if (hashResult != null)
                return hashResult;

            long fileSize = new FileInfo(filePath).Length;
            if (fileSize > MaxUploadBytes)
            {
                return new VirusScanResult
                {
                    FileHash = hash,
                    ScanDate = DateTime.UtcNow,
                    Error = $"File too large ({FormatBytes(fileSize)}) for VT free tier " +
                                $"(max {FormatBytes(MaxUploadBytes)}). Hash not found in VT database.",
                    IsInfected = false,
                };
            }

            string? analysisId = await UploadFileAsync(filePath, hash, fileSize, ct);

            if (analysisId == null)
            {
                var retryResult = await TryHashLookupAsync(hash, ct);
                if (retryResult != null)
                    return retryResult;

                return new VirusScanResult
                {
                    FileHash = hash,
                    ScanDate = DateTime.UtcNow,
                    Error = "File queued by VT but analysis not yet available. Try again in a few minutes.",
                    IsInfected = false,
                };
            }

            return await PollAnalysisAsync(analysisId, hash, filePath, ct);
        }

        private async Task<VirusScanResult?> TryHashLookupAsync(string hash, CancellationToken ct)
        {
            return await GatedRequestAsync(async () =>
            {
                var r = await _http.GetAsync($"files/{hash}", ct);

                if (r.StatusCode == System.Net.HttpStatusCode.NotFound)
                    return null;

                if (!r.IsSuccessStatusCode)
                    throw new HttpRequestException(
                        $"VT hash lookup failed: {(int)r.StatusCode} {r.ReasonPhrase}");

                var report = await r.Content
                    .ReadFromJsonAsync<VtFileReport>(_jsonOpts, cancellationToken: ct);

                if (report?.Data?.Attributes == null)
                    return null;

                var stats = report.Data.Attributes.LastAnalysisStats;
                var engines = report.Data.Attributes.LastAnalysisResults;

                return stats != null
                    ? MakeResult(hash, stats, engines)
                    : null;
            }, ct);
        }

        private async Task<string?> UploadFileAsync(
            string filePath, string hash, long fileSize, CancellationToken ct)
        {
            return await GatedRequestAsync(async () =>
            {
                await using var stream = File.OpenRead(filePath);
                using var fileContent = new StreamContent(stream);
                using var form = new MultipartFormDataContent();
                form.Add(fileContent, "file", Path.GetFileName(filePath));

                var resp = await _http.PostAsync("files", form, ct);

                if (resp.StatusCode == System.Net.HttpStatusCode.Conflict)
                    return null;

                if (resp.StatusCode == System.Net.HttpStatusCode.RequestEntityTooLarge)
                    throw new InvalidOperationException(
                        $"VT rejected upload (413). File: {FormatBytes(fileSize)}. Free tier limit is 32 MB.");

                resp.EnsureSuccessStatusCode();

                var upload = await resp.Content
                    .ReadFromJsonAsync<VtUploadResponse>(_jsonOpts, cancellationToken: ct);

                return upload?.Data?.Id
                    ?? throw new InvalidDataException("VT upload response missing analysis ID.");
            }, ct);
        }

        private async Task<VirusScanResult> PollAnalysisAsync(
            string analysisId, string hash, string filePath, CancellationToken ct)
        {
            for (int i = 0; i < MaxPollAttempts; i++)
            {
                await Task.Delay(PollDelay, ct);

                var pollResult = await GatedRequestAsync(async () =>
                {
                    var r = await _http.GetAsync($"analyses/{analysisId}", ct);

                    if (!r.IsSuccessStatusCode)
                    {
                        if (r.StatusCode == System.Net.HttpStatusCode.NotFound)
                            return null;
                        throw new HttpRequestException(
                            $"VT polling failed: {(int)r.StatusCode} {r.ReasonPhrase}");
                    }

                    var analysis = await r.Content
                        .ReadFromJsonAsync<VtAnalysisResponse>(_jsonOpts, cancellationToken: ct);

                    if (analysis?.Data?.Attributes?.Status != "completed")
                        return null;

                    var s = analysis.Data.Attributes.Stats;
                    var e = analysis.Data.Attributes.Results;
                    return s != null ? MakeResult(hash, s, e) : null;
                }, ct);

                if (pollResult != null)
                    return pollResult;
            }

            return new VirusScanResult
            {
                FileHash = hash,
                ScanDate = DateTime.UtcNow,
                Error = $"VT analysis timed out after {MaxPollAttempts} polls ({MaxPollAttempts * 15}s).",
                IsInfected = false,
            };
        }

        // ── Threshold + trusted-engine logic ─────────────────────────────────

        /// <summary>
        /// Applies detection threshold AND trusted-engine override to a raw result.
        ///
        /// Rules in order:
        ///   1. If any trusted engine flagged the file → IsInfected=true, FlaggedByTrustedEngine=true.
        ///      This cannot be suppressed by MinimumDetectionsToFlag or the trust store.
        ///   2. If Positives >= minDetectionsToFlag → IsInfected=true (normal threshold).
        ///   3. Otherwise → IsInfected=false.
        /// </summary>
        private static VirusScanResult ApplyThreshold(
            VirusScanResult r,
            int minDetectionsToFlag,
            IReadOnlyList<string>? trustedEngines)
        {
            string? flaggingEngine = null;

            if (trustedEngines != null && r.EngineResults.Count > 0)
            {
                foreach (var engine in trustedEngines)
                {
                    if (r.EngineResults.TryGetValue(engine, out var engineResult) &&
                        engineResult.Category is "malicious" or "suspicious")
                    {
                        flaggingEngine = engine;
                        break;
                    }
                }
            }

            bool trustedEngineHit = flaggingEngine != null;
            bool thresholdHit = r.Positives >= minDetectionsToFlag;

            return new VirusScanResult
            {
                FileHash = r.FileHash,
                Positives = r.Positives,
                TotalScans = r.TotalScans,
                ScanDate = r.ScanDate,
                Error = r.Error,
                IsInfected = trustedEngineHit || thresholdHit,
                FlaggedByTrustedEngine = trustedEngineHit,
                TrustedEngineName = flaggingEngine,
                EngineResults = r.EngineResults,
            };
        }

        // ── Gate ──────────────────────────────────────────────────────────────

        private async Task<T> GatedRequestAsync<T>(Func<Task<T>> request, CancellationToken ct)
        {
            await _gate.WaitAsync(ct);
            try
            {
                return await request();
            }
            finally
            {
                _gate.Release();
                // Delay AFTER releasing the gate so it doesn't block cancellation.
                // Use CancellationToken.None so the delay runs even on cancel — we
                // still owe VT the inter-request gap to avoid 429s on the next call.
                try { await Task.Delay(RequestDelay, CancellationToken.None); }
                catch (OperationCanceledException) { /* app is shutting down — ignore */ }
            }
        }

        // ── Cache ─────────────────────────────────────────────────────────────

        public async Task LoadCacheAsync(ILogService? log = null)
        {
            log ??= NullLogService.Instance;
            if (!File.Exists(_cacheFilePath)) return;
            try
            {
                var json = await File.ReadAllTextAsync(_cacheFilePath);
                var items = JsonSerializer.Deserialize<List<CachedScanResult>>(json, _cacheJsonOpts);
                if (items == null) return;

                var cutoff = DateTime.UtcNow - CacheExpiry;
                int loaded = 0;
                foreach (var item in items.Where(i => i.CachedAt > cutoff))
                {
                    _cache[item.Result.FileHash] = item;
                    loaded++;
                }
                log.Info($"[VT] Loaded {loaded} cache entries (expired entries discarded).");
            }
            catch (Exception ex)
            {
                log.Warning($"[VT] Cache load failed: {ex.Message}");
            }
        }

        public async Task SaveCacheAsync(ILogService? log = null)
        {
            log ??= NullLogService.Instance;
            try
            {
                var dir = Path.GetDirectoryName(_cacheFilePath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(_cache.Values.ToList(), _cacheJsonOpts);
                await File.WriteAllTextAsync(_cacheFilePath, json);
                log.Info($"[VT] Cache saved ({_cache.Count} entries).");
            }
            catch (Exception ex)
            {
                log.Warning($"[VT] Cache save failed: {ex.Message}");
            }
        }

        public void ClearCache() => _cache.Clear();

        // ── Helpers ───────────────────────────────────────────────────────────

        private static VirusScanResult MakeResult(
            string hash,
            VtAnalysisStats s,
            Dictionary<string, VtEngineResult>? engines) => new()
            {
                FileHash = hash,
                Positives = s.Malicious,
                TotalScans = s.Total,
                ScanDate = DateTime.UtcNow,
                EngineResults = engines ?? new(),
            };

        private static VirusScanResult TrustedFalsePositive(string hash) => new()
        {
            FileHash = hash,
            ScanDate = DateTime.UtcNow,
            IsInfected = false,
            IsTrustedFalsePositive = true,
        };

        private static VirusScanResult Skipped(string filePath, string reason) => new()
        {
            FileHash = Path.GetFileName(filePath),
            ScanDate = DateTime.UtcNow,
            Error = reason,
            IsInfected = false,
        };

        private static string FormatBytes(long bytes)
        {
            string[] s = { "B", "KB", "MB", "GB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < s.Length - 1) { v /= 1024; i++; }
            return $"{v:0.##} {s[i]}";
        }

        public void Dispose()
        {
            _http.Dispose();
            _gate.Dispose();
        }
    }

    // ── Result models ─────────────────────────────────────────────────────────

    public class VirusScanResult
    {
        public string FileHash { get; set; } = "";
        public int Positives { get; set; }
        public int TotalScans { get; set; }
        public DateTime ScanDate { get; set; } = DateTime.UtcNow;
        public string? Error { get; set; }
        public bool IsInfected { get; set; }

        /// <summary>True when a trusted engine (Microsoft, Kaspersky, etc.) flagged this file.</summary>
        public bool FlaggedByTrustedEngine { get; set; }

        /// <summary>Name of the trusted engine that flagged the file, or null.</summary>
        public string? TrustedEngineName { get; set; }

        /// <summary>
        /// True when the user has pre-marked this hash as a false positive in TrustStore.
        /// Lets the command handler skip the "User-trusted" sentinel string check.
        /// </summary>
        public bool IsTrustedFalsePositive { get; set; }

        /// <summary>Per-engine results — key is engine name, value is its verdict.</summary>
        public Dictionary<string, VtEngineResult> EngineResults { get; set; } = new();
    }

    public class CachedScanResult
    {
        public VirusScanResult Result { get; set; } = new();
        public DateTime CachedAt { get; set; } = DateTime.UtcNow;
    }

    public class VtEngineResult
    {
        public string? Category { get; set; }  // "malicious", "suspicious", "undetected", "harmless"
        public string? EngineName { get; set; }
        public string? Result { get; set; }    // threat name e.g. "Trojan.Rozena"
    }

    // ── VT API response models ────────────────────────────────────────────────

    internal class VtFileReport
    {
        public VtFileData? Data { get; set; }
    }
    internal class VtFileData
    {
        public string? Id { get; set; }
        public VtFileAttributes? Attributes { get; set; }
    }
    internal class VtFileAttributes
    {
        public VtAnalysisStats? LastAnalysisStats { get; set; }
        public Dictionary<string, VtEngineResult>? LastAnalysisResults { get; set; }
    }

    internal class VtAnalysisResponse
    {
        public VtAnalysisData? Data { get; set; }
    }
    internal class VtAnalysisData
    {
        public VtAnalysisAttributes? Attributes { get; set; }
    }
    internal class VtAnalysisAttributes
    {
        public string? Status { get; set; }
        public VtAnalysisStats? Stats { get; set; }
        public Dictionary<string, VtEngineResult>? Results { get; set; }
    }

    internal class VtAnalysisStats
    {
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Undetected { get; set; }
        public int Harmless { get; set; }
        public int Timeout { get; set; }

        [JsonIgnore]
        public int Total => Malicious + Suspicious + Undetected + Harmless + Timeout;
    }

    internal class VtUploadResponse
    {
        public VtUploadData? Data { get; set; }
    }
    internal class VtUploadData
    {
        public string? Id { get; set; }
    }
}