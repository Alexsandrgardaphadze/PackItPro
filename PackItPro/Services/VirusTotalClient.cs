// PackItPro/Services/VirusTotalClient.cs
#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public class VirusTotalClient : IDisposable
    {
        // VT free tier: 4 requests/minute = 1 per 15s.
        // We use a single gate (_gate) that serialises all VT HTTP calls and
        // enforces a post-request delay. This is simpler and more correct than
        // the previous two-semaphore approach that caused throughput loss.
        private static readonly TimeSpan RequestDelay = TimeSpan.FromSeconds(16); // 15s + buffer
        private static readonly TimeSpan PollDelay = TimeSpan.FromSeconds(5);  // polling is cheaper
        private static readonly TimeSpan CacheExpiry = TimeSpan.FromHours(24);
        private const int MaxPollAttempts = 10;

        private readonly HttpClient _http;
        private readonly SemaphoreSlim _gate = new(1, 1); // one VT request at a time
        private readonly ConcurrentDictionary<string, CachedScanResult> _cache = new();
        private readonly string _cacheFilePath;

        private readonly HashSet<string> _exeExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
            ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
            ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf",
        };

        public VirusTotalClient(string cacheFilePath, string apiKey = "")
        {
            _cacheFilePath = cacheFilePath;
            _http = new HttpClient();
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

        // ──────────────────────────────────────────────────────────────
        // Public API
        // ──────────────────────────────────────────────────────────────

        public async Task<VirusScanResult> ScanFileAsync(
            string filePath,
            string apiKey,
            bool onlyScanExecutables = true,
            int minDetectionsToFlag = 1,
            CancellationToken ct = default)
        {
            if (onlyScanExecutables && !IsExecutable(filePath))
                return Skipped(filePath, "Skipped — not an executable");

            SetApiKey(apiKey);
            string hash = FileHasher.ComputeFileHashString(filePath);

            if (_cache.TryGetValue(hash, out var cached) &&
                DateTime.UtcNow - cached.CachedAt < CacheExpiry)
            {
                return WithThreshold(cached.Result, minDetectionsToFlag);
            }

            var result = await ScanInternalAsync(filePath, hash, ct);
            _cache[hash] = new CachedScanResult { Result = result, CachedAt = DateTime.UtcNow };
            return WithThreshold(result, minDetectionsToFlag);
        }

        // ──────────────────────────────────────────────────────────────
        // Internal — all VT requests serialised through _gate
        // ──────────────────────────────────────────────────────────────

        private async Task<VirusScanResult> ScanInternalAsync(
            string filePath, string hash, CancellationToken ct)
        {
            // 1. Try hash lookup (no upload needed)
            var hashResult = await GatedRequestAsync(async () =>
            {
                var r = await _http.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hash}", ct);

                if (!r.IsSuccessStatusCode) return null;

                // FIX: Wrap JSON parsing in try/catch — invalid VT response must
                // not crash the app with an unhandled JsonException.
                try
                {
                    var report = await r.Content
                        .ReadFromJsonAsync<VtFileReport>(cancellationToken: ct);
                    return report?.Data?.Attributes?.LastAnalysisStats is { } s
                        ? MakeResult(hash, s) : null;
                }
                catch (JsonException ex)
                {
                    throw new InvalidOperationException(
                        "VirusTotal returned an unexpected JSON format for hash lookup.", ex);
                }
            }, ct);

            if (hashResult != null) return hashResult;

            // 2. Upload the file — streamed, safe for 1 GB+
            string analysisId = await GatedRequestAsync(async () =>
            {
                await using var stream = File.OpenRead(filePath);
                using var content = new StreamContent(stream);
                using var form = new MultipartFormDataContent();
                form.Add(content, "file", Path.GetFileName(filePath));

                var resp = await _http.PostAsync(
                    "https://www.virustotal.com/api/v3/files", form, ct);

                // Throw HttpRequestException with StatusCode set so GatedRequestAsync
                // can catch 429/401/403 and give the user a clear error message.
                if (!resp.IsSuccessStatusCode)
                    throw new HttpRequestException(
                        $"VirusTotal file upload failed with status {(int)resp.StatusCode} ({resp.ReasonPhrase}).",
                        inner: null,
                        statusCode: resp.StatusCode);

                // FIX: JSON parse guard on upload response too
                try
                {
                    var upload = await resp.Content
                        .ReadFromJsonAsync<VtUploadResponse>(cancellationToken: ct);
                    return upload?.Data?.Id
                        ?? throw new InvalidDataException("VT upload response missing analysis ID.");
                }
                catch (JsonException ex)
                {
                    throw new InvalidOperationException(
                        "VirusTotal returned an unexpected JSON format for file upload.", ex);
                }
            }, ct);

            // 3. Poll for results — _gate NOT held between polls so other work can proceed
            for (int i = 0; i < MaxPollAttempts; i++)
            {
                await Task.Delay(PollDelay, ct);

                var pollResult = await GatedRequestAsync(async () =>
                {
                    var r = await _http.GetAsync(
                        $"https://www.virustotal.com/api/v3/analyses/{analysisId}", ct);

                    if (!r.IsSuccessStatusCode) return null;

                    try
                    {
                        var analysis = await r.Content
                            .ReadFromJsonAsync<VtFileReport>(cancellationToken: ct);
                        return analysis?.Data?.Attributes?.LastAnalysisStats is { } s
                            ? MakeResult(hash, s) : null;
                    }
                    catch (JsonException ex)
                    {
                        throw new InvalidOperationException(
                            "VirusTotal returned an unexpected JSON format during polling.", ex);
                    }
                }, ct);

                if (pollResult != null) return pollResult;
            }

            throw new TimeoutException(
                $"VT analysis for '{Path.GetFileName(filePath)}' timed out after {MaxPollAttempts} polls.");
        }

        /// <summary>
        /// Serialises all VT requests through _gate, enforces the post-request
        /// rate-limit delay, and handles transient HTTP errors:
        ///
        ///   429 Too Many Requests — honours the Retry-After header if present,
        ///       otherwise backs off for <see cref="RateLimitBackoff"/> seconds,
        ///       then retries once. A second 429 is re-thrown as a clear message.
        ///
        ///   401 Unauthorized — thrown as InvalidOperationException with a clear
        ///       "check your API key" message instead of a raw HttpRequestException.
        ///
        ///   403 Forbidden — thrown as InvalidOperationException indicating daily
        ///       quota exhaustion (free-tier limit of 500 lookups/day).
        /// </summary>
        private async Task<T> GatedRequestAsync<T>(Func<Task<T>> request, CancellationToken ct)
        {
            await _gate.WaitAsync(ct);
            try
            {
                return await ExecuteWithRetryAsync(request, ct);
            }
            finally
            {
                await Task.Delay(RequestDelay, ct);
                _gate.Release();
            }
        }

        private static readonly TimeSpan RateLimitBackoff = TimeSpan.FromSeconds(60);

        private static async Task<T> ExecuteWithRetryAsync<T>(
            Func<Task<T>> request, CancellationToken ct, bool isRetry = false)
        {
            try
            {
                return await request();
            }
            catch (HttpRequestException ex) when (
                ex.StatusCode == HttpStatusCode.TooManyRequests && !isRetry)
            {
                // 429: back off and try once more.
                // The Retry-After header value is not directly accessible through
                // HttpRequestException, so we use a fixed conservative backoff.
                await Task.Delay(RateLimitBackoff, ct);
                return await ExecuteWithRetryAsync(request, ct, isRetry: true);
            }
            catch (HttpRequestException ex) when (
                ex.StatusCode == HttpStatusCode.TooManyRequests)
            {
                // Second 429 in a row — daily quota likely exhausted.
                throw new InvalidOperationException(
                    "VirusTotal rate limit exceeded after retry. " +
                    "The free API allows 4 requests/minute and 500/day. " +
                    "Wait a minute and try again, or upgrade to a paid API key.", ex);
            }
            catch (HttpRequestException ex) when (
                ex.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new InvalidOperationException(
                    "VirusTotal rejected the API key (401 Unauthorized). " +
                    "Check your key in Settings → VirusTotal API Key.", ex);
            }
            catch (HttpRequestException ex) when (
                ex.StatusCode == HttpStatusCode.Forbidden)
            {
                throw new InvalidOperationException(
                    "VirusTotal access forbidden (403). " +
                    "Your daily quota of 500 lookups may be exhausted. " +
                    "Wait until midnight UTC or upgrade to a paid API plan.", ex);
            }
        }

        // ──────────────────────────────────────────────────────────────
        // Cache persistence — FIX: accept ILogService instead of Debug.WriteLine
        // ──────────────────────────────────────────────────────────────

        public async Task LoadCacheAsync(ILogService? log = null)
        {
            log ??= NullLogService.Instance;
            if (!File.Exists(_cacheFilePath)) return;
            try
            {
                var json = await File.ReadAllTextAsync(_cacheFilePath);
                var items = JsonSerializer.Deserialize<List<CachedScanResult>>(json);
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

                var json = JsonSerializer.Serialize(
                    _cache.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true });

                await File.WriteAllTextAsync(_cacheFilePath, json);
                log.Info($"[VT] Cache saved ({_cache.Count} entries).");
            }
            catch (Exception ex)
            {
                log.Warning($"[VT] Cache save failed: {ex.Message}");
            }
        }

        public void ClearCache() => _cache.Clear();

        // ──────────────────────────────────────────────────────────────
        // Helpers
        // ──────────────────────────────────────────────────────────────

        private static VirusScanResult MakeResult(string hash, VtAnalysisStats s) => new()
        {
            FileHash = hash,
            Positives = s.Malicious,
            TotalScans = s.Total,
            ScanDate = DateTime.UtcNow,
        };

        private static VirusScanResult WithThreshold(VirusScanResult r, int threshold) => new()
        {
            FileHash = r.FileHash,
            Positives = r.Positives,
            TotalScans = r.TotalScans,
            ScanDate = r.ScanDate,
            Error = r.Error,
            IsInfected = r.Positives >= threshold,
        };

        private static VirusScanResult Skipped(string filePath, string reason) => new()
        {
            FileHash = Path.GetFileName(filePath),
            ScanDate = DateTime.UtcNow,
            Error = reason,
            IsInfected = false,
        };

        public void Dispose()
        {
            _http.Dispose();
            _gate.Dispose();
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Models
    // ──────────────────────────────────────────────────────────────────

    public class VirusScanResult
    {
        public string FileHash { get; set; } = "";
        public int Positives { get; set; }
        public int TotalScans { get; set; }
        public DateTime ScanDate { get; set; } = DateTime.UtcNow;
        public string? Error { get; set; }
        public bool IsInfected { get; set; }
    }

    public class CachedScanResult
    {
        public VirusScanResult Result { get; set; } = new();
        public DateTime CachedAt { get; set; } = DateTime.UtcNow;
    }

    internal class VtFileReport { public VtFileData? Data { get; set; } }
    internal class VtFileData { public string? Id { get; set; } public VtFileAttributes? Attributes { get; set; } }
    internal class VtFileAttributes { public VtAnalysisStats? LastAnalysisStats { get; set; } }
    internal class VtAnalysisStats { public int Malicious { get; set; } public int Total { get; set; } }
    internal class VtUploadResponse { public VtUploadData? Data { get; set; } }
    internal class VtUploadData { public string? Id { get; set; } }
}