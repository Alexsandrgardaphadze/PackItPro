// PackItPro/Services/VirusTotalClient.cs
#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public class VirusTotalClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _rateLimitSemaphore = new(4, 4);
        private readonly SemaphoreSlim _scanSemaphore = new(4);
        private readonly ConcurrentDictionary<string, VirusScanResult> _scanCache = new();
        private readonly string _cacheFilePath;
        private readonly HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
            ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
            ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf"
        };

        public VirusTotalClient(string cacheFilePath, string apiKey = "")
        {
            _cacheFilePath = cacheFilePath;
            _httpClient = new HttpClient();
            if (!string.IsNullOrEmpty(apiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }
        }

        public void SetApiKey(string apiKey)
        {
            _httpClient.DefaultRequestHeaders.Clear();
            if (!string.IsNullOrEmpty(apiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }
        }

        public bool IsExecutableExtension(string filePath) =>
            _executableExtensions.Contains(Path.GetExtension(filePath));

        public async Task<VirusScanResult> ScanFileAsync(
            string filePath,
            string apiKey,
            bool onlyScanExecutables = true,
            int minDetectionsToFlag = 1,
            CancellationToken cancellationToken = default)
        {
            if (onlyScanExecutables && !IsExecutableExtension(filePath))
            {
                var fileHashString = ComputeFileHashString(filePath);
                return new VirusScanResult
                {
                    FileHash = fileHashString,
                    Positives = 0,
                    TotalScans = 0,
                    ScanDate = DateTime.UtcNow,
                    Error = "Skipped (Not Executable)",
                    IsInfected = false
                };
            }

            string hash = ComputeFileHashString(filePath);
            if (_scanCache.TryGetValue(hash, out var cachedResult) && cachedResult != null)
            {
                return new VirusScanResult
                {
                    FileHash = hash,
                    Positives = cachedResult.Positives,
                    TotalScans = cachedResult.TotalScans,
                    ScanDate = cachedResult.ScanDate,
                    Error = cachedResult.Error,
                    IsInfected = cachedResult.Positives >= minDetectionsToFlag
                };
            }

            await _scanSemaphore.WaitAsync(cancellationToken);
            try
            {
                await _rateLimitSemaphore.WaitAsync(cancellationToken);
                try
                {
                    var result = await QueryVirusTotalAsync(filePath, hash, apiKey, cancellationToken);
                    result.IsInfected = result.Positives >= minDetectionsToFlag;
                    _scanCache[hash] = result;
                    return result;
                }
                finally
                {
                    _rateLimitSemaphore.Release();
                }
            }
            finally
            {
                _scanSemaphore.Release();
            }
        }

        private async Task<VirusScanResult> QueryVirusTotalAsync(string filePath, string hash, string apiKey, CancellationToken cancellationToken = default)
        {
            // FIXED: Remove extra spaces in URLs
            var reportResponse = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}", cancellationToken);

            if (reportResponse.IsSuccessStatusCode)
            {
                var report = await reportResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>(cancellationToken: cancellationToken)
                    ?? throw new InvalidDataException("Invalid VirusTotal response");

                if (report.Data?.Attributes?.LastAnalysisStats == null)
                    throw new InvalidDataException("Missing analysis data in VirusTotal response");

                return new VirusScanResult
                {
                    FileHash = hash,
                    Positives = report.Data.Attributes.LastAnalysisStats.Malicious,
                    TotalScans = report.Data.Attributes.LastAnalysisStats.Total,
                    ScanDate = DateTime.UtcNow
                };
            }

            // Upload file
            using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
            using var formData = new MultipartFormDataContent();
            formData.Add(fileContent, "file", Path.GetFileName(filePath));

            var uploadResponse = await _httpClient.PostAsync("https://www.virustotal.com/api/v3/files", formData, cancellationToken);
            uploadResponse.EnsureSuccessStatusCode();

            var uploadResult = await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>(cancellationToken: cancellationToken);
            if (uploadResult?.Data?.Id == null)
                throw new InvalidDataException("VirusTotal upload response missing analysis ID");

            var analysisId = uploadResult.Data.Id;

            // Poll for results
            for (int i = 0; i < 10; i++)
            {
                await Task.Delay(5000, cancellationToken);
                var analysisResponse = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/analyses/{analysisId}", cancellationToken);

                if (analysisResponse.IsSuccessStatusCode)
                {
                    var analysis = await analysisResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>(cancellationToken: cancellationToken);
                    if (analysis?.Data?.Attributes?.LastAnalysisStats != null)
                    {
                        return new VirusScanResult
                        {
                            FileHash = hash,
                            Positives = analysis.Data.Attributes.LastAnalysisStats.Malicious,
                            TotalScans = analysis.Data.Attributes.LastAnalysisStats.Total,
                            ScanDate = DateTime.UtcNow
                        };
                    }
                }
            }

            throw new TimeoutException("VirusTotal analysis timed out");
        }

        private string ComputeFileHashString(string filePath)
        {
            var hashBytes = FileHasher.ComputeFileHash(filePath);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        public async Task LoadCacheAsync()
        {
            if (File.Exists(_cacheFilePath))
            {
                var cacheJson = await File.ReadAllTextAsync(_cacheFilePath);
                var cache = JsonSerializer.Deserialize<List<VirusScanResult>>(cacheJson);
                if (cache != null)
                {
                    foreach (var item in cache)
                    {
                        _scanCache[item.FileHash] = item;
                    }
                }
            }
        }

        public async Task SaveCacheAsync()
        {
            var dirPath = Path.GetDirectoryName(_cacheFilePath);
            if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
            {
                Directory.CreateDirectory(dirPath);
            }
            var cacheList = _scanCache.Values.ToList();
            var cacheJson = JsonSerializer.Serialize(cacheList, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_cacheFilePath, cacheJson);
        }

        public void ClearCache() => _scanCache.Clear();

        private void LogError(string message, Exception ex)
        {
            Debug.WriteLine($"[VirusTotalClient] ERROR: {message}\n{ex}");
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimitSemaphore?.Dispose();
            _scanSemaphore?.Dispose();
        }
    }

    // Models (unchanged - keep as-is)
    public class VirusScanResult
    {
        public string FileHash { get; set; } = string.Empty;
        public int Positives { get; set; }
        public int TotalScans { get; set; }
        public DateTime ScanDate { get; set; } = DateTime.UtcNow;
        public string? Error { get; set; }
        public bool IsInfected { get; set; } = false;
    }

    public class VirusTotalFileReport
    {
        public VirusTotalFileData? Data { get; set; }
    }

    public class VirusTotalFileData
    {
        public string? Id { get; set; }
        public VirusTotalFileAttributes? Attributes { get; set; }
    }

    public class VirusTotalFileAttributes
    {
        public VirusTotalAnalysisStats? LastAnalysisStats { get; set; }
    }

    public class VirusTotalAnalysisStats
    {
        public int Malicious { get; set; }
        public int Total { get; set; }
    }

    public class VirusTotalUploadResponse
    {
        public VirusTotalUploadData? Data { get; set; }
    }

    public class VirusTotalUploadData
    {
        public string? Id { get; set; }
    }
}