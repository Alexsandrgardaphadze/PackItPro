// VirusTotalClient.cs
#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro
{
    // NEW: Separate class for VirusTotal operations
    public class VirusTotalClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _rateLimitSemaphore = new(4, 4); // Allow 4 concurrent requests
        private readonly SemaphoreSlim _scanSemaphore = new(4); // For overall scan concurrency if needed elsewhere
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
            _httpClient.DefaultRequestHeaders.Clear(); // Clear old headers
            if (!string.IsNullOrEmpty(apiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }
        }

        public bool IsExecutableExtension(string filePath)
        {
            return _executableExtensions.Contains(Path.GetExtension(filePath));
        }

        // NEW: Method to scan a single file
        public async Task<VirusScanResult> ScanFileAsync(string filePath, string apiKey, bool onlyScanExecutables = true, int minDetectionsToFlag = 1)
        {
            if (onlyScanExecutables && !IsExecutableExtension(filePath))
            {
                return new VirusScanResult
                {
                    FileHash = ComputeSHA256(filePath), // Still compute hash for potential cache consistency, though not scanned
                    Positives = 0,
                    TotalScans = 0,
                    ScanDate = DateTime.UtcNow,
                    Error = "Skipped (Not Executable)"
                };
            }

            string hash = ComputeSHA256(filePath);
            VirusScanResult result;

            if (_scanCache.TryGetValue(hash, out var cachedResult))
            {
                result = cachedResult;
            }
            else
            {
                await _scanSemaphore.WaitAsync();
                try
                {
                    await _rateLimitSemaphore.WaitAsync();

                    try
                    {
                        result = await QueryVirusTotalAsync(filePath, hash, apiKey);
                        _scanCache[hash] = result; // Cache the result
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

            // Determine if it's infected based on the result and settings
            result.IsInfected = result.Positives >= minDetectionsToFlag;
            return result;
        }

        // NEW: Internal method for API calls
        private async Task<VirusScanResult> QueryVirusTotalAsync(string filePath, string hash, string apiKey)
        {
            // Ensure API key is set for this call if passed
            if (apiKey != _httpClient.DefaultRequestHeaders.GetValues("x-apikey").FirstOrDefault())
            {
                _httpClient.DefaultRequestHeaders.Remove("x-apikey");
                _httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            try
            {
                // 1. Try fetching report by hash first
                var reportResponse = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}");

                if (reportResponse.IsSuccessStatusCode)
                {
                    var report = await reportResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>()
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

                // 2. If not found, upload the file
                using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                using var formData = new MultipartFormDataContent();
                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                var uploadResponse = await _httpClient.PostAsync("https://www.virustotal.com/api/v3/files", formData);
                uploadResponse.EnsureSuccessStatusCode();

                var uploadResult = await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>()
                    ?? throw new InvalidDataException("Invalid VirusTotal upload response");

                var analysisId = uploadResult.Data?.Id
                    ?? throw new InvalidDataException("Missing analysis ID in VirusTotal upload response");

                // 3. Poll for analysis results
                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(5000);
                    var analysisResponse = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/analyses/{analysisId}");

                    if (analysisResponse.IsSuccessStatusCode)
                    {
                        var analysis = await analysisResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>()
                            ?? throw new InvalidDataException("Invalid VirusTotal analysis response");

                        if (analysis.Data?.Attributes?.LastAnalysisStats == null)
                            throw new InvalidDataException("Missing analysis data in VirusTotal analysis response");

                        return new VirusScanResult
                        {
                            FileHash = hash,
                            Positives = analysis.Data.Attributes.LastAnalysisStats.Malicious,
                            TotalScans = analysis.Data.Attributes.LastAnalysisStats.Total,
                            ScanDate = DateTime.UtcNow
                        };
                    }
                }

                throw new TimeoutException("VirusTotal analysis timed out");
            }
            catch (Exception ex)
            {
                // Log or handle specific errors if needed
                return new VirusScanResult
                {
                    FileHash = hash,
                    Positives = 0,
                    TotalScans = 0,
                    Error = ex.Message,
                    ScanDate = DateTime.UtcNow
                };
            }
        }

        // NEW: Helper method to compute SHA256
        private string ComputeSHA256(string filePath)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }

        // NEW: Method to load cache from file
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

        // NEW: Method to save cache to file
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

        // NEW: Clear the in-memory cache
        public void ClearCache()
        {
            _scanCache.Clear();
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimitSemaphore?.Dispose();
            _scanSemaphore?.Dispose();
        }
    }
}