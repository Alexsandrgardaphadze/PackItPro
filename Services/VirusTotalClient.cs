// VirusTotalClient.cs
#nullable enable
using PackItPro;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
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
        public async Task<VirusScanResult> ScanFileAsync(string filePath, string apiKey, bool onlyScanExecutables = true, int minDetectionsToFlag =1)
        {
            if (onlyScanExecutables && !IsExecutableExtension(filePath))
            {
                // NEW: Convert byte[] hash to string for storage/reporting
                var fileHashBytes = FileHasher.ComputeFileHash(filePath);
                var fileHashString = BitConverter.ToString(fileHashBytes).Replace("-", "").ToLowerInvariant();
                return new VirusScanResult
                {
                    FileHash = fileHashString, // Store as string
                    Positives =0,
                    TotalScans =0,
                    ScanDate = DateTime.UtcNow,
                    Error = "Skipped (Not Executable)",
                    IsInfected = false // Skipped files are not infected
                };
            }

            // NEW: Convert byte[] hash to string for API calls and storage
            string hash = BitConverter.ToString(FileHasher.ComputeFileHash(filePath)).Replace("-", "").ToLowerInvariant();
            VirusScanResult result;

            // Safely handle cached entries that might be null
            if (_scanCache.TryGetValue(hash, out var cachedResult) && cachedResult != null)
            {
                result = cachedResult;
            }
            else
            {
                await _scanSemaphore.WaitAsync();
                try
                {
                    // NEW: Use SemaphoreSlim for rate limiting, await the permit
                    await _rateLimitSemaphore.WaitAsync();

                    try
                    {
                        result = await QueryVirusTotalAsync(filePath, hash, apiKey);
                        // Only cache non-null results
                        if (result != null)
                        {
                            _scanCache[hash] = result; // Cache the result (using the string hash as the key)
                        }
                    }
                    finally
                    {
                        // NEW: Always release the rate limit permit
                        _rateLimitSemaphore.Release();
                    }
                }
                finally
                {
                    _scanSemaphore.Release();
                }
            }

            // Determine if it's infected based on the result and settings
            result ??= new VirusScanResult { FileHash = hash, Positives = 0, TotalScans = 0, ScanDate = DateTime.UtcNow, IsInfected = false };
            result.IsInfected = result.Positives >= minDetectionsToFlag;
            return result;
        }

        // NEW: Internal method for API calls
        private async Task<VirusScanResult> QueryVirusTotalAsync(string filePath, string hash, string apiKey)
        {
            // Ensure API key is set for this call if passed
            // In QueryVirusTotalAsync: safely read existing header values
            string? existingApiKey = null;
            if (_httpClient.DefaultRequestHeaders.TryGetValues("x-apikey", out var vals))
            {
                existingApiKey = vals.FirstOrDefault();
            }

            if (apiKey != existingApiKey)
            {
                _httpClient.DefaultRequestHeaders.Remove("x-apikey");
                if (!string.IsNullOrEmpty(apiKey))
                {
                    _httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
                }
            }

            try
            {
                var reportResponse = await _httpClient.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hash}");

                if (reportResponse.IsSuccessStatusCode)
                {
                    var report = await reportResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>()
                    ?? throw new InvalidDataException("Invalid VirusTotal response");

                    if (report.Data?.Attributes?.LastAnalysisStats == null)
                        throw new InvalidDataException("Missing analysis data in VirusTotal response");
                    return new VirusScanResult
                    {
                        FileHash = hash, // Return the string hash
                        Positives = report.Data.Attributes.LastAnalysisStats.Malicious,
                        TotalScans = report.Data.Attributes.LastAnalysisStats.Total,
                        ScanDate = DateTime.UtcNow
                    };
                }

                // File not previously scanned, upload it
                using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                using var formData = new MultipartFormDataContent();
                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                var uploadResponse = await _httpClient.PostAsync(
                    "https://www.virustotal.com/api/v3/files", formData);
                uploadResponse.EnsureSuccessStatusCode();

                var uploadResult = await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>();
                if (uploadResult?.Data?.Id == null)
                    throw new InvalidDataException("VirusTotal upload response missing analysis ID");

                var analysisId = uploadResult.Data.Id;

                // Poll for results
                for (int i =0; i <10; i++)
                {
                    await Task.Delay(5000);
                    var analysisResponse = await _httpClient.GetAsync(
                        $"https://www.virustotal.com/api/v3/analyses/{analysisId}");

                    if (analysisResponse.IsSuccessStatusCode)
                    {
                        var analysis = await analysisResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>();
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
                        // Optionally, handle incomplete analysis data here
                    }
                }

                throw new TimeoutException("VirusTotal analysis timed out");
            }
            catch (Exception ex)
            {
                LogError("VirusTotal query failed", ex);
                // NEW: Ensure FileHash is a string even on error
                return new VirusScanResult
                {
                    FileHash = hash, // Use the string hash passed in
                    Positives =0,
                    TotalScans =0,
                    Error = ex.Message,
                    ScanDate = DateTime.UtcNow,
                    IsInfected = false // Error does not imply infection
                };
            }
        }

        // REMOVED: ComputeSHA256 method (moved to FileHasher)
        // REMOVED: ComputeDirectoryHash method (moved to FileHasher)
        // REMOVED: ComputeFileHash method (moved to FileHasher)


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
                        // NEW: The cache file should contain string hashes, which are the keys
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

        // NEW: Log helper specific to this class (optional, could use global one)
        private void LogError(string message, Exception ex)
        {
            // Could use the global LogError from MainWindow or a dedicated logger
            // For now, using Debug.WriteLine or Console if needed for debugging this class.
            Debug.WriteLine($"[VirusTotalClient] ERROR: {message}\n{ex}");
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimitSemaphore?.Dispose();
            _scanSemaphore?.Dispose();
        }
    }

    // Model classes for VirusTotal API responses (kept here or could be shared)
    public class VirusScanResult
    {
        public string FileHash { get; set; } = string.Empty; // Must be string for API interaction and caching keys
        public int Positives { get; set; }
        public int TotalScans { get; set; }
        public DateTime ScanDate { get; set; } = DateTime.UtcNow;
        public string? Error { get; set; }
        // NEW: Add IsInfected property here, calculated by the client
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