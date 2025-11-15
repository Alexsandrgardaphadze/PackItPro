// VirusTotalClient.cs
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
                    Error = "Skipped (Not Executable)",
                    IsInfected = false // Skipped files are not infected
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
                    // NEW: Use SemaphoreSlim for rate limiting, await the permit
                    await _rateLimitSemaphore.WaitAsync();

                    try
                    {
                        result = await QueryVirusTotalAsync(filePath, hash, apiKey);
                        _scanCache[hash] = result; // Cache the result
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
                var reportResponse = await _httpClient.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hash}"); // Fixed URL

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

                // File not previously scanned, upload it
                using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                using var formData = new MultipartFormDataContent();
                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                var uploadResponse = await _httpClient.PostAsync(
                    "https://www.virustotal.com/api/v3/files", formData); // Fixed URL
                uploadResponse.EnsureSuccessStatusCode();

                var analysisId = (await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>()).Data.Id;

                // Poll for results
                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(5000);
                    var analysisResponse = await _httpClient.GetAsync(
                        $"https://www.virustotal.com/api/v3/analyses/{analysisId}"); // Fixed URL

                    if (analysisResponse.IsSuccessStatusCode)
                    {
                        var analysis = await analysisResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>();
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
                LogError("VirusTotal query failed", ex);
                return new VirusScanResult
                {
                    FileHash = hash,
                    Positives = 0,
                    TotalScans = 0,
                    Error = ex.Message,
                    ScanDate = DateTime.UtcNow,
                    IsInfected = false // Error does not imply infection
                };
            }
        }

        private string ComputeSHA256(string filePath)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }

        // NEW: Helper method to compute directory hash (if needed elsewhere, e.g., for integrity check in packaging)
        // This can be moved to a utility class if used frequently outside VirusTotal context.
        public static byte[] ComputeDirectoryHash(string directoryPath)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var fileHashes = new List<byte[]>();

            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.OrdinalIgnoreCase); // Sort filenames to ensure consistent order

            foreach (var filePath in files)
            {
                var fileContentHash = ComputeFileHash(filePath);
                var relativePath = Path.GetRelativePath(directoryPath, filePath).ToLowerInvariant();
                var pathBytes = System.Text.Encoding.UTF8.GetBytes(relativePath);

                using var tempStream = new MemoryStream();
                tempStream.Write(pathBytes, 0, pathBytes.Length);
                tempStream.Write(fileContentHash, 0, fileContentHash.Length);
                tempStream.Position = 0;

                var combinedHash = sha256.ComputeHash(tempStream);
                fileHashes.Add(combinedHash);
            }

            fileHashes.Sort((x, y) => Comparer<byte[]>.Default.Compare(x, y));

            using var finalStream = new MemoryStream();
            foreach (var hash in fileHashes)
            {
                finalStream.Write(hash, 0, hash.Length);
            }
            finalStream.Position = 0;

            return sha256.ComputeHash(finalStream);
        }

        private static byte[] ComputeFileHash(string filePath)
        {
            using var fileStream = File.OpenRead(filePath);
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            return sha256.ComputeHash(fileStream);
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
        public string FileHash { get; set; } = string.Empty;
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