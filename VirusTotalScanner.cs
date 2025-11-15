using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro
{
    public class VirusTotalScanner : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly ConcurrentDictionary<string, VirusScanResult> _cache;
        private readonly SemaphoreSlim _rateLimiter = new(4, 4);
        private string _apiKey;

        public VirusTotalScanner(string apiKey, ConcurrentDictionary<string, VirusScanResult> cache)
        {
            _apiKey = apiKey;
            _cache = cache;
            _httpClient = new HttpClient();
        }

        public async Task<VirusScanResult> ScanFileAsync(string filePath)
        {
            string hash = ComputeSHA256(filePath);

            if (_cache.TryGetValue(hash, out var cachedResult))
                return cachedResult;

            await _rateLimiter.WaitAsync();
            try
            {
                var result = await QueryVirusTotal(filePath, hash);
                _cache[hash] = result;
                return result;
            }
            finally
            {
                _rateLimiter.Release();
            }
        }

        private async Task<VirusScanResult> QueryVirusTotal(string filePath, string hash)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);

                var reportResponse = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/files/{hash}");

                if (reportResponse.IsSuccessStatusCode)
                {
                    var report = await reportResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>()
                        ?? throw new InvalidDataException("Invalid VirusTotal response");

                    if (report.Data?.Attributes?.LastAnalysisStats == null)
                        throw new InvalidDataException("Missing analysis data");

                    return new VirusScanResult
                    {
                        FileHash = hash,
                        Positives = report.Data.Attributes.LastAnalysisStats.Malicious,
                        TotalScans = report.Data.Attributes.LastAnalysisStats.Total,
                        ScanDate = DateTime.UtcNow
                    };
                }

                // Upload file for scanning
                using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                using var formData = new MultipartFormDataContent();
                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                var uploadResponse = await _httpClient.PostAsync("https://www.virustotal.com/api/v3/files", formData);
                uploadResponse.EnsureSuccessStatusCode();

                var uploadResult = await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>()
                    ?? throw new InvalidDataException("Invalid upload response");

                var analysisId = uploadResult.Data?.Id
                    ?? throw new InvalidDataException("Missing analysis ID");

                // Poll for results
                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(5000);
                    var analysisResponse = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/analyses/{analysisId}");

                    if (analysisResponse.IsSuccessStatusCode)
                    {
                        var analysis = await analysisResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>()
                            ?? throw new InvalidDataException("Invalid analysis response");

                        if (analysis.Data?.Attributes?.LastAnalysisStats == null)
                            throw new InvalidDataException("Missing analysis data");

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

        private string ComputeSHA256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimiter?.Dispose();
        }
    }

    #region VirusTotal API Models
    public class VirusTotalFileReport
    {
        [JsonPropertyName("data")]
        public VirusTotalFileData? Data { get; set; }
    }

    public class VirusTotalFileData
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("attributes")]
        public VirusTotalFileAttributes? Attributes { get; set; }
    }

    public class VirusTotalFileAttributes
    {
        [JsonPropertyName("last_analysis_stats")]
        public VirusTotalAnalysisStats? LastAnalysisStats { get; set; }
    }

    public class VirusTotalAnalysisStats
    {
        [JsonPropertyName("malicious")]
        public int Malicious { get; set; }

        [JsonPropertyName("suspicious")]
        public int Suspicious { get; set; }

        [JsonPropertyName("undetected")]
        public int Undetected { get; set; }

        [JsonPropertyName("harmless")]
        public int Harmless { get; set; }

        [JsonPropertyName("timeout")]
        public int Timeout { get; set; }

        public int Total => Malicious + Suspicious + Undetected + Harmless + Timeout;
    }

    public class VirusTotalUploadResponse
    {
        [JsonPropertyName("data")]
        public VirusTotalUploadData? Data { get; set; }
    }

    public class VirusTotalUploadData
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }
    }
    #endregion
}