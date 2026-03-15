// PackItPro/Services/UpdateService.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public class UpdateService
    {
        private const string RepoOwner = "Alexsandrgardaphadze";
        private const string RepoName = "PackItPro";
        private const string ApiUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases?per_page=30";
        private const string ReleasesUrl = $"https://github.com/{RepoOwner}/{RepoName}/releases/latest";

        // Name of the asset we look for in each GitHub release.
        // Must match exactly what build.ps1 / CI uploads as the release asset.
        private const string PrimaryAssetName = "PackItPro.exe";

        private const int DownloadBufferSize = 81920; // 80 KB chunks

        private readonly HttpClient _http;

        // ---- Version --------------------------------------------------------

        public static string CurrentVersion
        {
            get
            {
                var v = Assembly.GetExecutingAssembly().GetName().Version;
                return v != null ? $"v{v.Major}.{v.Minor}.{v.Build}" : "v0.0.0";
            }
        }

        public UpdateService(HttpClient http)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            if (!_http.DefaultRequestHeaders.Contains("User-Agent"))
                _http.DefaultRequestHeaders.Add("User-Agent", $"PackItPro/{CurrentVersion}");
        }

        // ---- Check ----------------------------------------------------------

        /// <summary>
        /// Queries GitHub for the latest stable release.
        /// Never throws -- all errors are captured in the returned result.
        /// </summary>
        public async Task<UpdateCheckResult> CheckAsync(CancellationToken ct = default)
        {
            try
            {
                var releases = await _http.GetFromJsonAsync<List<GitHubRelease>>(ApiUrl, ct);

                if (releases == null || releases.Count == 0)
                    return UpdateCheckResult.NoReleasesYet();

                var stable = releases
                    .Where(r => !r.Draft && !r.Prerelease)
                    .Where(r => !string.IsNullOrWhiteSpace(r.TagName))
                    .OrderByDescending(r => ParseVersion(r.TagName!))
                    .FirstOrDefault();

                if (stable == null)
                    return UpdateCheckResult.NoReleasesYet();

                bool isNewer = IsNewerVersion(stable.TagName!, CurrentVersion);

                return new UpdateCheckResult
                {
                    Success = true,
                    UpdateAvailable = isNewer,
                    LatestVersion = stable.TagName,
                    CurrentVersion = CurrentVersion,
                    ReleaseUrl = stable.HtmlUrl ?? ReleasesUrl,
                    ReleaseNotes = stable.Body,
                    PublishedAt = stable.PublishedAt,
                    DownloadUrl = ResolveDownloadUrl(stable),
                };
            }
            catch (OperationCanceledException) { throw; }
            catch (HttpRequestException ex) when (ex.Message.Contains("404"))
            {
                return UpdateCheckResult.NoReleasesYet();
            }
            catch (HttpRequestException ex)
            {
                return UpdateCheckResult.Error(
                    $"Could not reach GitHub: {ex.Message}\n\nCheck your internet connection.");
            }
            catch (Exception ex)
            {
                return UpdateCheckResult.Error($"Unexpected error: {ex.Message}");
            }
        }

        // ---- Download -------------------------------------------------------

        /// <summary>
        /// Downloads the new PackItPro.exe to a temp file on the same drive as
        /// the currently running exe. Reports progress and supports cancellation.
        ///
        /// On success, DownloadResult.TempFilePath holds the path of the downloaded
        /// file. The caller hands this path to UpdaterLauncher.LaunchAndExit().
        ///
        /// On failure or cancellation, any partial temp file is deleted.
        /// Never throws (cancellation is re-thrown as OperationCanceledException).
        /// </summary>
        public async Task<DownloadResult> DownloadUpdateAsync(
            string downloadUrl,
            IProgress<DownloadProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(downloadUrl))
                return DownloadResult.Fail(
                    "No download URL is available for this release.\n\n" +
                    "The release may not have a PackItPro.exe asset attached.\n" +
                    "You can download it manually from the GitHub Releases page.");

            // Place the temp file next to the running exe so that the later
            // rename stays on the same drive (cross-drive rename = copy+delete,
            // which can fail on locked files).
            // Environment.ProcessPath is the correct API for single-file apps (.NET 6+).
            // Assembly.GetExecutingAssembly().Location always returns "" in a single-file
            // publish and triggers a compiler warning. Never use it for path resolution.
            string currentExe = Environment.ProcessPath ?? string.Empty;
            string currentDir = !string.IsNullOrEmpty(currentExe)
                ? (Path.GetDirectoryName(currentExe) ?? AppContext.BaseDirectory)
                : AppContext.BaseDirectory;
            string tempPath = Path.Combine(
                currentDir, $"PackItPro_update_{Guid.NewGuid():N}.tmp");

            try
            {
                using var response = await _http.GetAsync(
                    downloadUrl,
                    HttpCompletionOption.ResponseHeadersRead,
                    ct);

                response.EnsureSuccessStatusCode();

                long? totalBytes = response.Content.Headers.ContentLength;

                using var src = await response.Content.ReadAsStreamAsync(ct);
                using var dst = new FileStream(
                    tempPath, FileMode.Create, FileAccess.Write,
                    FileShare.None, DownloadBufferSize, useAsync: true);

                var buffer = new byte[DownloadBufferSize];
                long downloaded = 0;
                int read;

                while ((read = await src.ReadAsync(buffer, ct)) > 0)
                {
                    await dst.WriteAsync(buffer.AsMemory(0, read), ct);
                    downloaded += read;

                    progress?.Report(new DownloadProgress(
                        BytesReceived: downloaded,
                        TotalBytes: totalBytes,
                        Percent: totalBytes > 0
                            ? (int)(downloaded * 100 / totalBytes.Value)
                            : -1));
                }

                await dst.FlushAsync(ct);
                return DownloadResult.Ok(tempPath, downloaded);
            }
            catch (OperationCanceledException)
            {
                TryDelete(tempPath);
                throw;
            }
            catch (Exception ex)
            {
                TryDelete(tempPath);
                return DownloadResult.Fail($"Download failed: {ex.Message}");
            }
        }

        // ---- Helpers --------------------------------------------------------

        private static string? ResolveDownloadUrl(GitHubRelease release)
        {
            if (release.Assets == null || release.Assets.Count == 0)
                return null;

            // Prefer exact name match, fall back to first .exe asset
            return (release.Assets
                    .FirstOrDefault(a => string.Equals(
                        a.Name, PrimaryAssetName, StringComparison.OrdinalIgnoreCase))
                ?? release.Assets
                    .FirstOrDefault(a => a.Name?.EndsWith(
                        ".exe", StringComparison.OrdinalIgnoreCase) == true))
                ?.BrowserDownloadUrl;
        }

        private static bool IsNewerVersion(string latest, string current)
        {
            var l = ParseVersion(latest);
            var c = ParseVersion(current);
            return l != null && c != null && l > c;
        }

        private static Version? ParseVersion(string tag)
        {
            var clean = tag.TrimStart('v', 'V').Trim();
            return Version.TryParse(clean, out var v) ? v : null;
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
    }

    // ---- Result / progress types --------------------------------------------

    public class UpdateCheckResult
    {
        public bool Success { get; init; }
        public bool UpdateAvailable { get; init; }
        public string? LatestVersion { get; init; }
        public string? CurrentVersion { get; init; }
        public string? ReleaseUrl { get; init; }
        public string? ReleaseNotes { get; init; }
        public string? DownloadUrl { get; init; }  // direct asset URL
        public DateTimeOffset? PublishedAt { get; init; }
        public string? ErrorMessage { get; init; }
        public bool NoReleasesPublished { get; init; }

        public static UpdateCheckResult Error(string message) => new()
        {
            Success = false,
            ErrorMessage = message,
        };

        public static UpdateCheckResult NoReleasesYet() => new()
        {
            Success = true,
            UpdateAvailable = false,
            NoReleasesPublished = true,
        };
    }

    public class DownloadResult
    {
        public bool Success { get; init; }
        public string? TempFilePath { get; init; }
        public long BytesWritten { get; init; }
        public string? ErrorMessage { get; init; }

        public static DownloadResult Ok(string path, long bytes) => new()
        {
            Success = true,
            TempFilePath = path,
            BytesWritten = bytes,
        };

        public static DownloadResult Fail(string message) => new()
        {
            Success = false,
            ErrorMessage = message,
        };
    }

    /// <param name="BytesReceived">Bytes downloaded so far.</param>
    /// <param name="TotalBytes">Content-Length from server; null if not sent.</param>
    /// <param name="Percent">0-100 when TotalBytes is known; -1 for indeterminate.</param>
    public record DownloadProgress(long BytesReceived, long? TotalBytes, int Percent);

    // ---- GitHub API models --------------------------------------------------

    internal class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string? TagName { get; set; }
        [JsonPropertyName("html_url")] public string? HtmlUrl { get; set; }
        [JsonPropertyName("body")] public string? Body { get; set; }
        [JsonPropertyName("published_at")] public DateTimeOffset? PublishedAt { get; set; }
        [JsonPropertyName("prerelease")] public bool Prerelease { get; set; }
        [JsonPropertyName("draft")] public bool Draft { get; set; }
        [JsonPropertyName("assets")] public List<GitHubAsset>? Assets { get; set; }
    }

    internal class GitHubAsset
    {
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("browser_download_url")] public string? BrowserDownloadUrl { get; set; }
        [JsonPropertyName("size")] public long Size { get; set; }
    }
}