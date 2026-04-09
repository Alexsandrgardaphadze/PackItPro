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
    /// <summary>
    /// Checks GitHub for new releases and downloads update assets.
    /// Downloads both <c>PackItPro.exe</c> and <c>StubInstaller.exe</c> so
    /// both binaries are always in sync after an update.
    /// </summary>
    public class UpdateService
    {
        // ── Constants ─────────────────────────────────────────────────────────

        private const string RepoOwner = "Alexsandrgardaphadze";
        private const string RepoName = "PackItPro";
        private const string ApiUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases?per_page=30";
        private const string ReleasesUrl = $"https://github.com/{RepoOwner}/{RepoName}/releases/latest";

        /// <summary>Primary executable asset name expected in every release.</summary>
        private const string MainExeName = "PackItPro.exe";

        /// <summary>
        /// Stub asset name expected alongside the main exe.
        /// If absent from a release, the stub is skipped gracefully — it won't
        /// block the update, but the existing stub is left on disk as-is.
        /// </summary>
        private const string StubExeName = "StubInstaller.exe";

        private const int DownloadBufferSize = 81_920; // 80 KB chunks

        private readonly HttpClient _http;

        // ── Version ───────────────────────────────────────────────────────────

        /// <summary>
        /// Current application version read from the assembly manifest.
        /// Formatted as <c>vMAJOR.MINOR.BUILD</c>.
        /// </summary>
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

        // ── Check ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Queries GitHub for the latest stable release.
        /// Never throws — all errors are captured in the returned result.
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

                // Resolve download URLs for both assets.
                ResolveDownloadUrls(stable,
                    out string? mainUrl,
                    out string? stubUrl);

                return new UpdateCheckResult
                {
                    Success = true,
                    UpdateAvailable = isNewer,
                    LatestVersion = stable.TagName,
                    CurrentVersion = CurrentVersion,
                    ReleaseUrl = stable.HtmlUrl ?? ReleasesUrl,
                    ReleaseNotes = stable.Body,
                    PublishedAt = stable.PublishedAt,
                    DownloadUrl = mainUrl,
                    StubDownloadUrl = stubUrl,
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

        // ── Download ──────────────────────────────────────────────────────────

        /// <summary>
        /// Downloads <c>PackItPro.exe</c> and, when available, <c>StubInstaller.exe</c>
        /// to temp files on the same drive as the running executable.
        /// Progress is reported as the combined byte count across both downloads.
        /// On cancellation or failure all partial temp files are deleted.
        /// </summary>
        /// <param name="result">Check result that contains the download URLs.</param>
        /// <param name="progress">Optional progress reporter (0–100 % combined).</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>
        /// A <see cref="DualDownloadResult"/> containing temp paths for both assets.
        /// <see cref="DualDownloadResult.StubTempPath"/> is <c>null</c> when the stub
        /// asset is absent from the release.
        /// </returns>
        public async Task<DualDownloadResult> DownloadUpdateAsync(
            UpdateCheckResult result,
            IProgress<DownloadProgress>? progress = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(result.DownloadUrl))
                return DualDownloadResult.Fail(
                    "No download URL is available for this release.\n\n" +
                    "The release may not have a PackItPro.exe asset attached.\n" +
                    "You can download it manually from the GitHub Releases page.");

            string dir = ResolveDownloadDirectory();

            string mainTemp = Path.Combine(dir, $"PackItPro_update_{Guid.NewGuid():N}.tmp");
            string? stubTemp = null;

            try
            {
                // ── Determine total size for combined progress ─────────────────
                long? mainTotal = await GetContentLengthAsync(result.DownloadUrl, ct);
                long? stubTotal = !string.IsNullOrWhiteSpace(result.StubDownloadUrl)
                    ? await GetContentLengthAsync(result.StubDownloadUrl, ct)
                    : null;

                long? grandTotal = (mainTotal.HasValue && stubTotal.HasValue)
                    ? mainTotal.Value + stubTotal.Value
                    : null;

                long downloaded = 0;

                // ── Download PackItPro.exe ─────────────────────────────────────
                await DownloadFileAsync(result.DownloadUrl, mainTemp,
                    bytes =>
                    {
                        downloaded += bytes;
                        progress?.Report(new DownloadProgress(
                            downloaded, grandTotal,
                            grandTotal > 0 ? (int)(downloaded * 100 / grandTotal!.Value) : -1));
                    }, ct);

                // ── Download StubInstaller.exe (best-effort) ──────────────────
                if (!string.IsNullOrWhiteSpace(result.StubDownloadUrl))
                {
                    stubTemp = Path.Combine(dir, $"StubInstaller_update_{Guid.NewGuid():N}.tmp");
                    await DownloadFileAsync(result.StubDownloadUrl, stubTemp,
                        bytes =>
                        {
                            downloaded += bytes;
                            progress?.Report(new DownloadProgress(
                                downloaded, grandTotal,
                                grandTotal > 0 ? (int)(downloaded * 100 / grandTotal!.Value) : -1));
                        }, ct);
                }

                return DualDownloadResult.Ok(mainTemp, stubTemp, downloaded);
            }
            catch (OperationCanceledException)
            {
                TryDelete(mainTemp);
                TryDelete(stubTemp);
                throw;
            }
            catch (Exception ex)
            {
                TryDelete(mainTemp);
                TryDelete(stubTemp);
                return DualDownloadResult.Fail($"Download failed: {ex.Message}");
            }
        }

        // ── Private helpers ───────────────────────────────────────────────────

        /// <summary>
        /// Streams a single URL to <paramref name="destPath"/>, reporting byte
        /// counts via <paramref name="onBytes"/> as chunks arrive.
        /// </summary>
        private async Task DownloadFileAsync(
            string url,
            string destPath,
            Action<int> onBytes,
            CancellationToken ct)
        {
            using var response = await _http.GetAsync(
                url, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();

            using var src = await response.Content.ReadAsStreamAsync(ct);
            using var dst = new FileStream(
                destPath, FileMode.Create, FileAccess.Write,
                FileShare.None, DownloadBufferSize, useAsync: true);

            var buffer = new byte[DownloadBufferSize];
            int read;
            while ((read = await src.ReadAsync(buffer, ct)) > 0)
            {
                await dst.WriteAsync(buffer.AsMemory(0, read), ct);
                onBytes(read);
            }

            await dst.FlushAsync(ct);
        }

        /// <summary>
        /// Issues a HEAD request to read <c>Content-Length</c> without downloading.
        /// Returns <c>null</c> if the server omits the header or the request fails.
        /// </summary>
        private async Task<long?> GetContentLengthAsync(string url, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Head, url);
                using var resp = await _http.SendAsync(req, ct);
                return resp.Content.Headers.ContentLength;
            }
            catch { return null; }
        }

        /// <summary>
        /// Returns the directory that temp files should be written to.
        /// Placing temp files on the same drive as the running exe keeps the
        /// later <c>Move-Item</c> in the updater script atomic.
        /// </summary>
        private static string ResolveDownloadDirectory()
        {
            string? exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe))
            {
                string? dir = Path.GetDirectoryName(exe);
                if (!string.IsNullOrEmpty(dir)) return dir;
            }
            return AppContext.BaseDirectory;
        }

        /// <summary>
        /// Populates <paramref name="mainUrl"/> and <paramref name="stubUrl"/> by
        /// scanning the release assets for the expected file names.
        /// Falls back to the first <c>.exe</c> asset for the main exe when the
        /// exact name is not found.
        /// </summary>
        private static void ResolveDownloadUrls(
            GitHubRelease release,
            out string? mainUrl,
            out string? stubUrl)
        {
            mainUrl = null;
            stubUrl = null;

            if (release.Assets == null || release.Assets.Count == 0) return;

            // Main exe: prefer exact name, fall back to first .exe
            mainUrl = (release.Assets
                    .FirstOrDefault(a => string.Equals(
                        a.Name, MainExeName, StringComparison.OrdinalIgnoreCase))
                ?? release.Assets
                    .FirstOrDefault(a =>
                        a.Name?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true
                        && !string.Equals(a.Name, StubExeName, StringComparison.OrdinalIgnoreCase)))
                ?.BrowserDownloadUrl;

            // Stub exe: exact name only — we don't want to accidentally pick the wrong file
            stubUrl = release.Assets
                .FirstOrDefault(a => string.Equals(
                    a.Name, StubExeName, StringComparison.OrdinalIgnoreCase))
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

        private static void TryDelete(string? path)
        {
            if (path == null) return;
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
    }

    // ── Result / progress types ───────────────────────────────────────────────

    /// <summary>Result of a GitHub release check.</summary>
    public class UpdateCheckResult
    {
        public bool Success { get; init; }
        public bool UpdateAvailable { get; init; }
        public string? LatestVersion { get; init; }
        public string? CurrentVersion { get; init; }
        public string? ReleaseUrl { get; init; }
        public string? ReleaseNotes { get; init; }
        /// <summary>Direct download URL for <c>PackItPro.exe</c>.</summary>
        public string? DownloadUrl { get; init; }
        /// <summary>Direct download URL for <c>StubInstaller.exe</c>; null when absent.</summary>
        public string? StubDownloadUrl { get; init; }
        public DateTimeOffset? PublishedAt { get; init; }
        public string? ErrorMessage { get; init; }
        public bool NoReleasesPublished { get; init; }

        public static UpdateCheckResult Error(string message) => new()
        { Success = false, ErrorMessage = message };

        public static UpdateCheckResult NoReleasesYet() => new()
        { Success = true, UpdateAvailable = false, NoReleasesPublished = true };
    }

    /// <summary>
    /// Result of <see cref="UpdateService.DownloadUpdateAsync"/>.
    /// Both assets are represented: <see cref="StubTempPath"/> is null when
    /// the release did not include a <c>StubInstaller.exe</c> asset.
    /// </summary>
    public class DualDownloadResult
    {
        public bool Success { get; init; }
        /// <summary>Temp path of the downloaded <c>PackItPro.exe</c>.</summary>
        public string? MainTempPath { get; init; }
        /// <summary>Temp path of the downloaded <c>StubInstaller.exe</c>, or null.</summary>
        public string? StubTempPath { get; init; }
        public long BytesWritten { get; init; }
        public string? ErrorMessage { get; init; }

        public static DualDownloadResult Ok(string mainPath, string? stubPath, long bytes) => new()
        { Success = true, MainTempPath = mainPath, StubTempPath = stubPath, BytesWritten = bytes };

        public static DualDownloadResult Fail(string message) => new()
        { Success = false, ErrorMessage = message };
    }

    /// <param name="BytesReceived">Bytes downloaded so far (across all assets).</param>
    /// <param name="TotalBytes">Combined Content-Length; null when unknown.</param>
    /// <param name="Percent">0–100 when total is known; -1 for indeterminate.</param>
    public record DownloadProgress(long BytesReceived, long? TotalBytes, int Percent);

    // ── GitHub API models ─────────────────────────────────────────────────────

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