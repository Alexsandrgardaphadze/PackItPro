// PackItPro/Services/UpdateService.cs - v2.1
// Fix #8: Switch from /releases/latest (single object) to /releases (array)
//   and filter out drafts and prereleases before selecting the newest version.
//   /releases/latest already excludes pre-releases on GitHub's side, but using
//   the list endpoint gives us explicit control and avoids edge-cases where a
//   repo's "latest" tag is temporarily set to a pre-release by mistake.
using System;
using System.Collections.Generic;
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

        // List endpoint — returns up to 30 releases by default (newest first).
        // We filter client-side to exclude drafts and pre-releases.
        private const string ApiUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases?per_page=30";
        private const string ReleasesUrl = $"https://github.com/{RepoOwner}/{RepoName}/releases/latest";

        private readonly HttpClient _http;

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

        /// <summary>
        /// Queries GitHub for the latest stable release (no drafts, no pre-releases).
        /// Never throws — all errors are captured in the returned result.
        /// </summary>
        public async Task<UpdateCheckResult> CheckAsync(CancellationToken ct = default)
        {
            try
            {
                var releases = await _http.GetFromJsonAsync<List<GitHubRelease>>(ApiUrl, ct);

                if (releases == null || releases.Count == 0)
                    return UpdateCheckResult.NoReleasesYet();

                // Filter: skip drafts and pre-releases, then pick the highest version tag.
                // Using MaxBy rather than [0] because the list is ordered by publish date,
                // not by semantic version — a hotfix on an older branch could appear first.
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
                };
            }
            catch (OperationCanceledException)
            {
                throw;
            }
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
    }

    public class UpdateCheckResult
    {
        public bool Success { get; init; }
        public bool UpdateAvailable { get; init; }
        public string? LatestVersion { get; init; }
        public string? CurrentVersion { get; init; }
        public string? ReleaseUrl { get; init; }
        public string? ReleaseNotes { get; init; }
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

    internal class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string? TagName { get; set; }
        [JsonPropertyName("html_url")] public string? HtmlUrl { get; set; }
        [JsonPropertyName("body")] public string? Body { get; set; }
        [JsonPropertyName("published_at")] public DateTimeOffset? PublishedAt { get; set; }
        [JsonPropertyName("prerelease")] public bool Prerelease { get; set; }
        [JsonPropertyName("draft")] public bool Draft { get; set; }
    }
}