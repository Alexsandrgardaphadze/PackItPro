// PackItPro/Services/UpdateService.cs
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    /// <summary>
    /// Checks for new PackItPro releases via the GitHub Releases API.
    /// Keep one instance alive for the application lifetime (injected via MainViewModel).
    /// </summary>
    public class UpdateService
    {
        private const string RepoOwner = "Alexsandrgardaphadze";
        private const string RepoName = "PackItPro";
        private const string ApiUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
        private const string ReleasesUrl = $"https://github.com/{RepoOwner}/{RepoName}/releases/latest";

        private readonly HttpClient _http;

        /// <summary>
        /// Version read from the assembly — stays in sync with PackItPro.csproj &lt;Version&gt; automatically.
        /// Format returned: "v1.2.3" (prefixed so it matches GitHub tag conventions).
        /// </summary>
        public static string CurrentVersion
        {
            get
            {
                var v = Assembly.GetExecutingAssembly().GetName().Version;
                // Version has 4 parts (Major.Minor.Build.Revision). We only use 3.
                return v != null ? $"v{v.Major}.{v.Minor}.{v.Build}" : "v0.0.0";
            }
        }

        public UpdateService(HttpClient http)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));

            // GitHub API requires a User-Agent — requests without one get HTTP 403
            if (!_http.DefaultRequestHeaders.Contains("User-Agent"))
                _http.DefaultRequestHeaders.Add("User-Agent", $"PackItPro/{CurrentVersion}");
        }

        /// <summary>
        /// Queries GitHub for the latest release.
        /// Never throws — all errors are captured in the returned result.
        /// </summary>
        public async Task<UpdateCheckResult> CheckAsync(CancellationToken ct = default)
        {
            try
            {
                var release = await _http.GetFromJsonAsync<GitHubRelease>(ApiUrl, ct);

                if (release == null)
                    return UpdateCheckResult.Error("GitHub returned an empty response.");

                if (string.IsNullOrWhiteSpace(release.TagName))
                    return UpdateCheckResult.NoReleasesYet();

                bool isNewer = IsNewerVersion(release.TagName, CurrentVersion);

                return new UpdateCheckResult
                {
                    Success = true,
                    UpdateAvailable = isNewer,
                    LatestVersion = release.TagName,
                    CurrentVersion = CurrentVersion,
                    ReleaseUrl = release.HtmlUrl ?? ReleasesUrl,
                    ReleaseNotes = release.Body,
                    PublishedAt = release.PublishedAt,
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
            if (!TryParseVersion(latest, out var latestVer)) return false;
            if (!TryParseVersion(current, out var currentVer)) return false;
            return latestVer > currentVer;
        }

        private static bool TryParseVersion(string tag, out Version version)
        {
            var clean = tag.TrimStart('v', 'V').Trim();
            return Version.TryParse(clean, out version!);
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
        [JsonPropertyName("tag_name")]
        public string? TagName { get; set; }

        [JsonPropertyName("html_url")]
        public string? HtmlUrl { get; set; }

        [JsonPropertyName("body")]
        public string? Body { get; set; }

        [JsonPropertyName("published_at")]
        public DateTimeOffset? PublishedAt { get; set; }

        [JsonPropertyName("prerelease")]
        public bool Prerelease { get; set; }

        [JsonPropertyName("draft")]
        public bool Draft { get; set; }
    }
}