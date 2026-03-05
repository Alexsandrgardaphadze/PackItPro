using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace StubInstaller
{
    public class PackageManifest
    {
        [JsonPropertyName("packageName")]
        public string PackageName { get; set; } = "MySoftwareBundle";

        [JsonPropertyName("version")]
        public string Version { get; set; } = "1.0";

        [JsonPropertyName("sha256Checksum")]
        public string? SHA256Checksum { get; set; }

        [JsonPropertyName("files")]
        public List<ManifestFile> Files { get; set; } = new();

        [JsonPropertyName("autoUpdateScript")]
        public string? AutoUpdateScript { get; set; }

        [JsonPropertyName("requiresAdmin")]
        public bool RequiresAdmin { get; set; } = false;

        [JsonPropertyName("cleanup")]
        public bool Cleanup { get; set; } = true;

        /// <summary>
        /// Minimum Windows build number required. Null = default (18362 = Win10 1903).
        /// Examples: 18362 = Win10 1903, 19041 = Win10 2004, 22000 = Win11.
        /// </summary>
        [JsonPropertyName("minWindowsBuild")]
        public int? MinWindowsBuild { get; set; }

        /// <summary>
        /// True if the package requires a 64-bit (x64) operating system.
        /// False (default) means any architecture is accepted.
        /// </summary>
        [JsonPropertyName("requiresX64")]
        public bool RequiresX64 { get; set; } = false;

        /// <summary>
        /// Minimum free disk space in MB. Null = auto-estimate from payload size.
        /// Set explicitly if the installed software requires significantly more space
        /// than the installer payload (e.g. a game that extracts 50 GB).
        /// </summary>
        [JsonPropertyName("minFreeDiskMB")]
        public int? MinFreeDiskMB { get; set; }
    }

    public class ManifestFile
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("installType")]
        public string InstallType { get; set; } = "exe";

        [JsonPropertyName("silentArgs")]
        public string[]? SilentArgs { get; set; }

        [JsonPropertyName("requiresAdmin")]
        public bool RequiresAdmin { get; set; } = false;

        [JsonPropertyName("installOrder")]
        public int InstallOrder { get; set; } = 0;

        [JsonPropertyName("timeoutMinutes")]
        public int TimeoutMinutes { get; set; } = 10;

        /// <summary>
        /// How InstallType was determined by PackItPro at packaging time:
        ///   "extension" — inferred from file extension only (⚠ lower confidence)
        ///   "header"    — confirmed by PE binary signature scan (✅ reliable)
        ///   "manifest"  — explicitly set by the user in PackItPro UI (✅ authoritative)
        /// Defaults to "extension" so packages built before this field was added
        /// still deserialize correctly — the stub treats missing as extension-level.
        /// </summary>
        [JsonPropertyName("detectionSource")]
        public string DetectionSource { get; set; } = "extension";
    }
}