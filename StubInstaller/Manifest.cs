// StubInstaller/Manifest.cs - v1.2
// Changes vs v1.1:
//   - Added DetectionSource property to ManifestFile.
//     Written by PackItPro at packaging time; read by the stub at install time.
//     Values: "extension" | "header" | "manifest"
//     Logged during install so users see detection confidence immediately.
//     Default is "extension" so old packages without this field still deserialize.
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