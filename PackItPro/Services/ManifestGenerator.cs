// PackItPro/Services/ManifestGenerator.cs - v2.5
// Changes vs v2.4:
//   [1] DetectionSource field added to ManifestFile and populated at Generate() time.
//       "extension" = type inferred from file extension only (lower confidence)
//       "header"    = type confirmed by PE binary signature scan (reliable)
//       Stub reads this field and logs it with a ✅/⚠️ indicator.
//   [2] DetectInstallTypeWithSource() returns (Type, Source) tuple for the above.
//       DetectInstallType() delegates to it — fully backward compatible.
//   [3] DetectExeTypeWithSource() replaces DetectExeType() — same detection logic.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PackItPro.Services
{
    public static class ManifestGenerator
    {
        private static readonly JsonSerializerOptions WriteOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        public static string Generate(
            List<string> filePaths,
            string packageName,
            bool requiresAdmin,
            bool includeWingetUpdateScript = false)
        {
            var files = filePaths
                .OrderBy(p => p)
                .Select((path, index) =>
                {
                    var (type, source) = DetectInstallTypeWithSource(path);
                    return new ManifestFile
                    {
                        Name = Path.GetFileName(path),
                        InstallType = type,
                        DetectionSource = source,
                        SilentArgs = GetDefaultSilentArgs(type),
                        RequiresAdmin = false,
                        InstallOrder = index,
                        TimeoutMinutes = GetDefaultTimeout(path),
                    };
                })
                .ToList();

            var manifest = new PackageManifest
            {
                PackageName = packageName,
                Files = files,
                RequiresAdmin = requiresAdmin,
                Cleanup = true,
                AutoUpdateScript = includeWingetUpdateScript ? "update_all.bat" : null,
            };

            return JsonSerializer.Serialize(manifest, WriteOptions);
        }

        // ──────────────────────────────────────────────────────────────
        // Type detection — public for unit tests and PackItPro UI preview
        // ──────────────────────────────────────────────────────────────

        public static string DetectInstallType(string filePath) =>
            DetectInstallTypeWithSource(filePath).Type;

        /// <summary>
        /// Returns (InstallType, DetectionSource) so the manifest can record
        /// how confident the detection was. The stub logs this at install time.
        /// </summary>
        public static (string Type, string Source) DetectInstallTypeWithSource(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            return ext switch
            {
                ".msi" => ("msi", "extension"),
                ".msp" => ("msp", "extension"),
                ".appx" => ("appx", "extension"),
                ".appxbundle" => ("appx", "extension"),
                ".msix" => ("msix", "extension"),
                ".exe" => DetectExeTypeWithSource(filePath),
                _ => ("file", "extension"),
            };
        }

        private static (string Type, string Source) DetectExeTypeWithSource(string filePath)
        {
            try
            {
                const int ScanBytes = 4096;
                byte[] header = new byte[ScanBytes];
                int read;
                using (var fs = File.OpenRead(filePath))
                    read = fs.Read(header, 0, ScanBytes);

                if (read < 8) return ("exe", "extension");

                var span = header.AsSpan(0, read);

                if (ContainsAscii(span, "Inno Setup"))
                    return ("inno", "header");

                if (read >= 8 &&
                    span[4] == 0xEF && span[5] == 0xBE &&
                    span[6] == 0xAD && span[7] == 0xDE)
                    return ("nsis", "header");

                if (ContainsAscii(span, "Squirrel"))
                    return ("squirrel", "header");

                if (ContainsAscii(span, ".wixburn") || ContainsAscii(span, "WiX Burn"))
                    return ("burn", "header");
            }
            catch { }

            return ("exe", "extension");
        }

        /// <summary>
        /// Case-sensitive byte-level ASCII substring search.
        /// Avoids Encoding.ASCII.GetString which can produce false positives
        /// on non-ASCII bytes in binary content.
        /// </summary>
        private static bool ContainsAscii(ReadOnlySpan<byte> data, string needle)
        {
            if (needle.Length == 0 || data.Length < needle.Length) return false;

            // Convert needle to bytes once
            Span<byte> needleBytes = stackalloc byte[needle.Length];
            for (int i = 0; i < needle.Length; i++)
                needleBytes[i] = (byte)needle[i];

            return data.IndexOf(needleBytes) >= 0;
        }

        // ──────────────────────────────────────────────────────────────
        // Silent args — one correct arg per type
        // ──────────────────────────────────────────────────────────────

        internal static string[]? GetDefaultSilentArgs(string installType)
        {
            return installType switch
            {
                "msi" => new[] { "/quiet", "/norestart" },
                "msp" => new[] { "/quiet", "/norestart" },
                "inno" => new[] { "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" },
                "nsis" => new[] { "/S" },
                "squirrel" => new[] { "--silent" },
                "burn" => new[] { "/quiet", "/norestart" },

                // Generic exe: null = stub will try /S at runtime via InstallerDetector
                "exe" => null,

                // Store/patch formats — no CLI silent flag
                "appx" => null,
                "msix" => null,
                "file" => null,
                _ => null,
            };
        }

        private static int GetDefaultTimeout(string filePath)
        {
            try
            {
                double mb = new FileInfo(filePath).Length / (1024.0 * 1024.0);
                if (mb > 500) return 60;
                if (mb > 100) return 30;
            }
            catch { }
            return 10;
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Manifest models
    // ──────────────────────────────────────────────────────────────────

    public class PackageManifest
    {
        public string PackageName { get; set; } = "MySoftwareBundle";
        public string Version { get; set; } = "1.0";
        public List<ManifestFile> Files { get; set; } = new();
        public bool Cleanup { get; set; } = true;
        public string? AutoUpdateScript { get; set; }
        public string? SHA256Checksum { get; set; }
        public bool RequiresAdmin { get; set; } = false;
    }

    public class ManifestFile
    {
        public string Name { get; set; } = "";
        public string InstallType { get; set; } = "exe";
        public string[]? SilentArgs { get; set; }
        public bool RequiresAdmin { get; set; } = false;
        public int InstallOrder { get; set; } = 0;
        public int TimeoutMinutes { get; set; } = 10;

        /// <summary>
        /// How the InstallType was determined. Values:
        ///   "extension"  — inferred from file extension only (lowest confidence)
        ///   "header"     — confirmed by PE header / binary signature scan (high confidence)
        ///   "manifest"   — explicitly set by the user in the UI (authoritative)
        /// Stored in the manifest so the stub can log it for diagnostics.
        /// </summary>
        public string DetectionSource { get; set; } = "extension";
    }
}