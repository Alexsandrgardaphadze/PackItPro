// PackItPro/Services/ManifestGenerator.cs - v2.2
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
                    // FIX: Detect once, use everywhere — no double detection cost.
                    var type = DetectInstallType(path);
                    return new ManifestFile
                    {
                        Name = Path.GetFileName(path),
                        InstallType = type,
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
        // Detection
        // ──────────────────────────────────────────────────────────────

        public static string DetectInstallType(string filePath)
        {
            return Path.GetExtension(filePath).ToLowerInvariant() switch
            {
                ".msi" => "msi",
                ".msp" => "msp",
                ".appx" => "appx",
                ".appxbundle" => "appx",
                ".msix" => "msix",
                ".exe" => DetectExeType(filePath),
                _ => "file",
            };
        }

        private static string DetectExeType(string filePath)
        {
            try
            {
                Span<byte> header = stackalloc byte[512];
                using var fs = File.OpenRead(filePath);
                int read = fs.Read(header);

                // FIX: Guard against tiny EXEs (< 8 bytes) that can't contain
                // any valid signature — return "exe" immediately.
                if (read < 8) return "exe";

                header = header[..read];

                // FIX: Use Span<byte>.IndexOf with UTF-8 literal instead of
                // Encoding.ASCII.GetString — binary→string conversion can produce
                // false positives when arbitrary bytes coincidentally match ASCII
                // sequences. Raw byte comparison is exact.

                // InnoSetup: "Inno Setup" appears in the early header bytes
                if (header.IndexOf("Inno Setup"u8) >= 0)
                    return "inno";

                // NSIS: magic bytes 0xEFBEADDE at offset 4 (after MZ header)
                if (header[4] == 0xEF &&
                    header[5] == 0xBE &&
                    header[6] == 0xAD &&
                    header[7] == 0xDE)
                    return "nsis";
            }
            catch
            {
                // Unreadable header — fall through to generic "exe"
            }

            return "exe";
        }

        // ──────────────────────────────────────────────────────────────
        // Silent args — keyed on type string, not path
        // ──────────────────────────────────────────────────────────────

        private static string[]? GetDefaultSilentArgs(string installType)
        {
            return installType switch
            {
                "msi" => new[] { "/quiet", "/norestart" },
                "msp" => new[] { "/quiet", "/norestart" },
                "inno" => new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" },
                "nsis" => new[] { "/S" },
                "exe" => new[] { "/S", "/silent", "/quiet", "/SILENT", "/VERYSILENT" },
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
    }
}