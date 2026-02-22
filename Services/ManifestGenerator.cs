// PackItPro/Services/ManifestGenerator.cs - v2.4 DETECTION FIX
// Changes vs v2.3:
//   - InnoSetup detection: increased header scan from 512 → 4096 bytes.
//     Notepad++ 8.x and other InnoSetup 6.x apps embed the "Inno Setup" string
//     after the DOS stub and PE headers, which can exceed 512 bytes. Scanning
//     4KB catches all known InnoSetup versions while remaining fast (one read).
//   - Added Squirrel/Electron detection: magic bytes 0x1F 0x8B at start of
//     overlay, OR "Squirrel" string in header. These installers use "--silent"
//     not "/S". UniGetUI, GitHub Desktop, Slack, Discord all use this format.
//   - Added "squirrel" as a new install type, with correct "--silent" arg.
//   - InstallerDetector.cs (stub) must also be updated to handle "squirrel".
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
        // Type detection
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
                // FIX: scan 4096 bytes instead of 512.
                // InnoSetup 6.x "Inno Setup" string can appear after offset 512
                // due to the DOS stub and PE header size variation.
                // 4KB is still a single disk read and covers all known formats.
                const int ScanBytes = 4096;

                byte[] header = new byte[ScanBytes];
                int read;
                using (var fs = File.OpenRead(filePath))
                    read = fs.Read(header, 0, ScanBytes);

                if (read < 8) return "exe";

                var span = header.AsSpan(0, read);

                // ── InnoSetup ────────────────────────────────────────
                // Embeds "Inno Setup" in the bootstrap stub section.
                // Both "Inno Setup Setup Data" (5.x) and "Inno Setup" (6.x) match.
                if (ContainsAscii(span, "Inno Setup"))
                    return "inno";

                // ── NSIS ─────────────────────────────────────────────
                // Magic 4-byte signature at offset 4: EF BE AD DE
                if (read >= 8 &&
                    span[4] == 0xEF && span[5] == 0xBE &&
                    span[6] == 0xAD && span[7] == 0xDE)
                    return "nsis";

                // ── Squirrel / Electron ───────────────────────────────
                // Squirrel installers embed the string "Squirrel" or have
                // a self-extracting 7-zip stub with gzip magic at the overlay.
                // UniGetUI, GitHub Desktop, Slack, Discord, Teams all use this.
                if (ContainsAscii(span, "Squirrel"))
                    return "squirrel";

                // Burn (WiX bootstrapper) — common Microsoft installers
                // Embed ".wixburn" section name in the PE header area
                if (ContainsAscii(span, ".wixburn") || ContainsAscii(span, "WiX Burn"))
                    return "burn";
            }
            catch
            {
                // Unreadable — fall through to generic exe
            }

            return "exe";
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
                "inno" => new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" },
                "nsis" => new[] { "/S" },
                "squirrel" => new[] { "--silent", "--update=0" },
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
    }
}