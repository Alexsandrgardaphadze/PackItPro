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

        // How many bytes to read from each EXE for signature scanning.
        // 512 KB covers all common installer resource sections.
        private const int ScanSize = 512 * 1024;

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

        /// <summary>Returns just the install type string (for callers that don't need the source).</summary>
        public static string DetectInstallType(string filePath) =>
            DetectInstallTypeWithSource(filePath).Type;

        /// <summary>
        /// Returns (InstallType, DetectionSource).
        /// DetectionSource is "header" when a binary signature confirmed the type,
        /// "extension" when only the file extension was available.
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
                ".exe" => DetectExeType(filePath),
                _ => ("file", "extension"),
            };
        }

        private static (string Type, string Source) DetectExeType(string filePath)
        {
            ReadOnlyMemory<byte> header = ReadHeader(filePath, ScanSize);
            if (header.IsEmpty) return ("exe", "extension");

            var span = header.Span;

            // Priority order: check most unambiguous signatures first.
            // WiX Burn: ".wixburn" is a PE section name, always in the first 512 bytes
            if (ContainsAscii(span, ".wixburn"))
                return ("burn", "header");

            // NSIS: "Nullsoft" is embedded in the installer resource section
            if (ContainsAscii(span, "Nullsoft"))
                return ("nsis", "header");

            // Inno Setup: multiple possible strings; check the most specific first
            if (ContainsAscii(span, "Inno Setup Setup Data") ||
                ContainsAscii(span, "InnoSetupVersion") ||
                ContainsAscii(span, "Inno Setup"))
                return ("inno", "header");

            // Squirrel/Electron: version resource usually contains these strings
            if (ContainsAscii(span, "Squirrel.Windows") ||
                ContainsAscii(span, "SquirrelSetup") ||
                ContainsAscii(span, "Squirrel"))
                return ("squirrel", "header");

            return ("exe", "extension");
        }

        /// <summary>
        /// Reads up to <paramref name="maxBytes"/> from the start of the file.
        /// Returns empty on any I/O error.
        /// </summary>
        private static ReadOnlyMemory<byte> ReadHeader(string filePath, int maxBytes)
        {
            try
            {
                using var fs = File.OpenRead(filePath);
                int length = (int)Math.Min(fs.Length, maxBytes);
                if (length < 8) return ReadOnlyMemory<byte>.Empty;

                var buf = new byte[length];
                int read = 0;
                while (read < length)
                {
                    int n = fs.Read(buf, read, length - read);
                    if (n == 0) break;
                    read += n;
                }
                return buf.AsMemory(0, read);
            }
            catch { return ReadOnlyMemory<byte>.Empty; }
        }

        /// <summary>
        /// Returns true if <paramref name="needle"/> (ASCII) appears anywhere in
        /// <paramref name="data"/>. Does not allocate a string.
        /// </summary>
        private static bool ContainsAscii(ReadOnlySpan<byte> data, string needle)
        {
            if (needle.Length == 0 || data.Length < needle.Length) return false;

            Span<byte> needleBytes = stackalloc byte[needle.Length];
            for (int i = 0; i < needle.Length; i++)
                needleBytes[i] = (byte)needle[i];

            return data.IndexOf(needleBytes) >= 0;
        }

        internal static string[]? GetDefaultSilentArgs(string installType) => installType switch
        {
            "msi" => new[] { "/quiet", "/norestart" },
            "msp" => new[] { "/quiet", "/norestart" },
            "inno" => new[] { "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" },
            "nsis" => new[] { "/S" },
            "squirrel" => new[] { "--silent" },
            "burn" => new[] { "/quiet", "/norestart" },
            _ => null,
        };

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
        /// How InstallType was determined:
        ///   "extension" — inferred from file extension only (lower confidence)
        ///   "header"    — confirmed by binary signature scan (high confidence)
        ///   "manifest"  — user-specified in the PackItPro UI (authoritative)
        /// </summary>
        public string DetectionSource { get; set; } = "extension";
    }
}