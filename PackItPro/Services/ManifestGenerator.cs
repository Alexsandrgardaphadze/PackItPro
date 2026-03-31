// PackItPro/Services/ManifestGenerator.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        private const int ScanSize = 512 * 1024;

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// A file path paired with an optional user note and VirusTotal result.
        /// Notes are written into the manifest JSON and visible to the stub UI.
        /// </summary>
        public record FileEntry(string Path, string? Notes = null, string? ScanResult = null);

        /// <summary>
        /// Primary overload — preserves per-file Notes, scan results, and shortcuts.
        /// </summary>
        public static string Generate(
            List<FileEntry> files,
            string packageName,
            bool requiresAdmin,
            bool includeWingetUpdateScript = false,
            List<Models.ShortcutEntry>? shortcuts = null)
        {
            var manifestFiles = files
                .OrderBy(f => f.Path)
                .Select((entry, index) =>
                {
                    var (type, source) = DetectInstallTypeWithSource(entry.Path);

                    // Office Click-to-Run: auto-inject a warning note so the user knows
                    // Office installs in the background long after the stub exits.
                    string? resolvedNotes = type == "office-c2r" && string.IsNullOrWhiteSpace(entry.Notes)
                        ? "WARNING: Office installs in the background after this exits. Allow 10-30 min after stub closes."
                        : (string.IsNullOrWhiteSpace(entry.Notes) ? null : entry.Notes.Trim());

                    return new ManifestFile
                    {
                        Name = Path.GetFileName(entry.Path),
                        DisplayName = ResolveDisplayName(entry.Path),
                        Notes = resolvedNotes,
                        ScanResult = string.IsNullOrWhiteSpace(entry.ScanResult) ? null : entry.ScanResult.ToLowerInvariant(),
                        InstallType = type,
                        DetectionSource = source,
                        SilentArgs = GetDefaultSilentArgs(type),
                        RequiresAdmin = DetectRequiresAdmin(entry.Path),
                        InstallOrder = index,
                        TimeoutMinutes = GetDefaultTimeout(entry.Path),
                    };
                })
                .ToList();

            // Convert shortcut entries to manifest shortcut entries, filtering
            // out any rows left blank by the user in the UI.
            List<ManifestShortcut>? manifestShortcuts = null;
            if (shortcuts != null && shortcuts.Count > 0)
            {
                manifestShortcuts = shortcuts
                    .Where(s => !string.IsNullOrWhiteSpace(s.Name)
                             && !string.IsNullOrWhiteSpace(s.TargetPath))
                    .Select(s => new ManifestShortcut
                    {
                        Name = s.Name.Trim(),
                        TargetPath = s.TargetPath.Trim(),
                        Arguments = string.IsNullOrWhiteSpace(s.Arguments) ? null : s.Arguments.Trim(),
                        Description = string.IsNullOrWhiteSpace(s.Description) ? null : s.Description.Trim(),
                        Location = s.Location.ToString(),
                    })
                    .ToList();

                if (manifestShortcuts.Count == 0) manifestShortcuts = null;
            }

            var manifest = new PackageManifest
            {
                PackageName = packageName,
                Files = manifestFiles,
                RequiresAdmin = requiresAdmin,
                Cleanup = true,
                AutoUpdateScript = includeWingetUpdateScript ? "update_all.bat" : null,
                Shortcuts = manifestShortcuts,
            };

            return JsonSerializer.Serialize(manifest, WriteOptions);
        }

        /// <summary>
        /// Backward-compatible overload for callers that don't have Notes or shortcuts.
        /// </summary>
        public static string Generate(
            List<string> filePaths,
            string packageName,
            bool requiresAdmin,
            bool includeWingetUpdateScript = false)
        {
            var entries = filePaths.Select(p => new FileEntry(p)).ToList();
            return Generate(entries, packageName, requiresAdmin, includeWingetUpdateScript);
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

        // ── EXE detection ─────────────────────────────────────────────────────

        private const int TailScanSize = 512 * 1024;
        private const int InnoScanSize = 4 * 1024 * 1024;

        private static (string Type, string Source) DetectExeType(string filePath)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(filePath);
                string prod = (vi.ProductName ?? "").Trim();
                string desc = (vi.FileDescription ?? "").Trim();
                string comp = (vi.CompanyName ?? "").Trim();
                string orig = (vi.OriginalFilename ?? "").Trim();
                string all = (prod + " " + desc + " " + comp + " " + orig).ToUpperInvariant();

                var hdr512 = ReadHeader(filePath, 512);
                if (!hdr512.IsEmpty && ContainsAscii(hdr512.Span, ".wixburn"))
                    return ("burn", "header");

                if (prod.Equals("ShareX", StringComparison.OrdinalIgnoreCase) || all.Contains("SHAREX"))
                    return ("sharex", "header");

                if (prod.Equals("Git", StringComparison.OrdinalIgnoreCase) &&
                    comp.IndexOf("Git Development", StringComparison.OrdinalIgnoreCase) >= 0)
                    return ("git-inno", "header");

                if (all.Contains("UNIGETUI") || all.Contains("WINGETUI"))
                    return ("unigetui", "header");

                if (all.Contains("VISUAL STUDIO CODE") || all.Contains("VSCODE"))
                    return ("vscode-inno", "header");

                if (all.Contains(".NET FRAMEWORK REPAIR") || all.Contains("FIXDOTNET") ||
                    (all.Contains("NETFXREPAIRTOOL") || (all.Contains(".NET FRAMEWORK") && all.Contains("REPAIR"))))
                    return ("netfxtool", "header");

                if (all.Contains("NULLSOFT"))
                    return ("nsis", "header");

                if (all.Contains("JAVA(TM) SE DEVELOPMENT KIT") ||
                    all.Contains("JAVA SE DEVELOPMENT KIT") ||
                    all.Contains("JDKINSTALLER") ||
                    (all.Contains("JDK") && all.Contains("ORACLE")))
                    return ("jdk", "header");

                if (all.Contains("WEBVIEW2") || all.Contains("EDGEWEBVIEW") ||
                    all.Contains("MICROSOFT EDGE WEBVIEW"))
                    return ("edgewebview2", "header");

                if (all.Contains("VISUAL C++") || all.Contains("VCREDIST") ||
                    (all.Contains("MICROSOFT") && all.Contains("VISUAL C")))
                {
                    bool isMs = comp.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
                    return isMs ? ("vcredist-ms", "header") : ("vcredist", "header");
                }

                if (all.Contains("OFFICECLICK") || all.Contains("C2RSETUP") ||
                    all.Contains("CLICK-TO-RUN") || all.Contains("CLICKTORUN"))
                    return ("office-c2r", "header");

                if (all.Contains("SQUIRREL"))
                    return ("squirrel", "header");

                if (all.Contains("DIRECTX") || all.Contains("D3DX"))
                {
                    if (desc.ToUpperInvariant().Contains("SETUP") && !desc.ToUpperInvariant().Contains("CABINET"))
                        return ("dxweb", "header");
                    return ("dxcab", "header");
                }

                if (all.Contains("WIX BURN") || all.Contains("WIXBURN"))
                    return ("burn", "header");
            }
            catch { /* version resource unavailable — fall through */ }

            ReadOnlyMemory<byte> header = ReadHeader(filePath, ScanSize);
            if (header.IsEmpty) return ("exe", "extension");

            var span = header.Span;

            if (ContainsAscii(span, ".wixburn")) return ("burn", "header");
            if (ContainsAsciiOrUtf16(span, "Nullsoft")) return ("nsis", "header");
            if (ContainsAsciiOrUtf16(span, "Inno Setup Setup Data") ||
                ContainsAsciiOrUtf16(span, "InnoSetupVersion") ||
                ContainsAsciiOrUtf16(span, "Inno Setup")) return ("inno", "header");

            var innoExtended = ReadHeader(filePath, InnoScanSize);
            if (!innoExtended.IsEmpty && ContainsAscii(innoExtended.Span, "rDlPt")) return ("inno", "header");

            var tail = ReadTail(filePath, TailScanSize);
            if (!tail.IsEmpty)
            {
                var tailSpan = tail.Span;
                if (ContainsAsciiOrUtf16(tailSpan, "Inno Setup Setup Data") ||
                    ContainsAsciiOrUtf16(tailSpan, "InnoSetupVersion") ||
                    ContainsAscii(tailSpan, "ISetupDel") ||
                    ContainsAscii(tailSpan, "JRSoft")) return ("inno", "content");
            }

            if (ContainsAsciiOrUtf16(span, "Squirrel.Windows") ||
                ContainsAsciiOrUtf16(span, "SquirrelSetup")) return ("squirrel", "header");
            if (ContainsAsciiOrUtf16(span, "OfficeClickToRun") ||
                ContainsAsciiOrUtf16(span, "C2RSetup")) return ("office-c2r", "header");
            if (ContainsAscii(span, "IFTW") ||
                ContainsAsciiOrUtf16(span, "JDKInstaller")) return ("jdk", "header");
            if (ContainsAsciiOrUtf16(span, "MicrosoftEdgeWebView2") ||
                ContainsAsciiOrUtf16(span, "EdgeWebView")) return ("edgewebview2", "header");
            if (ContainsAsciiOrUtf16(span, "Visual C++ Redistributable") ||
                ContainsAsciiOrUtf16(span, "VisualCppRedist")) return ("vcredist", "header");

            return ("exe", "extension");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

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

        private static ReadOnlyMemory<byte> ReadTail(string filePath, int maxBytes)
        {
            try
            {
                using var fs = File.OpenRead(filePath);
                if (fs.Length < 16) return ReadOnlyMemory<byte>.Empty;

                long startPos = Math.Max(0, fs.Length - maxBytes);
                int length = (int)(fs.Length - startPos);
                fs.Seek(startPos, SeekOrigin.Begin);

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

        private static bool ContainsAscii(ReadOnlySpan<byte> data, string needle)
        {
            if (needle.Length == 0 || data.Length < needle.Length) return false;
            Span<byte> nb = stackalloc byte[needle.Length];
            for (int i = 0; i < needle.Length; i++) nb[i] = (byte)needle[i];
            return data.IndexOf(nb) >= 0;
        }

        private static bool ContainsUtf16LE(ReadOnlySpan<byte> data, string needle)
        {
            if (needle.Length == 0) return false;
            int byteLen = needle.Length * 2;
            if (data.Length < byteLen) return false;
            Span<byte> nb = stackalloc byte[byteLen];
            for (int i = 0; i < needle.Length; i++)
            {
                char ch = needle[i];
                nb[i * 2] = (byte)(ch & 0xFF);
                nb[i * 2 + 1] = (byte)(ch >> 8);
            }
            return data.IndexOf(nb) >= 0;
        }

        private static bool ContainsAsciiOrUtf16(ReadOnlySpan<byte> data, string needle) =>
            ContainsAscii(data, needle) || ContainsUtf16LE(data, needle);

        // ── Silent args ───────────────────────────────────────────────────────

        internal static string[]? GetDefaultSilentArgs(string installType) => installType switch
        {
            "msi" => new[] { "/quiet", "/norestart" },
            "msp" => new[] { "/quiet", "/norestart" },
            "inno" => new[] { "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" },
            "sharex" => new[] { "/VERYSILENT", "/NORUN" },
            "git-inno" => new[] { "/VERYSILENT", "/NORESTART", "/NOCANCEL", "/SP-",
                                     "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS" },
            "unigetui" => new[] { "/SP", "/VERYSILENT", "/SUPPRESSMSGBOXES",
                                     "/NORESTART", "/NoAutoStart", "/ALLUSERS", "/LANG=english" },
            "vscode-inno" => new[] { "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES",
                                     "/NORESTART", "/MERGETASKS=!runcode" },
            "netfxtool" => new[] { "/q", "/n" },
            "nsis" => new[] { "/S" },
            "squirrel" => new[] { "--silent" },
            "burn" => new[] { "/quiet", "/norestart" },
            "office-c2r" => new[] { "/quiet" },
            "dxcab" => new[] { "/Q", "/T:{tempdir}" },
            "dxweb" => new[] { "/Q" },
            "jdk" => new[] { "/s" },
            "edgewebview2" => new[] { "--silent", "--system-level" },
            "vcredist" => new[] { "/ai", "/gm2" },
            "vcredist-ms" => new[] { "/install", "/quiet", "/norestart" },
            _ => null,
        };

        /// <summary>
        /// Detects whether an EXE requests administrator rights via its embedded
        /// UAC application manifest (requireAdministrator / highestAvailable).
        /// Never throws — returns false on any read error.
        /// </summary>
        private static bool DetectRequiresAdmin(string filePath)
        {
            try
            {
                ReadOnlyMemory<byte> data = ReadHeader(filePath, ScanSize);
                if (data.IsEmpty) return false;
                var span = data.Span;
                if (ContainsAscii(span, "requireAdministrator")) return true;
                if (ContainsAscii(span, "highestAvailable")) return true;
                if (ContainsAscii(span, "level=\"requireAdministrator\"")) return true;
                if (ContainsAscii(span, "level=\"highestAvailable\"")) return true;
                return false;
            }
            catch { return false; }
        }

        private static int GetDefaultTimeout(string filePath) =>
            GetDefaultTimeoutForType(DetectInstallType(filePath), filePath);

        private static int GetDefaultTimeoutForType(string installType, string filePath)
        {
            if (installType == "office-c2r") return 5;
            if (installType == "dxcab") return 5;
            if (installType == "dxweb") return 5;
            if (installType == "jdk") return 30;
            if (installType == "vcredist") return 10;
            if (installType is "sharex" or "git-inno" or "unigetui" or "vscode-inno") return 10;
            if (installType == "netfxtool") return 15;
            if (installType == "edgewebview2") return 15;
            try
            {
                double mb = new FileInfo(filePath).Length / (1024.0 * 1024.0);
                if (mb > 500) return 60;
                if (mb > 100) return 30;
            }
            catch { }
            return 10;
        }

        private static readonly HashSet<string> _windowsSystemNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft® Windows® Operating System",
            "Microsoft Windows Operating System",
            "Windows® Internet Explorer",
            "Windows Internet Explorer",
            "Internet Explorer",
            "Microsoft® Visual C++",
            "Microsoft Visual C++",
            "Microsoft® .NET Framework",
            "Microsoft .NET Framework",
            "Microsoft® Windows® Operating System Setup",
        };

        /// <summary>
        /// Reads the Windows version resource of an exe/msi to get a human-readable name.
        /// Priority: ProductName (if not a Windows system component) → FileDescription → filename.
        /// Never throws.
        /// </summary>
        private static string? ResolveDisplayName(string filePath)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(filePath);
                string? name = null;

                if (!string.IsNullOrWhiteSpace(vi.ProductName)
                    && !_windowsSystemNames.Contains(vi.ProductName.Trim()))
                    name = vi.ProductName.Trim();

                if (string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(vi.FileDescription))
                    name = vi.FileDescription.Trim();

                if (string.IsNullOrWhiteSpace(name))
                    name = Path.GetFileNameWithoutExtension(filePath);

                return name;
            }
            catch { return Path.GetFileNameWithoutExtension(filePath); }
        }
    }

    // ── Manifest models ───────────────────────────────────────────────────────

    /// <summary>
    /// Root manifest object serialized to <c>packitmeta.json</c> and embedded
    /// in the package ZIP. The stub deserializes this at runtime.
    /// </summary>
    public class PackageManifest
    {
        [JsonPropertyName("packageName")]
        public string PackageName { get; set; } = "MySoftwareBundle";

        [JsonPropertyName("version")]
        public string Version { get; set; } = "1.0";

        [JsonPropertyName("files")]
        public List<ManifestFile> Files { get; set; } = new();

        [JsonPropertyName("cleanup")]
        public bool Cleanup { get; set; } = true;

        [JsonPropertyName("autoUpdateScript")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? AutoUpdateScript { get; set; }

        [JsonPropertyName("sha256Checksum")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? SHA256Checksum { get; set; }

        [JsonPropertyName("requiresAdmin")]
        public bool RequiresAdmin { get; set; } = false;

        /// <summary>
        /// Shortcuts to create on the end-user's machine after all installers finish.
        /// Null when no shortcuts were configured — existing packages without this
        /// field deserialize safely (the stub skips shortcut creation).
        /// </summary>
        [JsonPropertyName("shortcuts")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<ManifestShortcut>? Shortcuts { get; set; }
    }

    /// <summary>Describes a single installer file in the package.</summary>
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
        /// How the install type was determined:
        /// "extension" — inferred from file extension (lower confidence),
        /// "header"    — confirmed by PE binary signature (reliable),
        /// "manifest"  — explicitly set by the user (authoritative).
        /// </summary>
        [JsonPropertyName("detectionSource")]
        public string DetectionSource { get; set; } = "extension";

        /// <summary>Optional free-text note set in the PackItPro UI.</summary>
        [JsonPropertyName("notes")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Notes { get; set; }

        /// <summary>
        /// Human-readable product name from FileVersionInfo.
        /// Null means the stub falls back to the raw filename.
        /// </summary>
        [JsonPropertyName("displayName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DisplayName { get; set; }

        /// <summary>
        /// VirusTotal result recorded at packaging time.
        /// "clean" | "infected" | null (not scanned).
        /// </summary>
        [JsonPropertyName("scanResult")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ScanResult { get; set; }
    }

    /// <summary>
    /// Describes a Windows shortcut (.lnk) the stub creates after all
    /// installers have run successfully.
    /// </summary>
    public class ManifestShortcut
    {
        /// <summary>Shortcut display name (without the .lnk extension).</summary>
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        /// <summary>
        /// Path to the target executable. Supports %ENV% variables, e.g.
        /// <c>%ProgramFiles%\MyApp\app.exe</c>.
        /// </summary>
        [JsonPropertyName("targetPath")]
        public string TargetPath { get; set; } = "";

        /// <summary>Optional command-line arguments passed to the target.</summary>
        [JsonPropertyName("arguments")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Arguments { get; set; }

        /// <summary>Optional tooltip text shown in the shortcut's Properties dialog.</summary>
        [JsonPropertyName("description")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Description { get; set; }

        /// <summary>
        /// Destination folder string: "Desktop" | "StartMenu" | "Startup".
        /// Matches the values of <c>ShortcutLocation</c> in the Models namespace.
        /// </summary>
        [JsonPropertyName("location")]
        public string Location { get; set; } = "Desktop";
    }
}