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
        // 512 KB covers all common installer resource sections.
        private const int ScanSize = 512 * 1024;

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// A file path paired with an optional user note.
        /// Notes are written into the manifest JSON and visible to the stub.
        /// </summary>
        public record FileEntry(string Path, string? Notes = null, string? ScanResult = null);

        /// <summary>
        /// Primary overload — preserves per-file Notes in the manifest.
        /// </summary>
        public static string Generate(
            List<FileEntry> files,
            string packageName,
            bool requiresAdmin,
            bool includeWingetUpdateScript = false)
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

            var manifest = new PackageManifest
            {
                PackageName = packageName,
                Files = manifestFiles,
                RequiresAdmin = requiresAdmin,
                Cleanup = true,
                AutoUpdateScript = includeWingetUpdateScript ? "update_all.bat" : null,
            };

            return JsonSerializer.Serialize(manifest, WriteOptions);
        }

        /// <summary>
        /// Backward-compatible overload for callers that don't have Notes.
        /// Converts to FileEntry list and delegates to the primary overload.
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

        // How many bytes to read from the END of an exe for Inno tail scan.
        // Inno stores its "Inno Setup Setup Data" signature near the end of the binary.
        private const int TailScanSize = 512 * 1024;

        // Inno Setup embeds an "rDlPt" PE resource name in its .rsrc section.
        // For large installers (>20MB) the .rsrc section can be beyond 512KB.
        // We scan up to 4MB to reliably find it.
        private const int InnoScanSize = 4 * 1024 * 1024;

        private static (string Type, string Source) DetectExeType(string filePath)
        {
            // Pass 1: FileVersionInfo uses the Windows VerQueryValue API which correctly
            // reads UTF-16LE PE version resources regardless of encoding or language.
            // Catches: JDK, WebView2, VCRedist, Office C2R, Squirrel, WiX Burn, NSIS.
            // Inno Setup does NOT embed its framework name in version resources — it is
            // caught by the byte/tail scan in Pass 2.
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(filePath);
                string prod = (vi.ProductName ?? "").Trim();
                string desc = (vi.FileDescription ?? "").Trim();
                string comp = (vi.CompanyName ?? "").Trim();
                string orig = (vi.OriginalFilename ?? "").Trim();
                string all = (prod + " " + desc + " " + comp + " " + orig).ToUpperInvariant();

                // WiX Burn: .wixburn PE section (fastest, most unambiguous)
                var hdr512 = ReadHeader(filePath, 512);
                if (!hdr512.IsEmpty && ContainsAscii(hdr512.Span, ".wixburn"))
                    return ("burn", "header");

                // Known installers with app-specific silent args
                // ShareX: /NORUN prevents auto-launch (official docs)
                if (prod.Equals("ShareX", StringComparison.OrdinalIgnoreCase) ||
                    all.Contains("SHAREX"))
                    return ("sharex", "header");

                // Git for Windows: needs /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /NOCANCEL
                if (prod.Equals("Git", StringComparison.OrdinalIgnoreCase) &&
                    comp.IndexOf("Git Development", StringComparison.OrdinalIgnoreCase) >= 0)
                    return ("git-inno", "header");

                // UniGetUI / WingetUI: /NoAutoStart /ALLUSERS prevents auto-launch
                if (all.Contains("UNIGETUI") || all.Contains("WINGETUI"))
                    return ("unigetui", "header");

                // VS Code Inno installer: /MERGETASKS=!runcode prevents auto-launch
                if (all.Contains("VISUAL STUDIO CODE") || all.Contains("VSCODE"))
                    return ("vscode-inno", "header");

                // .NET Framework Repair Tool: /q /n (Microsoft official docs)
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
                    // Official Microsoft vc_redist: CompanyName="Microsoft Corporation"
                    // AIO repack (abbodi1406): different company, needs /ai /gm2 not /install
                    bool isMs = comp.IndexOf("Microsoft", System.StringComparison.OrdinalIgnoreCase) >= 0;
                    return isMs ? ("vcredist-ms", "header") : ("vcredist", "header");
                }

                if (all.Contains("OFFICECLICK") || all.Contains("C2RSETUP") ||
                    all.Contains("CLICK-TO-RUN") || all.Contains("CLICKTORUN"))
                    return ("office-c2r", "header");

                if (all.Contains("SQUIRREL"))
                    return ("squirrel", "header");

                // DirectX June 2010 CAB self-extractor
                // FileDescription = "Win32 Cabinet Self-Extractor", ProductName = "Microsoft DirectX"
                // Two different DirectX files:
                // dxwebsetup.exe = web downloader (just needs /Q)
                // directx_Jun2010_redist.exe = CAB extractor (needs extract + DXSETUP.exe)
                if (all.Contains("DIRECTX") || all.Contains("D3DX"))
                {
                    if (desc.ToUpperInvariant().Contains("SETUP") && !desc.ToUpperInvariant().Contains("CABINET"))
                        return ("dxweb", "header");
                    return ("dxcab", "header");
                }

                if (all.Contains("WIX BURN") || all.Contains("WIXBURN"))
                    return ("burn", "header");
            }
            catch { /* version resource unavailable -- fall through */ }

            // Pass 2: Byte scan -- catches Inno Setup and NSIS variants that don't
            // include their framework name in PE version resources.
            ReadOnlyMemory<byte> header = ReadHeader(filePath, ScanSize);
            if (header.IsEmpty) return ("exe", "extension");

            var span = header.Span;

            if (ContainsAscii(span, ".wixburn"))
                return ("burn", "header");

            if (ContainsAsciiOrUtf16(span, "Nullsoft"))
                return ("nsis", "header");

            if (ContainsAsciiOrUtf16(span, "Inno Setup Setup Data") ||
                ContainsAsciiOrUtf16(span, "InnoSetupVersion") ||
                ContainsAsciiOrUtf16(span, "Inno Setup"))
                return ("inno", "header");

            // Extended Inno scan: "rDlPt" is a PE resource name that Inno embeds
            // in the .rsrc section. For large installers (Git=58MB, VSCode=103MB)
            // the .rsrc section starts beyond the first 512KB. Scan up to 4MB.
            var innoExtended = ReadHeader(filePath, InnoScanSize);
            if (!innoExtended.IsEmpty && ContainsAscii(innoExtended.Span, "rDlPt"))
                return ("inno", "header");

            // Inno tail scan: checks last 512KB for uncompressed header strings.
            var tail = ReadTail(filePath, TailScanSize);
            if (!tail.IsEmpty)
            {
                var tailSpan = tail.Span;
                if (ContainsAsciiOrUtf16(tailSpan, "Inno Setup Setup Data") ||
                    ContainsAsciiOrUtf16(tailSpan, "InnoSetupVersion") ||
                    ContainsAscii(tailSpan, "ISetupDel") ||
                    ContainsAscii(tailSpan, "JRSoft"))
                    return ("inno", "content");
            }

            // Byte-scan fallbacks for Pass-1 types
            if (ContainsAsciiOrUtf16(span, "Squirrel.Windows") ||
                ContainsAsciiOrUtf16(span, "SquirrelSetup"))
                return ("squirrel", "header");

            if (ContainsAsciiOrUtf16(span, "OfficeClickToRun") ||
                ContainsAsciiOrUtf16(span, "C2RSetup"))
                return ("office-c2r", "header");

            if (ContainsAscii(span, "IFTW") ||
                ContainsAsciiOrUtf16(span, "JDKInstaller"))
                return ("jdk", "header");

            if (ContainsAsciiOrUtf16(span, "MicrosoftEdgeWebView2") ||
                ContainsAsciiOrUtf16(span, "EdgeWebView"))
                return ("edgewebview2", "header");

            if (ContainsAsciiOrUtf16(span, "Visual C++ Redistributable") ||
                ContainsAsciiOrUtf16(span, "VisualCppRedist"))
                return ("vcredist", "header");

            return ("exe", "extension");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

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
        /// Reads up to <paramref name="maxBytes"/> from the END of the file.
        /// Used to detect Inno Setup signatures stored in the file tail.
        /// Returns empty on any I/O error or if file is too small.
        /// </summary>
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

        /// <summary>
        /// Returns true if <paramref name="needle"/> encoded as UTF-16LE appears
        /// anywhere in <paramref name="data"/>. PE version info resources store all
        /// strings as UTF-16LE — installer signatures like "Inno Setup",
        /// "MicrosoftEdgeWebView2", and "Java(TM) SE Development Kit" are only
        /// reliably findable this way.
        /// </summary>
        private static bool ContainsUtf16LE(ReadOnlySpan<byte> data, string needle)
        {
            if (needle.Length == 0) return false;
            int byteLen = needle.Length * 2;
            if (data.Length < byteLen) return false;

            // Encode needle as UTF-16LE without BOM — max needle is ~40 chars, stack-safe
            Span<byte> needleBytes = stackalloc byte[byteLen];
            for (int i = 0; i < needle.Length; i++)
            {
                char ch = needle[i];
                needleBytes[i * 2] = (byte)(ch & 0xFF);
                needleBytes[i * 2 + 1] = (byte)(ch >> 8);
            }

            return data.IndexOf(needleBytes) >= 0;
        }

        /// <summary>
        /// Returns true if <paramref name="needle"/> appears in <paramref name="data"/>
        /// as either ASCII or UTF-16LE. Catches the same string regardless of how it was
        /// stored in the PE resource table.
        /// </summary>
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

            // Office Click-to-Run: no silent flag — the bootstrapper manages its own UI.
            // It exits 0 immediately; the background download/install continues on its own.
            // PackItPro surfaces a warning at packaging time; the stub just runs it as-is.
            "office-c2r" => new[] { "/quiet" },

            // DirectX June 2010 CAB self-extractor: two-step (extract + DXSETUP.exe).
            "dxcab" => new[] { "/Q", "/T:{tempdir}" },
            // DirectX web setup: /Q for quiet. Downloads from internet, exits fast.
            "dxweb" => new[] { "/Q" },

            // JDK installer: /s (lowercase) is the correct silent flag, not /S.
            // Requires admin. Spawns msiexec internally for the actual installation.
            "jdk" => new[] { "/s" },

            // Edge WebView2 bootstrapper: --silent --system-level installs machine-wide.
            // Without --system-level it installs per-user and may not require admin.
            "edgewebview2" => new[] { "--silent", "--system-level" },

            // Visual C++ Redistributable: /install runs full install (not repair/uninstall).
            // /S does not work — the vcredist family uses WiX-based args.
            "vcredist" => new[] { "/ai", "/gm2" },       // AIO repack silent install
            "vcredist-ms" => new[] { "/install", "/quiet", "/norestart" }, // official MS vc_redist.exe

            _ => null,   // exe/appx/msix/file: stub tries /S at runtime
        };

        /// <summary>
        /// Detects whether an EXE requests administrator rights via its embedded
        /// UAC application manifest. Reads the PE resource section and searches
        /// for requestedExecutionLevel strings.
        ///
        /// Catches: requireAdministrator (most installers), highestAvailable
        /// (some installers that run elevated when the user is an admin).
        /// Returns false for asInvoker, or if no manifest is found.
        /// Never throws — returns false on any read error.
        /// </summary>
        private static bool DetectRequiresAdmin(string filePath)
        {
            try
            {
                // Read the full file up to ScanSize — UAC manifests are in the
                // resource section which can be anywhere in the first 512 KB.
                // For large installers also scan the header region separately.
                ReadOnlyMemory<byte> data = ReadHeader(filePath, ScanSize);
                if (data.IsEmpty) return false;

                var span = data.Span;

                // The embedded manifest XML contains one of these strings.
                // Check for the most common patterns first.
                if (ContainsAscii(span, "requireAdministrator"))
                    return true;

                // "highestAvailable" = elevated if running as admin, normal otherwise.
                // Treat as requiring admin since most installers use it this way.
                if (ContainsAscii(span, "highestAvailable"))
                    return true;

                // Some manifests use the full attribute form
                if (ContainsAscii(span, "level=\"requireAdministrator\""))
                    return true;

                if (ContainsAscii(span, "level=\"highestAvailable\""))
                    return true;

                return false;
            }
            catch { return false; }
        }

        private static int GetDefaultTimeout(string filePath) =>
            GetDefaultTimeoutForType(DetectInstallType(filePath), filePath);

        private static int GetDefaultTimeoutForType(string installType, string filePath)
        {
            // Office Click-to-Run: the bootstrapper exits quickly but triggers a background
            // download that takes 10-30 minutes. We can't wait for the background process,
            // so we give the bootstrapper itself a 5-minute timeout (enough to start it).
            if (installType == "office-c2r") return 5;

            if (installType == "dxcab") return 5;   // extraction only; DXSETUP runs separately
            if (installType == "dxweb") return 5;   // web bootstrapper exits fast

            // JDK: extracts and runs msiexec internally, can take 5-15 minutes.
            if (installType == "jdk") return 30;

            // VCRedist: usually fast (< 2 min), but /install on first-time can take longer.
            if (installType == "vcredist") return 10;
            if (installType is "sharex" or "git-inno" or "unigetui" or "vscode-inno") return 10;
            if (installType == "netfxtool") return 15;

            // EdgeWebView2: downloads and installs, can take several minutes.
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

        // Windows system component names embedded in redistributable installers.
        // These are internal Microsoft product names that are meaningless to end users
        // — fall through to FileDescription or filename when we see them.
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
        /// Never throws — bad version resources are silently ignored.
        /// </summary>
        private static string? ResolveDisplayName(string filePath)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(filePath);

                // Try ProductName first, but reject generic Windows system component strings —
                // redistributables like dxwebsetup.exe and vcredist embed the OS component
                // name ("Windows® Internet Explorer") rather than the actual product name.
                string? name = null;
                if (!string.IsNullOrWhiteSpace(vi.ProductName)
                    && !_windowsSystemNames.Contains(vi.ProductName.Trim()))
                {
                    name = vi.ProductName.Trim();
                }

                // FileDescription is usually more specific for system redistributables
                if (string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(vi.FileDescription))
                    name = vi.FileDescription.Trim();

                // Final fallback: filename without extension — always meaningful
                if (string.IsNullOrWhiteSpace(name))
                    name = Path.GetFileNameWithoutExtension(filePath);

                return name;
            }
            catch
            {
                // File locked, corrupt PE header, etc. — use filename.
                return Path.GetFileNameWithoutExtension(filePath);
            }
        }
    }

    // ── Manifest models ───────────────────────────────────────────────────────

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
    }

    public class ManifestFile
    {
        // JsonPropertyName attributes ensure the JSON keys match the stub's Manifest.cs
        // exactly, even if this class is serialized with default (PascalCase) settings.
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

        [JsonPropertyName("detectionSource")]
        public string DetectionSource { get; set; } = "extension";

        /// <summary>Optional user note — visible in the manifest, passed to the stub.</summary>
        [JsonPropertyName("notes")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Notes { get; set; }

        /// <summary>
        /// Human-readable display name for the stub UI.
        /// Populated from FileVersionInfo.ProductName at packaging time.
        /// Null = stub falls back to filename. WhenWritingNull keeps JSON clean.
        /// </summary>
        [JsonPropertyName("displayName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DisplayName { get; set; }

        /// <summary>
        /// VirusTotal scan result recorded by PackItPro at packaging time.
        /// "clean" = no detections, "infected" = detections found, null = not scanned.
        /// Displayed in the stub UI — does not block installation.
        /// </summary>
        [JsonPropertyName("scanResult")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ScanResult { get; set; }
    }
}