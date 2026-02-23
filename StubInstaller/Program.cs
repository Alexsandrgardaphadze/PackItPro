// StubInstaller/Program.cs - v1.8
// Changes vs v1.7:
//   [1] ShowError now copies log to Desktop on failure (timestamped filename).
//       Users almost never find %TEMP%\PackItPro\{guid}\install.log on their own.
//       Desktop copy survives cleanup and is findable without instructions.
//       Falls back to clipboard-only if Desktop copy fails (redirected profile, etc.)
//   [2] Partial-failure completion dialog also copies log to Desktop proactively.
//   [3] Manifest listing now shows DetectionSource per installer:
//       "header signature ✅" / "user-specified ✅" / "extension only ⚠️"
//       Immediately visible in the log — 90% of silent failures come from wrong type.
//   [4] StubVersion constant updated to "1.8".

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace StubInstaller
{
    // ── MSI / installer exit code classification ──────────────────────────────

    public enum ExitCodeResult
    {
        Success,
        SuccessRebootRequired,   // 3010 — install OK, reboot needed to complete
        SuccessRebootInitiated,  // 1641 — install OK, reboot already started
        UserCancelled,           // 1602
        AnotherInstallRunning,   // 1618 — should retry after a pause
        Failure,
    }

    public static class ExitCodeClassifier
    {
        public static ExitCodeResult Classify(int exitCode) => exitCode switch
        {
            0 => ExitCodeResult.Success,
            3010 => ExitCodeResult.SuccessRebootRequired,
            1641 => ExitCodeResult.SuccessRebootInitiated,
            1602 => ExitCodeResult.UserCancelled,
            1618 => ExitCodeResult.AnotherInstallRunning,
            _ => ExitCodeResult.Failure,
        };

        public static bool IsSuccess(ExitCodeResult r) =>
            r is ExitCodeResult.Success
              or ExitCodeResult.SuccessRebootRequired
              or ExitCodeResult.SuccessRebootInitiated;

        public static string Describe(int exitCode)
        {
            var r = Classify(exitCode);
            return r switch
            {
                ExitCodeResult.Success => "Success (0)",
                ExitCodeResult.SuccessRebootRequired => "Success — reboot required (3010)",
                ExitCodeResult.SuccessRebootInitiated => "Success — reboot initiated (1641)",
                ExitCodeResult.UserCancelled => "Cancelled by user (1602)",
                ExitCodeResult.AnotherInstallRunning => "Another install in progress (1618)",
                _ => $"Failed (exit code {exitCode})",
            };
        }
    }

    // ── Main program ──────────────────────────────────────────────────────────

    internal class Program
    {
        private static string? _logPath;
        private static bool _consoleMode;
        private static bool _rebootRequired;
        // Lock ensures no interleaved writes if we ever add parallel operations
        private static readonly object _logLock = new();

        // Version constant — update this when building a new release
        private const string StubVersion = "1.8";
        private const string StubBuildDate = "2026-02-22";

        private const string ArgTempDir = "--temp-dir";
        private const string ArgLogPath = "--log-path";

        [STAThread]
        static async Task<int> Main(string[] args)
        {
            // Parse resume args (present only in elevated child launched by us)
            string? resumeTempDir = GetArgValue(args, ArgTempDir);
            string? resumeLogPath = GetArgValue(args, ArgLogPath);
            bool isElevatedResume = resumeTempDir != null && resumeLogPath != null;

            DetectConsoleMode();

            // Elevated resume: set log path first, write separator, jump to Step 5
            if (isElevatedResume)
            {
                _logPath = resumeLogPath!;
                AppendElevationSeparator();
            }
            else
            {
                // Bootstrap log in %TEMP% — only used until extraction dir is ready
                _logPath = Path.Combine(
                    Path.GetTempPath(),
                    $"PackItPro_Stub_{DateTime.Now:yyyyMMdd_HHmmss_fff}.log");
                WriteLogHeader();
            }

            try
            {
                Log("========================================");
                Log($"PackItPro Stub Installer v{StubVersion}{(isElevatedResume ? " [ELEVATED]" : "")}");
                Log($"Build date:    {StubBuildDate}");
                Log("========================================");
                Log($"Time:          {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                Log($"OS:            {Environment.OSVersion}");
                Log($"64-bit OS:     {Environment.Is64BitOperatingSystem}");
                Log($"Process path:  {Environment.ProcessPath}");
                Log($"Running admin: {IsRunningAsAdmin()}");
                if (isElevatedResume)
                {
                    Log($"Resumed temp:  {resumeTempDir}");
                    Log($"Resumed log:   {resumeLogPath}");
                }
                Log("========================================");

                if (isElevatedResume)
                    return await RunFromStep5Async(resumeTempDir!);

                return await RunFreshAsync();
            }
            catch (Exception ex)
            {
                LogError("UNHANDLED EXCEPTION IN MAIN", ex);
                ShowError($"An unexpected error occurred.\n\nError: {ex.Message}\n\nLog: {_logPath}", "Fatal Error");
                return 1;
            }
        }

        // ── Fresh (non-elevated) run: Steps 1-4 ──────────────────────────────

        private static async Task<int> RunFreshAsync()
        {
            string? tempExtractionPath = null;

            // STEP 1 — Extract payload bytes
            Log("");
            Log("STEP 1: Extracting payload from executable...");

            byte[] payloadData;
            try
            {
                payloadData = PayloadExtractor.ExtractPayloadFromEndOfFile();
                Log($"✅ Payload extracted: {FormatBytes(payloadData.Length)}");
            }
            catch (Exception ex)
            {
                LogError("FATAL: Failed to extract payload", ex);
                ShowError($"Failed to extract package payload.\n\nError: {ex.Message}\n\nLog: {_logPath}", "Extraction Failed");
                return 1;
            }

            // STEP 2 — Unzip to temp directory
            Log("");
            Log("STEP 2: Extracting to temporary directory...");

            try
            {
                tempExtractionPath = PayloadExtractor.ExtractPayloadToTempDirectory(payloadData);

                // FIX: switch log to install.log inside extraction dir NOW,
                // before anything else writes to it. No copy/delete race.
                string newLogPath = Path.Combine(tempExtractionPath, "install.log");
                try
                {
                    // Copy whatever we logged so far into the final log
                    if (!string.IsNullOrEmpty(_logPath) && File.Exists(_logPath))
                    {
                        var existing = File.ReadAllText(_logPath);
                        File.WriteAllText(newLogPath, existing);
                        // Safe to delete bootstrap log — we've flushed synchronously
                        try { File.Delete(_logPath); } catch { }
                    }
                    else
                    {
                        File.WriteAllText(newLogPath, "");
                    }
                    _logPath = newLogPath;
                }
                catch
                {
                    // Non-fatal: keep bootstrap log path if switch fails
                }

                Log($"✅ Extracted to: {tempExtractionPath}");
                Log("Extracted files:");
                foreach (var f in Directory.GetFiles(tempExtractionPath).OrderBy(x => x))
                    Log($"  - {Path.GetFileName(f)} ({FormatBytes(new FileInfo(f).Length)})");
            }
            catch (Exception ex)
            {
                LogError("FATAL: Failed to extract ZIP", ex);
                ShowError($"Failed to extract package contents.\n\nError: {ex.Message}", "Extraction Failed");
                return 1;
            }

            // STEP 3 — Load manifest
            Log("");
            Log("STEP 3: Loading package manifest...");

            string manifestPath = Path.Combine(tempExtractionPath!, "packitmeta.json");

            if (!File.Exists(manifestPath))
            {
                LogError($"Manifest not found: {manifestPath}", null);
                ShowError("Package manifest (packitmeta.json) not found.\n\nThis package may be corrupted.", "Invalid Package");
                return 1;
            }

            PackageManifest manifest;
            try
            {
                var manifestJson = await File.ReadAllTextAsync(manifestPath);
                var m = JsonSerializer.Deserialize<PackageManifest>(
                    manifestJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                manifest = m ?? throw new InvalidOperationException("Manifest deserialized to null.");
                if (manifest.Files == null) throw new InvalidOperationException("Manifest.Files is null.");

                Log($"✅ Loaded: '{manifest.PackageName}' v{manifest.Version}");
                Log($"   Files:          {manifest.Files.Count}");
                Log($"   Requires Admin: {manifest.RequiresAdmin}");
                Log($"   Cleanup:        {manifest.Cleanup}");
                Log($"   Has checksum:   {!string.IsNullOrEmpty(manifest.SHA256Checksum)}");

                // FEATURE: log detection results for each installer
                Log("Installers in manifest:");
                foreach (var file in manifest.Files.OrderBy(f => f.InstallOrder))
                {
                    var silentArgs = file.SilentArgs != null && file.SilentArgs.Length > 0
                        ? string.Join(" ", file.SilentArgs)
                        : $"[fallback: {string.Join(" ", InstallerDetector.GetSilentArgs(file.InstallType))}]";

                    // DetectionSource tells us how confident the type detection was:
                    //   "header"    = signature match in PE bytes (reliable)
                    //   "extension" = guessed from file extension only (⚠ lower confidence)
                    //   "manifest"  = user-specified (authoritative)
                    var confidence = file.DetectionSource switch
                    {
                        "header" => "header signature ✅",
                        "manifest" => "user-specified ✅",
                        "extension" => "extension only ⚠️",
                        _ => file.DetectionSource
                    };

                    Log($"   [{file.InstallOrder}] {file.Name}");
                    Log($"         Type:        {file.InstallType} (detected via: {confidence})");
                    Log($"         Silent args: {silentArgs}");
                    Log($"         Timeout:     {file.TimeoutMinutes} min");
                }
            }
            catch (Exception ex)
            {
                LogError("FATAL: Failed to parse manifest", ex);
                ShowError($"Could not read package manifest.\n\nError: {ex.Message}", "Invalid Manifest");
                return 1;
            }

            // STEP 4 — Admin elevation check
            Log("");
            Log("STEP 4: Checking administrator rights...");

            if (manifest.RequiresAdmin && !IsRunningAsAdmin())
            {
                Log("❌ Admin rights required — restarting elevated...");
                Log($"   Temp dir: {tempExtractionPath}");
                Log($"   Log path: {_logPath}");
                RestartElevated(tempExtractionPath!, _logPath);
                return 0; // parent exits; elevated child resumes from Step 5
            }

            Log($"✅ Admin check passed (is admin: {IsRunningAsAdmin()})");

            return await RunFromStep5Async(tempExtractionPath!);
        }

        // ── Steps 5-9 (shared by non-elevated admin run and elevated child) ───

        private static async Task<int> RunFromStep5Async(string tempExtractionPath)
        {
            // Reload manifest — elevated child has a fresh process context
            string manifestPath = Path.Combine(tempExtractionPath, "packitmeta.json");
            PackageManifest manifest;

            try
            {
                var manifestJson = await File.ReadAllTextAsync(manifestPath);
                var m = JsonSerializer.Deserialize<PackageManifest>(
                    manifestJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                manifest = m ?? throw new InvalidOperationException("Manifest null after reload.");
                if (manifest.Files == null) throw new InvalidOperationException("Manifest.Files null after reload.");
            }
            catch (Exception ex)
            {
                LogError("FATAL: Could not reload manifest", ex);
                ShowError($"Could not read manifest.\n\nError: {ex.Message}", "Invalid Manifest");
                return 1;
            }

            // STEP 5 — Integrity
            Log("");
            Log("STEP 5: Verifying package integrity...");

            if (!string.IsNullOrEmpty(manifest.SHA256Checksum))
            {
                try
                {
                    var actualHash = Convert.ToBase64String(
                        ComputeDirectoryHash(tempExtractionPath,
                            excludes: new[] { "packitmeta.json", "install.log" }));

                    if (actualHash == manifest.SHA256Checksum)
                    {
                        Log("✅ Integrity verified.");
                    }
                    else
                    {
                        LogError($"Hash mismatch!\n  Expected: {manifest.SHA256Checksum}\n  Actual:   {actualHash}", null);

                        var choice = MessageBox.Show(
                            "⚠️ Package integrity check FAILED.\n\n" +
                            "The files do not match what was originally packed.\n" +
                            "This could mean the package was modified or corrupted.\n\n" +
                            "Continue anyway? (Not recommended)",
                            "Integrity Check Failed",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning,
                            MessageBoxDefaultButton.Button2);

                        if (choice == DialogResult.No)
                        {
                            Log("Aborted by user after integrity failure.");
                            return 1;
                        }
                        Log("⚠️ User chose to continue despite integrity failure.");
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Integrity check exception", ex);
                    Log("Continuing after integrity check error...");
                }
            }
            else
            {
                Log("ℹ️  No checksum in manifest — skipping integrity check.");
            }

            // STEP 6 — Run installers
            Log("");
            Log("========================================");
            Log("STEP 6: RUNNING INSTALLERS");
            Log("========================================");

            if (manifest.Files.Count == 0)
            {
                LogError("No installers in manifest!", null);
                ShowError("The package lists no installers.", "Invalid Package");
                return 1;
            }

            var installStart = DateTime.Now;
            bool installSuccess = await RunInstallersWithExitCodeClassificationAsync(
                manifest.Files, tempExtractionPath);

            // STEP 7 — Optional post-install script
            if (!string.IsNullOrEmpty(manifest.AutoUpdateScript))
            {
                Log("");
                Log("STEP 7: Running post-install script...");
                var scriptPath = Path.Combine(tempExtractionPath, manifest.AutoUpdateScript);
                if (File.Exists(scriptPath))
                {
                    try
                    {
                        var proc = Process.Start(new ProcessStartInfo(scriptPath)
                        {
                            UseShellExecute = true,
                            WorkingDirectory = tempExtractionPath
                        });
                        proc?.WaitForExit();
                        Log($"Script exited: {proc?.ExitCode}");
                    }
                    catch (Exception ex) { LogError("Script failed", ex); }
                }
                else
                {
                    Log($"⚠️  Script not found: {scriptPath}");
                }
            }

            // STEP 8 — Completion dialog
            Log("");
            Log("========================================");
            Log("INSTALLATION COMPLETE");
            Log($"Overall success: {installSuccess}");
            Log($"Reboot required: {_rebootRequired}");
            Log($"Total duration:  {(DateTime.Now - installStart).TotalSeconds:0.0}s");
            Log($"Finished:        {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Log("========================================");

            string completionMessage = _rebootRequired
                ? $"✅ '{manifest.PackageName}' installed successfully!\n\n⚠️ A system restart is required to complete the installation."
                : installSuccess
                    ? $"✅ '{manifest.PackageName}' installed successfully!"
                    : $"⚠️ '{manifest.PackageName}' completed with errors.\n\nLog: {_logPath}";

            // On partial failure: proactively copy log to Desktop so users can find it
            if (!installSuccess && !string.IsNullOrEmpty(_logPath) && File.Exists(_logPath))
            {
                try
                {
                    string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string destName = $"PackItPro_install_log_{DateTime.Now:yyyyMMdd_HHmmss}.log";
                    string destPath = Path.Combine(desktop, destName);
                    File.Copy(_logPath, destPath, overwrite: true);
                    completionMessage += $"\n\nLog saved to Desktop:\n{destName}";
                    Log($"Log copied to Desktop: {destPath}");
                }
                catch (Exception ex)
                {
                    Log($"Could not copy log to Desktop: {ex.Message}");
                }
            }

            ShowCompletion(completionMessage, installSuccess);

            if (_rebootRequired)
                Log("NOTE: Reboot is required — user notified.");

            // STEP 9 — Cleanup
            if (manifest.Cleanup)
            {
                Log("");
                Log("STEP 9: Cleaning up...");
                Cleanup.CleanupTempDirectory(tempExtractionPath, true, Log, msg => LogError(msg, null));
            }
            else
            {
                Log($"STEP 9: Cleanup skipped. Temp dir retained: {tempExtractionPath}");
            }

            Log("STUB EXECUTION COMPLETED");
            return installSuccess ? 0 : 1;
        }

        // ── Installer runner with exit code classification ────────────────────

        private static async Task<bool> RunInstallersWithExitCodeClassificationAsync(
            List<ManifestFile> files, string tempDir)
        {
            bool allSuccess = true;
            var orderedFiles = files.OrderBy(f => f.InstallOrder).ToList();

            for (int i = 0; i < orderedFiles.Count; i++)
            {
                var file = orderedFiles[i];
                Log("");
                Log($"--- Installer {i + 1}/{orderedFiles.Count}: {file.Name} ---");
                Log($"    Type:        {file.InstallType}");

                // Determine args — manifest wins, InstallerDetector is fallback
                string[] silentArgs;
                if (file.SilentArgs != null && file.SilentArgs.Length > 0)
                {
                    silentArgs = file.SilentArgs;
                    Log($"    Silent args: {string.Join(" ", silentArgs)} (from manifest)");
                }
                else
                {
                    silentArgs = InstallerDetector.GetSilentArgs(file.InstallType);
                    Log($"    Silent args: {string.Join(" ", silentArgs)} (fallback via InstallerDetector)");
                }

                string filePath = Path.Combine(tempDir, file.Name);
                if (!File.Exists(filePath))
                {
                    LogError($"File not found: {filePath}", null);
                    allSuccess = false;
                    continue;
                }

                // Retry loop for exit code 1618 (another install in progress)
                int attempt = 0;
                const int MaxAttempts = 3;
                int exitCode = -1;

                while (attempt < MaxAttempts)
                {
                    attempt++;
                    if (attempt > 1)
                    {
                        Log("    Waiting for Windows Installer mutex...");
                        Log($"    Retry {attempt}/{MaxAttempts} (pausing 15 seconds — exit code 1618 means another install is in progress)...");
                        await Task.Delay(TimeSpan.FromSeconds(15));
                    }

                    var sw = Stopwatch.StartNew();

                    exitCode = await InstallerRunner.RunSingleInstallerAsync(
                        file, filePath, silentArgs,
                        Log, msg => LogError(msg, null));

                    sw.Stop();
                    Log($"    Duration:    {sw.Elapsed.TotalSeconds:0.0}s");

                    var result = ExitCodeClassifier.Classify(exitCode);
                    Log($"    Exit code:   {exitCode} → {ExitCodeClassifier.Describe(exitCode)}");

                    if (result == ExitCodeResult.AnotherInstallRunning && attempt < MaxAttempts)
                        continue; // retry

                    if (ExitCodeClassifier.IsSuccess(result))
                    {
                        Log($"    ✅ {file.Name} — {ExitCodeClassifier.Describe(exitCode)}");

                        if (result is ExitCodeResult.SuccessRebootRequired
                                   or ExitCodeResult.SuccessRebootInitiated)
                        {
                            _rebootRequired = true;
                            Log("    ⚠️  Reboot required flagged.");
                        }
                    }
                    else if (result == ExitCodeResult.UserCancelled)
                    {
                        Log($"    ⚠️  {file.Name} — cancelled by user.");
                        allSuccess = false;
                    }
                    else
                    {
                        LogError($"{file.Name} FAILED — {ExitCodeClassifier.Describe(exitCode)}", null);
                        allSuccess = false;
                    }

                    break; // don't retry if exit code was anything other than 1618
                }
            }

            return allSuccess;
        }

        #region Argument parsing

        /// <summary>
        /// Parses --key value and --key=value (with or without surrounding quotes on value).
        /// </summary>
        private static string? GetArgValue(string[] args, string key)
        {
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];

                // Form 1: --key=value  or  --key="value"
                if (arg.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                {
                    var val = arg.Substring(key.Length + 1);
                    return val.Trim('"');
                }

                // Form 2: --key value  or  --key "value"
                if (arg.Equals(key, StringComparison.OrdinalIgnoreCase) && i < args.Length - 1)
                {
                    var val = args[i + 1];
                    if (val.Length >= 2 && val[0] == '"' && val[^1] == '"')
                        val = val[1..^1];
                    return val;
                }
            }
            return null;
        }

        #endregion

        #region Integrity hash

        private static readonly HashSet<string> DefaultHashExclusions =
            new(StringComparer.OrdinalIgnoreCase) { "packitmeta.json", "install.log" };

        private static byte[] ComputeDirectoryHash(string directoryPath, string[]? excludes = null)
        {
            var exclusions = new HashSet<string>(DefaultHashExclusions, StringComparer.OrdinalIgnoreCase);
            if (excludes != null)
                foreach (var e in excludes) exclusions.Add(e);

            using var sha256 = SHA256.Create();
            var perFile = new List<byte[]>();
            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);

            foreach (var filePath in files)
            {
                if (exclusions.Contains(Path.GetFileName(filePath))) continue;

                byte[] fileHash;
                using (var fs = File.OpenRead(filePath))
                    fileHash = sha256.ComputeHash(fs);
                sha256.Initialize();

                var relPath = Path.GetRelativePath(directoryPath, filePath).Replace('\\', '/');
                var pathBytes = Encoding.UTF8.GetBytes(relPath);

                using var ms = new MemoryStream(pathBytes.Length + fileHash.Length);
                ms.Write(pathBytes);
                ms.Write(fileHash);
                ms.Position = 0;
                perFile.Add(sha256.ComputeHash(ms));
                sha256.Initialize();
            }

            if (perFile.Count == 0)
                throw new InvalidOperationException($"No hashable files in '{directoryPath}'.");

            perFile.Sort((a, b) =>
            {
                int len = Math.Min(a.Length, b.Length);
                for (int i = 0; i < len; i++) { int d = a[i].CompareTo(b[i]); if (d != 0) return d; }
                return a.Length.CompareTo(b.Length);
            });

            using var final = new MemoryStream(perFile.Count * 32);
            foreach (var h in perFile) final.Write(h);
            final.Position = 0;
            return sha256.ComputeHash(final);
        }

        #endregion

        #region Logging

        private static void DetectConsoleMode()
        {
            try { var _ = Console.WindowHeight; _consoleMode = true; }
            catch { _consoleMode = false; }
        }

        private static void WriteLogHeader()
        {
            try
            {
                File.WriteAllText(_logPath!,
                    "========================================\n" +
                    "PackItPro Stub Installer Log\n" +
                    $"Stub version: {StubVersion}  Build: {StubBuildDate}\n" +
                    $"Started:    {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                    $"Executable: {Environment.ProcessPath}\n" +
                    "========================================\n\n");
            }
            catch { }
        }

        private static void AppendElevationSeparator()
        {
            var content =
                "\n========================================\n" +
                $"[ELEVATED RESUME] {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                $"Process ID: {Process.GetCurrentProcess().Id}\n" +
                "========================================\n\n";
            lock (_logLock)
            {
                try { File.AppendAllText(_logPath!, content); } catch { }
            }
        }

        private static void Log(string message)
        {
            var entry = $"[{DateTime.Now:HH:mm:ss.fff}] {message}";
            if (!string.IsNullOrEmpty(_logPath))
            {
                lock (_logLock)
                {
                    try { File.AppendAllText(_logPath, entry + Environment.NewLine); } catch { }
                }
            }
            if (_consoleMode) Console.WriteLine(entry);
            Debug.WriteLine(entry);
        }

        private static void LogError(string message, Exception? ex)
        {
            var sb = new StringBuilder($"❌ ERROR: {message}\n");
            if (ex != null)
            {
                sb.AppendLine($"  Type:    {ex.GetType().Name}");
                sb.AppendLine($"  Message: {ex.Message}");
                if (ex.StackTrace != null) sb.AppendLine($"  Stack:   {ex.StackTrace.Trim()}");
                if (ex.InnerException != null) sb.AppendLine($"  Inner:   {ex.InnerException.Message}");
            }
            Log(sb.ToString().TrimEnd());
        }

        #endregion

        #region UI

        private static void ShowError(string message, string title)
        {
            // On failure: copy the log to the Desktop so the user can find it easily.
            // %TEMP%\PackItPro\{guid}\install.log is invisible to most users.
            // The Desktop copy survives cleanup and is findable without instructions.
            if (!string.IsNullOrEmpty(_logPath) && File.Exists(_logPath))
            {
                try
                {
                    string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string destName = $"PackItPro_install_log_{DateTime.Now:yyyyMMdd_HHmmss}.log";
                    string destPath = Path.Combine(desktop, destName);
                    File.Copy(_logPath, destPath, overwrite: true);
                    message += $"\n\nLog saved to Desktop:\n{destName}";
                    // Also still copy the path to clipboard as before
                    try { Clipboard.SetText(destPath); } catch { }
                }
                catch
                {
                    // Desktop copy failed (e.g. redirected Desktop, locked) —
                    // fall back to clipboard only
                    try
                    {
                        Clipboard.SetText(_logPath);
                        message += "\n\n(Log path copied to clipboard)";
                    }
                    catch { }
                }
            }
            MessageBox.Show(message, $"PackItPro — {title}", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private static void ShowCompletion(string message, bool success) =>
            MessageBox.Show(message, "PackItPro — Installation",
                MessageBoxButtons.OK,
                success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

        #endregion

        #region Utilities

        private static bool IsRunningAsAdmin()
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        private static void RestartElevated(string tempDir, string? logPath)
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
            {
                ShowError("Cannot determine executable path for elevation.", "Elevation Error");
                Environment.Exit(1);
                return;
            }

            var sb = new StringBuilder();

            // Pass through original args, skipping any stale --temp-dir / --log-path
            var originalArgs = Environment.GetCommandLineArgs().Skip(1).ToArray();
            foreach (var a in originalArgs)
            {
                if (a.StartsWith(ArgTempDir, StringComparison.OrdinalIgnoreCase)) continue;
                if (a.StartsWith(ArgLogPath, StringComparison.OrdinalIgnoreCase)) continue;
                sb.Append(a.Contains(' ') ? $"\"{a}\" " : $"{a} ");
            }

            if (!string.IsNullOrEmpty(tempDir))
                sb.Append($"{ArgTempDir} \"{tempDir}\" ");
            if (!string.IsNullOrEmpty(logPath))
                sb.Append($"{ArgLogPath} \"{logPath}\" ");

            Log($"Launching elevated with args: {sb.ToString().TrimEnd()}");

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    UseShellExecute = true,
                    FileName = exePath,
                    Arguments = sb.ToString().TrimEnd(),
                    Verb = "runas"
                });
                Environment.Exit(0);
            }
            catch (System.ComponentModel.Win32Exception)
            {
                ShowError("Administrator rights required but were denied.\n\nInstallation cancelled.", "UAC Denied");
                Environment.Exit(1);
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";
            string[] s = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes; int o = 0;
            while (v >= 1024 && o < s.Length - 1) { o++; v /= 1024; }
            return $"{v:0.##} {s[o]}";
        }

        #endregion
    }
}