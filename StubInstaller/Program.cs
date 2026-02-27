// StubInstaller/Program.cs
// Orchestrator only — owns the installation step sequence and nothing else.
// All helpers live in their own files; see the list in the header comment.
//
//   ArgParser.cs           — command-line parsing
//   Cleanup.cs             — temp directory removal with retry
//   Constants.cs           — version, file names, arg keys
//   ElevationHelper.cs     — IsRunningAsAdmin, RestartElevated
//   ExitCodeClassifier.cs  — installer exit code classification
//   InstallerDetector.cs   — silent arg lookup by installer type
//   InstallerRunner.cs     — process launch, stdout/stderr capture
//   IntegrityChecker.cs    — SHA-256 directory hash
//   Manifest.cs            — PackageManifest / ManifestFile models
//   PrerequisiteChecker.cs — disk space, OS version, architecture checks
//   StubLogger.cs          — log file state, Log/LogError
//   StubUI.cs              — ShowError, ShowCompletion dialogs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace StubInstaller
{
    internal class Program
    {
        // Spans Steps 6 and 8 — the one piece of run state Program genuinely owns.
        private static bool _rebootRequired;

        // ── Entry point ───────────────────────────────────────────────────────

        static async Task<int> Main(string[] args)
        {
            string? resumeTempDir = ArgParser.GetValue(args, Constants.ArgTempDir);
            string? resumeLogPath = ArgParser.GetValue(args, Constants.ArgLogPath);
            bool isElevatedResume = resumeTempDir != null && resumeLogPath != null;

            StubLogger.DetectConsoleMode();

            if (isElevatedResume)
            {
                StubLogger.LogPath = resumeLogPath!;
                StubLogger.AppendElevationSeparator();
            }
            else
            {
                // Bootstrap log in %TEMP% until the extraction dir is ready (Step 2)
                StubLogger.LogPath = Path.Combine(
                    Path.GetTempPath(),
                    $"PackItPro_Stub_{DateTime.Now:yyyyMMdd_HHmmss_fff}.log");
                StubLogger.WriteLogHeader(Constants.StubVersion, Constants.StubBuildDate);
            }

            try
            {
                LogBanner(isElevatedResume, resumeTempDir, resumeLogPath);

                return isElevatedResume
                    ? await RunFromStep5Async(resumeTempDir!)
                    : await RunFreshAsync();
            }
            catch (Exception ex)
            {
                StubLogger.LogError("UNHANDLED EXCEPTION IN MAIN", ex);
                StubUI.ShowError(
                    $"An unexpected error occurred.\n\nError: {ex.Message}\n\nLog: {StubLogger.LogPath}",
                    "Fatal Error");
                return 1;
            }
        }

        // ── STEPS 1–4: Fresh (non-elevated) run ──────────────────────────────

        private static async Task<int> RunFreshAsync()
        {
            // STEP 1 — Extract payload bytes from the end of this EXE
            StubLogger.Log("");
            StubLogger.Log("STEP 1: Extracting payload from executable...");
            byte[] payloadData;
            try
            {
                payloadData = PayloadExtractor.ExtractPayloadFromEndOfFile();
                StubLogger.Log($"✅ Payload: {Util.FormatBytes(payloadData.Length)}");
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to extract payload", ex);
                StubUI.ShowError($"Failed to extract the package payload.\n\nError: {ex.Message}", "Extraction Failed");
                return 1;
            }

            // STEP 2 — Unzip to temp directory; migrate log into extraction dir
            StubLogger.Log("");
            StubLogger.Log("STEP 2: Extracting to temporary directory...");
            string tempDir;
            try
            {
                tempDir = PayloadExtractor.ExtractPayloadToTempDirectory(payloadData);
                MigrateLogToTempDir(tempDir);

                StubLogger.Log($"✅ Extracted to: {tempDir}");
                StubLogger.Log("Extracted files:");
                foreach (var f in Directory.GetFiles(tempDir).OrderBy(x => x))
                    StubLogger.Log($"  {Path.GetFileName(f)}  ({Util.FormatBytes(new FileInfo(f).Length)})");
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to extract ZIP", ex);
                StubUI.ShowError($"Failed to extract package contents.\n\nError: {ex.Message}", "Extraction Failed");
                return 1;
            }

            // STEP 3 — Load manifest
            StubLogger.Log("");
            StubLogger.Log("STEP 3: Loading package manifest...");
            var manifest = await LoadManifestAsync(tempDir);
            if (manifest == null) return 1; // error shown inside LoadManifestAsync

            // STEP 3.5 — Prerequisites (disk, OS version, architecture)
            StubLogger.Log("");
            StubLogger.Log("STEP 3.5: Checking prerequisites...");
            var prereq = PrerequisiteChecker.Check(manifest, tempDir, StubLogger.Log);
            if (!prereq.Passed)
            {
                StubLogger.LogError("PREREQUISITES FAILED", null);
                foreach (var f in prereq.Failures)
                    StubLogger.Log($"  ✗ {f}");
                StubUI.ShowError(prereq.UserMessage, "Requirements Not Met");
                return 1;
            }
            StubLogger.Log("✅ Prerequisites met.");

            // STEP 4 — Elevation
            StubLogger.Log("");
            StubLogger.Log("STEP 4: Checking administrator rights...");
            if (manifest.RequiresAdmin && !ElevationHelper.IsRunningAsAdmin())
            {
                StubLogger.Log("Admin rights required — relaunching elevated...");
                StubLogger.Log($"  Temp dir: {tempDir}");
                StubLogger.Log($"  Log path: {StubLogger.LogPath}");
                ElevationHelper.RestartElevated(tempDir, StubLogger.LogPath);
                return 0; // this process exits; elevated child picks up at Step 5
            }
            StubLogger.Log($"✅ Running as admin: {ElevationHelper.IsRunningAsAdmin()}");

            return await RunFromStep5Async(tempDir);
        }

        // ── STEPS 5–9: Shared by non-elevated and elevated runs ───────────────

        private static async Task<int> RunFromStep5Async(string tempDir)
        {
            // Elevated child has a fresh process — reload the manifest
            var manifest = await LoadManifestAsync(tempDir);
            if (manifest == null) return 1;

            // STEP 5 — Integrity
            StubLogger.Log("");
            StubLogger.Log("STEP 5: Verifying package integrity...");
            if (!await VerifyIntegrityAsync(manifest, tempDir))
                return 1;

            // STEP 6 — Run installers
            StubLogger.Log("");
            StubLogger.Log("========================================");
            StubLogger.Log("STEP 6: RUNNING INSTALLERS");
            StubLogger.Log("========================================");

            if (manifest.Files.Count == 0)
            {
                StubLogger.LogError("No installers listed in manifest.", null);
                StubUI.ShowError("The package contains no installers.", "Invalid Package");
                return 1;
            }

            var installStart = DateTime.Now;
            bool installSuccess = await RunInstallersAsync(manifest.Files, tempDir);

            // STEP 7 — Optional post-install script
            await RunPostInstallScriptAsync(manifest, tempDir);

            // STEP 8 — Completion
            LogCompletionBanner(installSuccess, DateTime.Now - installStart);
            string completionMsg = BuildCompletionMessage(manifest.PackageName, installSuccess);
            StubUI.ShowCompletion(completionMsg, installSuccess);

            if (_rebootRequired)
                StubLogger.Log("NOTE: A reboot is required — user has been notified.");

            // STEP 9 — Cleanup
            StubLogger.Log("");
            if (manifest.Cleanup)
            {
                StubLogger.Log("STEP 9: Cleaning up...");
                Cleanup.CleanupTempDirectory(tempDir, true,
                    StubLogger.Log, msg => StubLogger.LogError(msg, null));
            }
            else
            {
                StubLogger.Log($"STEP 9: Cleanup skipped — temp dir retained: {tempDir}");
            }

            StubLogger.Log("STUB EXECUTION COMPLETED");
            return installSuccess ? 0 : 1;
        }

        // ── Installer loop ────────────────────────────────────────────────────

        private static async Task<bool> RunInstallersAsync(List<ManifestFile> files, string tempDir)
        {
            bool allSuccess = true;
            var ordered = files.OrderBy(f => f.InstallOrder).ToList();

            for (int i = 0; i < ordered.Count; i++)
            {
                var file = ordered[i];
                StubLogger.Log("");
                StubLogger.Log($"--- Installer {i + 1}/{ordered.Count}: {file.Name} ---");

                bool argsFromManifest = file.SilentArgs?.Length > 0;
                string[] silentArgs = argsFromManifest
                    ? file.SilentArgs!
                    : InstallerDetector.GetSilentArgs(file.InstallType);

                StubLogger.Log(argsFromManifest
                    ? $"  Silent args: {string.Join(" ", silentArgs)} (manifest)"
                    : $"  Silent args: {string.Join(" ", silentArgs)} (InstallerDetector fallback)");

                string filePath = Path.Combine(tempDir, file.Name);
                if (!File.Exists(filePath))
                {
                    StubLogger.LogError($"File not found: {filePath}", null);
                    allSuccess = false;
                    continue;
                }

                bool ok = await RunInstallerWithRetryAsync(file, filePath, silentArgs, tempDir);
                if (!ok) allSuccess = false;
            }

            return allSuccess;
        }

        private static async Task<bool> RunInstallerWithRetryAsync(
            ManifestFile file, string filePath, string[] silentArgs, string tempDir)
        {
            const int MaxAttempts = 3;

            for (int attempt = 1; attempt <= MaxAttempts; attempt++)
            {
                if (attempt > 1)
                {
                    StubLogger.Log($"  Waiting for Windows Installer mutex (retry {attempt}/{MaxAttempts} in 15s)...");
                    await Task.Delay(TimeSpan.FromSeconds(15));
                }

                var sw = Stopwatch.StartNew();
                int exitCode = await InstallerRunner.RunSingleInstallerAsync(
                    file, filePath, silentArgs, tempDir,
                    StubLogger.Log, msg => StubLogger.LogError(msg, null));
                sw.Stop();

                StubLogger.Log($"  Duration:  {sw.Elapsed.TotalSeconds:0.0}s");

                var result = ExitCodeClassifier.Classify(exitCode);
                StubLogger.Log($"  Exit code: {exitCode} → {ExitCodeClassifier.Describe(exitCode)}");

                if (result == ExitCodeResult.AnotherInstallRunning && attempt < MaxAttempts)
                    continue;

                if (ExitCodeClassifier.IsSuccess(result))
                {
                    StubLogger.Log($"  ✅ {file.Name} — {ExitCodeClassifier.Describe(exitCode)}");
                    if (result is ExitCodeResult.SuccessRebootRequired
                               or ExitCodeResult.SuccessRebootInitiated)
                    {
                        _rebootRequired = true;
                        StubLogger.Log("  ⚠️  Reboot flagged.");
                    }
                    return true;
                }

                if (result == ExitCodeResult.UserCancelled)
                    StubLogger.Log($"  ⚠️  {file.Name} — cancelled by user.");
                else
                    StubLogger.LogError($"{file.Name} FAILED — {ExitCodeClassifier.Describe(exitCode)}", null);

                return false;
            }

            return false; // exhausted retries
        }

        // ── Private helpers ───────────────────────────────────────────────────

        /// <summary>Loads and validates the manifest. Returns null and shows an error on failure.</summary>
        private static async Task<PackageManifest?> LoadManifestAsync(string tempDir)
        {
            string manifestPath = Path.Combine(tempDir, Constants.ManifestFileName);

            if (!File.Exists(manifestPath))
            {
                StubLogger.LogError($"Manifest not found: {manifestPath}", null);
                StubUI.ShowError(
                    $"Package manifest ({Constants.ManifestFileName}) not found.\n\nThis package may be corrupted.",
                    "Invalid Package");
                return null;
            }

            try
            {
                var json = await File.ReadAllTextAsync(manifestPath);
                var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var m = JsonSerializer.Deserialize<PackageManifest>(json, opts)
                           ?? throw new InvalidOperationException("Deserialized to null.");

                if (m.Files == null)
                    throw new InvalidOperationException("Manifest.Files is null.");

                StubLogger.Log($"✅ Manifest: '{m.PackageName}' v{m.Version}  " +
                               $"({m.Files.Count} file(s), admin={m.RequiresAdmin}, cleanup={m.Cleanup})");

                StubLogger.Log("  Installers:");
                foreach (var f in m.Files.OrderBy(f => f.InstallOrder))
                {
                    string argsDisplay = f.SilentArgs?.Length > 0
                        ? string.Join(" ", f.SilentArgs)
                        : $"[fallback: {string.Join(" ", InstallerDetector.GetSilentArgs(f.InstallType))}]";
                    string confidence = f.DetectionSource switch
                    {
                        "header" => "header ✅",
                        "manifest" => "manifest ✅",
                        _ => "extension ⚠️",
                    };
                    StubLogger.Log($"    [{f.InstallOrder}] {f.Name}  type={f.InstallType} ({confidence})  args={argsDisplay}  timeout={f.TimeoutMinutes}m");
                }

                return m;
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to parse manifest", ex);
                StubUI.ShowError($"Could not read the package manifest.\n\nError: {ex.Message}", "Invalid Manifest");
                return null;
            }
        }

        /// <summary>Returns true if integrity is verified or skipped, false if the user aborts.</summary>
        private static async Task<bool> VerifyIntegrityAsync(PackageManifest manifest, string tempDir)
        {
            if (string.IsNullOrEmpty(manifest.SHA256Checksum))
            {
                StubLogger.Log("ℹ️  No checksum in manifest — integrity check skipped.");
                return true;
            }

            try
            {
                string actual = Convert.ToBase64String(
                    IntegrityChecker.ComputeDirectoryHash(tempDir));

                if (actual == manifest.SHA256Checksum)
                {
                    StubLogger.Log("✅ Integrity verified.");
                    return true;
                }

                StubLogger.LogError(
                    $"Hash mismatch!\n  Expected: {manifest.SHA256Checksum}\n  Actual:   {actual}", null);

                var choice = MessageBox.Show(
                    "⚠️ Package integrity check FAILED.\n\n" +
                    "The files may have been modified or corrupted since packaging.\n\n" +
                    "Continue anyway? (Not recommended)",
                    "Integrity Check Failed",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);

                if (choice == DialogResult.No)
                {
                    StubLogger.Log("Installation aborted by user after integrity failure.");
                    return false;
                }

                StubLogger.Log("⚠️ User chose to continue despite integrity failure.");
                return true;
            }
            catch (Exception ex)
            {
                StubLogger.LogError("Integrity check threw an exception — continuing", ex);
                return true; // don't block on a check error
            }

            // satisfy compiler — unreachable
            await Task.CompletedTask;
        }

        private static async Task RunPostInstallScriptAsync(PackageManifest manifest, string tempDir)
        {
            if (string.IsNullOrEmpty(manifest.AutoUpdateScript)) return;

            StubLogger.Log("");
            StubLogger.Log("STEP 7: Running post-install script...");
            string scriptPath = Path.Combine(tempDir, manifest.AutoUpdateScript);

            if (!File.Exists(scriptPath))
            {
                StubLogger.Log($"⚠️  Script not found: {scriptPath}");
                return;
            }

            try
            {
                var proc = Process.Start(new ProcessStartInfo(scriptPath)
                {
                    UseShellExecute = true,
                    WorkingDirectory = tempDir,
                });
                proc?.WaitForExit();
                StubLogger.Log($"Script exited with code: {proc?.ExitCode}");
            }
            catch (Exception ex)
            {
                StubLogger.LogError("Post-install script failed", ex);
            }

            await Task.CompletedTask;
        }

        /// <summary>Atomically switches the log from the bootstrap temp file to install.log
        /// inside the extraction dir, copying existing content first.</summary>
        private static void MigrateLogToTempDir(string tempDir)
        {
            string newLogPath = Path.Combine(tempDir, Constants.LogFileName);
            try
            {
                string existing = !string.IsNullOrEmpty(StubLogger.LogPath) && File.Exists(StubLogger.LogPath)
                    ? File.ReadAllText(StubLogger.LogPath)
                    : string.Empty;

                File.WriteAllText(newLogPath, existing);
                try { File.Delete(StubLogger.LogPath!); } catch { }
                StubLogger.LogPath = newLogPath;
            }
            catch { /* Non-fatal: keep the bootstrap log path */ }
        }

        private static string BuildCompletionMessage(string packageName, bool success)
        {
            if (_rebootRequired)
                return $"✅ '{packageName}' installed successfully!\n\n" +
                       "⚠️ A system restart is required to complete the installation.";
            if (success)
                return $"✅ '{packageName}' installed successfully!";
            return $"⚠️ '{packageName}' completed with errors.\n\nLog: {StubLogger.LogPath}";
        }

        private static void LogBanner(bool isElevated, string? resumeTempDir, string? resumeLogPath)
        {
            StubLogger.Log("========================================");
            StubLogger.Log($"PackItPro Stub Installer v{Constants.StubVersion}" +
                           (isElevated ? " [ELEVATED]" : ""));
            StubLogger.Log($"Build:         {Constants.StubBuildDate}");
            StubLogger.Log("========================================");
            StubLogger.Log($"Time:          {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            StubLogger.Log($"OS:            {Environment.OSVersion}");
            StubLogger.Log($"64-bit:        {Environment.Is64BitOperatingSystem}");
            StubLogger.Log($"Process:       {Environment.ProcessPath}");
            StubLogger.Log($"Admin:         {ElevationHelper.IsRunningAsAdmin()}");
            if (isElevated)
            {
                StubLogger.Log($"Resumed temp:  {resumeTempDir}");
                StubLogger.Log($"Resumed log:   {resumeLogPath}");
            }
            StubLogger.Log("========================================");
        }

        private static void LogCompletionBanner(bool success, TimeSpan duration)
        {
            StubLogger.Log("");
            StubLogger.Log("========================================");
            StubLogger.Log("INSTALLATION COMPLETE");
            StubLogger.Log($"Success:         {success}");
            StubLogger.Log($"Reboot required: {_rebootRequired}");
            StubLogger.Log($"Total duration:  {duration.TotalSeconds:0.0}s");
            StubLogger.Log($"Finished:        {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            StubLogger.Log("========================================");
        }
    }
}