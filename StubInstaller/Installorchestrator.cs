// StubInstaller/InstallOrchestrator.cs - v1.0
// Owns the full installation step sequence.
// Extracted from Program.cs to keep the entry point thin.
//
// Step map:
//   Fresh run (non-elevated):
//     1  Extract payload from EXE tail
//     2  Unzip to temp dir, migrate log
//     3  Load manifest
//     3.5 Check prerequisites
//     4  Elevation (re-launch if needed)
//     → hands off to RunFromStep5Async
//
//   Elevated resume (and non-elevated when no elevation needed):
//     5  Verify SHA-256 integrity
//     5.5 AMSI scan all extracted installers
//     6  Run installers (with retry)
//     7  Post-install script
//     8  Completion dialog
//     9  Cleanup temp dir

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace StubInstaller
{
    internal static class InstallOrchestrator
    {
        // Shared across Steps 6 and 8 within one run.
        // Static is fine because only one installation runs at a time.
        internal static bool RebootRequired { get; private set; }

        // ── Entry point called by Program.Main ────────────────────────────────

        internal static async Task<int> RunAsync(string[] args)
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
                StubLogger.LogPath = Path.Combine(
                    Path.GetTempPath(),
                    $"PackItPro_Stub_{DateTime.Now:yyyyMMdd_HHmmss_fff}.log");
                StubLogger.WriteLogHeader(Constants.StubVersion, Constants.StubBuildDate);
            }

            LogBanner(isElevatedResume, resumeTempDir, resumeLogPath);

            return isElevatedResume
                ? await RunFromStep5Async(resumeTempDir!)
                : await RunFreshAsync();
        }

        // ── STEPS 1–4: Fresh (non-elevated) run ──────────────────────────────

        private static async Task<int> RunFreshAsync()
        {
            // ── STEP 1: Extract payload ───────────────────────────────────────
            StubLogger.Log("");
            StubLogger.Log("STEP 1: Extracting payload from executable...");
            byte[] payloadData;
            try
            {
                payloadData = PayloadExtractor.ExtractPayloadFromEndOfFile();
                StubLogger.Log($"✅ Payload: {Util.FormatBytes(payloadData.Length)}");
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("PAYLOAD INTEGRITY CHECK FAILED"))
            {
                StubLogger.LogError("FATAL: Payload integrity verification failed", ex);
                StubUI.ShowError(
                    $"Package integrity check failed!\n\n" +
                    $"The payload may have been corrupted or tampered with.\n\n" +
                    $"Error: {ex.Message}\n\n" +
                    $"Installation cannot proceed.",
                    "Integrity Verification Failed");
                return 1;
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to extract payload", ex);
                StubUI.ShowError($"Failed to extract the package payload.\n\nError: {ex.Message}", "Extraction Failed");
                return 1;
            }

            // ── STEP 2: Unzip to temp dir ─────────────────────────────────────
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

            // ── STEP 3: Load manifest ─────────────────────────────────────────
            StubLogger.Log("");
            StubLogger.Log("STEP 3: Loading package manifest...");
            var manifest = await ManifestLoader.LoadAsync(tempDir);
            if (manifest == null) return 1;

            // ── STEP 3.5: Prerequisites ───────────────────────────────────────
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

            // ── STEP 4: Elevation ─────────────────────────────────────────────
            StubLogger.Log("");
            StubLogger.Log("STEP 4: Checking administrator rights...");
            if (manifest.RequiresAdmin && !ElevationHelper.IsRunningAsAdmin())
            {
                StubLogger.Log("Admin rights required — relaunching elevated...");
                StubLogger.Log($"  Temp dir: {tempDir}");
                StubLogger.Log($"  Log path: {StubLogger.LogPath}");
                ElevationHelper.RestartElevated(tempDir, StubLogger.LogPath);
                return 0; // current process exits; elevated child resumes at Step 5
            }
            StubLogger.Log($"✅ Running as admin: {ElevationHelper.IsRunningAsAdmin()}");

            return await RunFromStep5Async(tempDir);
        }

        // ── STEPS 5–9: Shared by non-elevated and elevated runs ───────────────

        internal static async Task<int> RunFromStep5Async(string tempDir)
        {
            // Elevated child is a fresh process — reload manifest
            var manifest = await ManifestLoader.LoadAsync(tempDir);
            if (manifest == null) return 1;

            // ── STEP 5: SHA-256 integrity ──────────────────────────────────────
            StubLogger.Log("");
            StubLogger.Log("STEP 5: Verifying package integrity...");
            if (!IntegrityVerifier.Verify(manifest, tempDir))
                return 1;

            // ── STEP 5.5: AMSI scan ────────────────────────────────────────────
            StubLogger.Log("");
            StubLogger.Log("STEP 5.5: Scanning installers with local AV engine (AMSI)...");
            if (!AmsiStep.ScanAll(manifest.Files, tempDir))
                return 1;

            // ── STEP 6: Run installers ─────────────────────────────────────────
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
            bool installSuccess = await InstallerLoop.RunAllAsync(manifest.Files, tempDir);

            // ── STEP 7: Post-install script ────────────────────────────────────
            await PostInstallRunner.RunAsync(manifest, tempDir);

            // ── STEP 8: Completion ─────────────────────────────────────────────
            LogCompletionBanner(installSuccess, DateTime.Now - installStart);
            string completionMsg = BuildCompletionMessage(manifest.PackageName, installSuccess);
            StubUI.ShowCompletion(completionMsg, installSuccess);

            if (RebootRequired)
                StubLogger.Log("NOTE: A reboot is required — user has been notified.");

            // ── STEP 9: Cleanup ────────────────────────────────────────────────
            StubLogger.Log("");
            if (manifest.Cleanup)
            {
                StubLogger.Log("STEP 9: Cleaning up...");
                await Cleanup.CleanupTempDirectoryAsync(tempDir, true,
                    StubLogger.Log, msg => StubLogger.LogError(msg, null));
            }
            else
            {
                StubLogger.Log($"STEP 9: Cleanup skipped — temp dir retained: {tempDir}");
            }

            StubLogger.Log("STUB EXECUTION COMPLETED");
            return installSuccess ? 0 : 1;
        }

        // ── Called by InstallerLoop to flag a reboot ──────────────────────────

        internal static void FlagReboot() => RebootRequired = true;

        // ── Private helpers ───────────────────────────────────────────────────

        /// <summary>
        /// Moves the bootstrap log (written to %TEMP% before we had a tempDir)
        /// into install.log inside the extraction directory.
        /// Non-fatal — if this fails we keep writing to the bootstrap path.
        /// </summary>
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
            catch { /* non-fatal */ }
        }

        private static string BuildCompletionMessage(string packageName, bool success)
        {
            if (RebootRequired)
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
            StubLogger.Log($"Reboot required: {RebootRequired}");
            StubLogger.Log($"Total duration:  {duration.TotalSeconds:0.0}s");
            StubLogger.Log($"Finished:        {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            StubLogger.Log("========================================");
        }
    }
}