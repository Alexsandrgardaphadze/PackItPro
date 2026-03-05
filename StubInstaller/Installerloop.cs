// StubInstaller/InstallerLoop.cs - v1.0
// Runs all installers in order with per-installer retry logic.
// Extracted from Program.cs so the retry/exit-code handling lives here alone.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace StubInstaller
{
    internal static class InstallerLoop
    {
        /// <summary>
        /// Runs all files in manifest order. Returns true only if every installer succeeded.
        /// Sets InstallOrchestrator.RebootRequired if any installer returns 3010/1641.
        /// </summary>
        internal static async Task<bool> RunAllAsync(List<ManifestFile> files, string tempDir)
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

                bool ok = await RunWithRetryAsync(file, filePath, silentArgs, tempDir);
                if (!ok) allSuccess = false;
            }

            return allSuccess;
        }

        // ── Retry loop ────────────────────────────────────────────────────────

        private static async Task<bool> RunWithRetryAsync(
            ManifestFile file, string filePath, string[] silentArgs, string tempDir)
        {
            const int MaxAttempts = 3;

            for (int attempt = 1; attempt <= MaxAttempts; attempt++)
            {
                if (attempt > 1)
                {
                    StubLogger.Log(
                        $"  Waiting for Windows Installer mutex " +
                        $"(retry {attempt}/{MaxAttempts} in 15s)...");
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

                // Retry only on "another install running" and only if we have attempts left
                if (result == ExitCodeResult.AnotherInstallRunning && attempt < MaxAttempts)
                    continue;

                if (ExitCodeClassifier.IsSuccess(result))
                {
                    StubLogger.Log($"  ✅ {file.Name} — {ExitCodeClassifier.Describe(exitCode)}");

                    if (result is ExitCodeResult.SuccessRebootRequired
                               or ExitCodeResult.SuccessRebootInitiated)
                    {
                        InstallOrchestrator.FlagReboot();
                        StubLogger.Log("  ⚠️  Reboot flagged.");
                    }
                    return true;
                }

                if (result == ExitCodeResult.UserCancelled)
                    StubLogger.Log($"  ⚠️  {file.Name} — cancelled by user.");
                else
                    StubLogger.LogError(
                        $"{file.Name} FAILED — {ExitCodeClassifier.Describe(exitCode)}", null);

                return false;
            }

            return false; // exhausted retries
        }
    }
}