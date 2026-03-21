// StubInstaller/Program.Startup.cs
// Steps 1-4 (pre-install checks) and the WPF window launch.
using StubInstaller.Core;
using StubInstaller.Infrastrucure;
using StubInstaller.ViewModels;
using StubInstaller.Views;
using System;
using System.Threading.Tasks;
using System.Windows.Threading;
using WpfApp = System.Windows.Application;

namespace StubInstaller
{
    internal partial class Program
    {
        /// <summary>
        /// Runs Steps 1-4 synchronously before the WPF window opens:
        /// extraction → manifest load → prerequisites → elevation check.
        /// Returns Early(code) on any failure or elevation re-launch.
        /// Returns Ready(tempDir, manifest) when the window should open.
        /// </summary>
        private static PreInstallResult RunPreInstallSteps(
            bool isElevatedResume, string? resumeTempDir)
        {
            if (isElevatedResume)
            {
                var manifest = LoadManifestSync(resumeTempDir!);
                if (manifest == null) return PreInstallResult.Early(1);
                return PreInstallResult.Ready(resumeTempDir!, manifest);
            }

            // STEPS 1+2 — Extract payload
            StubLogger.Log("");
            StubLogger.Log("STEP 1+2: Extracting and decompressing payload...");
            string tempDir;
            try
            {
                tempDir = PayloadExtractor.ExtractAndDecompressPayload();
                MigrateLogToTempDir(tempDir);
                StubLogger.Log($"✅ Extracted to: {tempDir}");
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("PAYLOAD INTEGRITY CHECK FAILED"))
            {
                StubLogger.LogError("FATAL: Payload integrity verification failed", ex);
                ShowError(
                    "Package integrity check failed!\n\nThe payload may have been corrupted or tampered with.\n\n" +
                    $"Error: {ex.Message}\n\nInstallation cannot proceed.",
                    "Integrity Verification Failed");
                return PreInstallResult.Early(1);
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to extract payload", ex);
                ShowError($"Failed to extract the package payload.\n\nError: {ex.Message}", "Extraction Failed");
                return PreInstallResult.Early(1);
            }

            // STEP 3 — Load manifest
            StubLogger.Log("");
            StubLogger.Log("STEP 3: Loading package manifest...");
            var mf = LoadManifestSync(tempDir);
            if (mf == null) return PreInstallResult.Early(1);

            // STEP 3.5 — Prerequisites
            StubLogger.Log("");
            StubLogger.Log("STEP 3.5: Checking prerequisites...");
            var prereq = PrerequisiteChecker.Check(mf, tempDir, StubLogger.Log);
            if (!prereq.Passed)
            {
                StubLogger.LogError("PREREQUISITES FAILED", null);
                foreach (var f in prereq.Failures) StubLogger.Log($"  ✗ {f}");
                ShowError(prereq.UserMessage, "Requirements Not Met");
                return PreInstallResult.Early(1);
            }
            StubLogger.Log("✅ Prerequisites met.");

            // STEP 4 — Elevation
            StubLogger.Log("");
            StubLogger.Log("STEP 4: Checking administrator rights...");
            if (mf.RequiresAdmin && !ElevationHelper.IsRunningAsAdmin())
            {
                StubLogger.Log("Admin rights required — relaunching elevated...");
                ElevationHelper.RestartElevated(tempDir, StubLogger.LogPath);
                return PreInstallResult.Early(0);
            }
            StubLogger.Log($"✅ Running as admin: {ElevationHelper.IsRunningAsAdmin()}");

            return PreInstallResult.Ready(tempDir, mf);
        }

        /// <summary>
        /// Launches the WPF Application and MainInstallWindow.
        /// Blocks until the window closes and returns the exit code.
        /// </summary>
        private static int RunWpfInstaller(string tempDir, PackageManifest manifest)
        {
            StubLogger.Log("");
            StubLogger.Log("STEP 5+: Launching WPF installer window...");

            var app = new WpfApp
            {
                ShutdownMode = System.Windows.ShutdownMode.OnMainWindowClose
            };

            int exitCode = 0;

            app.Startup += (_, _) =>
            {
                var vm = new MainInstallViewModel(manifest, tempDir, Dispatcher.CurrentDispatcher);
                var window = new MainInstallWindow(vm);

                window.Closed += (_, _) =>
                {
                    exitCode = vm.InstallSucceeded ? 0 : 1;
                    StubLogger.Log($"Window closed. Success={vm.InstallSucceeded}");

                    // Always copy log to Desktop on close — both success and failure.
                    // On failure essential for bug reports; on success useful confirmation.
                    try
                    {
                        string? desk = StubLogger.TryCopyLogToDesktop(Constants.DesktopLogPrefix);
                        if (desk != null)
                            StubLogger.Log($"Log copied to Desktop: {System.IO.Path.GetFileName(desk)}");
                    }
                    catch { }

                    if (manifest.Cleanup)
                        _ = System.Threading.Tasks.Task.Run(async () =>
                            await Cleanup.CleanupTempDirectoryAsync(
                                tempDir, true,
                                StubLogger.Log,
                                msg => StubLogger.LogError(msg, null)));
                };

                app.MainWindow = window;
                window.Show();
            };

            app.Run();
            return exitCode;
        }
    }
}