// StubInstaller/InstallerRunner.cs - v2.2
// Changes vs v2.1:
//   [1] WorkingDirectory set to the installer's own directory in both RunExeAsync
//       and RunMsiAsync. Many installers look for relative-path resources (data,
//       cabs, helpers) in their own folder. Without WorkingDirectory, they launch,
//       find nothing, and exit with code 0 — appearing to succeed while installing
//       nothing. This is one of the most common silent-install failure patterns.
//   [2] Full command-line logging: each launch now logs the complete command line
//       and working directory on separate lines, matching enterprise installer logs.
//       Format: "Command line: / <exe> <args>" then "Working dir: <path>"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace StubInstaller
{
    public static class InstallerRunner
    {
        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Runs all installers in the manifest. Returns true if all completed
        /// with a successful exit code (including 3010 / 1641).
        /// Called by Program.cs for the non-exit-code-aware path.
        /// </summary>
        public static async Task<bool> RunInstallersAsync(
            List<ManifestFile> files,
            string tempDir,
            Action<string> logInfo,
            Action<string> logError)
        {
            bool allSuccess = true;
            foreach (var file in files.OrderBy(f => f.InstallOrder))
            {
                string filePath = Path.Combine(tempDir, file.Name);
                if (!File.Exists(filePath))
                {
                    logError($"File not found: {filePath}");
                    allSuccess = false;
                    continue;
                }

                var silentArgs = ResolveSilentArgs(file, logInfo);
                int exitCode = await RunSingleInstallerAsync(file, filePath, silentArgs, logInfo, logError);

                var result = ExitCodeClassifier.Classify(exitCode);
                logInfo($"Result: {ExitCodeClassifier.Describe(exitCode)}");

                if (!ExitCodeClassifier.IsSuccess(result))
                    allSuccess = false;
            }
            return allSuccess;
        }

        /// <summary>
        /// Runs a single installer file and returns the raw process exit code.
        /// The caller is responsible for interpreting the exit code.
        /// </summary>
        public static async Task<int> RunSingleInstallerAsync(
            ManifestFile file,
            string filePath,
            string[] silentArgs,
            Action<string> logInfo,
            Action<string> logError)
        {
            string extension = Path.GetExtension(filePath).ToLowerInvariant();
            int timeoutMs = file.TimeoutMinutes * 60 * 1000;

            logInfo($"Installing: {file.Name}");
            logInfo($"  Type:        {file.InstallType} (detected via: {file.DetectionSource switch
            {
                "header" => "header signature ✅",
                "manifest" => "user-specified ✅",
                _ => "extension only ⚠️"
            }})");
            logInfo($"  Silent args: {(silentArgs.Length > 0 ? string.Join(" ", silentArgs) : "(none)")}");
            logInfo($"  Timeout:     {file.TimeoutMinutes} min");

            // Known limitation notice for Squirrel/Electron installers.
            // These run a custom splash screen before the Squirrel engine reads --silent,
            // so a brief UI flash is expected and cannot be suppressed from the outside.
            // This is an upstream bug in the installer, not in PackItPro.
            if (file.InstallType == "squirrel")
            {
                logInfo("  ⚠️  NOTE: Squirrel/Electron installers (e.g. UniGetUI, Discord, Slack) may");
                logInfo("      briefly show a window before --silent takes effect. This is a known");
                logInfo("      upstream limitation and does not affect the installation outcome.");
            }

            try
            {
                return extension switch
                {
                    ".msi" => await RunMsiAsync(filePath, silentArgs, timeoutMs, logInfo, logError),
                    ".msp" => await RunMsiAsync(filePath, silentArgs, timeoutMs, logInfo, logError),
                    _ => await RunExeAsync(filePath, silentArgs, timeoutMs, logInfo, logError),
                };
            }
            catch (OperationCanceledException)
            {
                logError($"TIMEOUT: {file.Name} did not complete within {file.TimeoutMinutes} minutes.");
                return -1;
            }
            catch (Exception ex)
            {
                logError($"Exception running {file.Name}: {ex.Message}\n  {ex.GetType().Name}");
                return -1;
            }
        }

        /// <summary>
        /// Resolves the silent args to use for an installer, logging the source.
        /// Manifest args take priority; InstallerDetector is the fallback.
        /// </summary>
        public static string[] ResolveSilentArgs(ManifestFile file, Action<string> logInfo)
        {
            if (file.SilentArgs != null && file.SilentArgs.Length > 0)
            {
                logInfo($"  Args source: manifest → {string.Join(" ", file.SilentArgs)}");
                return file.SilentArgs;
            }

            var fallback = InstallerDetector.GetSilentArgs(file.InstallType);
            logInfo($"  Args source: InstallerDetector fallback (type={file.InstallType}) → " +
                    (fallback.Length > 0 ? string.Join(" ", fallback) : "(none)"));
            return fallback;
        }

        // ── Private runners ───────────────────────────────────────────────────

        private static async Task<int> RunMsiAsync(
            string filePath,
            string[] silentArgs,
            int timeoutMs,
            Action<string> logInfo,
            Action<string> logError)
        {
            var argParts = new List<string> { $"/i \"{filePath}\"" };
            argParts.AddRange(silentArgs);
            string arguments = string.Join(" ", argParts);
            // MSI working dir is the file's directory so relative transforms/cabs resolve
            string workingDir = Path.GetDirectoryName(filePath) ?? Directory.GetCurrentDirectory();

            logInfo("  Command line:");
            logInfo($"    msiexec.exe {arguments}");
            logInfo($"  Working dir: {workingDir}");

            var psi = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir,  // FIX: relative cabs/transforms now found
            };

            return await RunProcessWithTimeoutAsync(psi, timeoutMs, logInfo, logError);
        }

        private static async Task<int> RunExeAsync(
            string filePath,
            string[] silentArgs,
            int timeoutMs,
            Action<string> logInfo,
            Action<string> logError)
        {
            string arguments = string.Join(" ", silentArgs);
            // FIX: set working directory to the installer's own directory.
            // Many installers expect to find relative-path resources (data files,
            // cab archives, helper EXEs) in the same folder they live in.
            // Without this, they launch, find nothing, and exit silently with code 0.
            string workingDir = Path.GetDirectoryName(filePath) ?? Directory.GetCurrentDirectory();

            logInfo("  Command line:");
            logInfo($"    \"{filePath}\" {arguments}");
            logInfo($"  Working dir: {workingDir}");

            var psi = new ProcessStartInfo
            {
                FileName = filePath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir,  // FIX: was missing — broke relative-path installers
            };

            return await RunProcessWithTimeoutAsync(psi, timeoutMs, logInfo, logError);
        }

        private static async Task<int> RunProcessWithTimeoutAsync(
            ProcessStartInfo psi,
            int timeoutMs,
            Action<string> logInfo,
            Action<string> logError)
        {
            using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
            using var cts = new CancellationTokenSource(timeoutMs);

            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            process.Exited += (s, e) => tcs.TrySetResult(process.ExitCode);

            using var _ = cts.Token.Register(() =>
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                tcs.TrySetCanceled();
            });

            process.Start();
            logInfo($"  PID: {process.Id}");

            int exitCode = await tcs.Task; // throws OperationCanceledException on timeout
            logInfo($"  Exited with code: {exitCode}");
            return exitCode;
        }
    }
}