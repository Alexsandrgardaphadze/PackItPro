// StubInstaller/InstallerRunner.cs - v2.4
// Changes vs v2.3:
//   [1] Installer name prefix on all captured output lines.
//       Format: "[npp.8.7.4.Installer.x64.exe OUT] ..."
//               "[npp.8.7.4.Installer.x64.exe ERR] ..."
//       Makes multi-installer logs readable at a glance without scrolling back
//       to find which installer header a given output line belongs to.
//
//   [2] Buffer-then-conditional-flush for stdout/stderr.
//       Lines are accumulated in memory during the run. On SUCCESS the buffer is
//       discarded — successful installs produce no [OUT]/[ERR] noise in the log.
//       On FAILURE (non-zero, non-reboot exit code) the full buffer is flushed
//       to the log so the complete output is available for diagnosis.
//       This keeps clean install logs concise while preserving full detail
//       for the cases that actually need it.
//       Thread safety: List<string> access is locked since DataReceived callbacks
//       fire on arbitrary thread pool threads.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace StubInstaller
{
    public static class InstallerRunner
    {
        // ── [4] String constants ──────────────────────────────────────────────
        // Must stay in sync with ManifestGenerator.cs and InstallerDetector.cs

        public const string TypeMsi = "msi";
        public const string TypeMsp = "msp";
        public const string TypeInno = "inno";
        public const string TypeNsis = "nsis";
        public const string TypeSquirrel = "squirrel";
        public const string TypeBurn = "burn";
        public const string TypeExe = "exe";
        public const string TypeAppx = "appx";
        public const string TypeMsix = "msix";
        public const string TypeFile = "file";

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Runs all installers in order. Returns true if all succeeded
        /// (including 3010/1641 which mean success + reboot required).
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
                // [3] Validate path before anything else
                if (!TryResolveSafePath(tempDir, file.Name, out string filePath, out string? pathError))
                {
                    logError($"SECURITY: {pathError} — skipping {file.Name}");
                    allSuccess = false;
                    continue;
                }

                if (!File.Exists(filePath))
                {
                    logError($"File not found: {filePath}");
                    allSuccess = false;
                    continue;
                }

                var silentArgs = ResolveSilentArgs(file, logInfo);
                int exitCode = await RunSingleInstallerAsync(file, filePath, silentArgs, tempDir, logInfo, logError);

                var result = ExitCodeClassifier.Classify(exitCode);
                logInfo($"Result: {ExitCodeClassifier.Describe(exitCode)}");

                if (!ExitCodeClassifier.IsSuccess(result))
                    allSuccess = false;
            }
            return allSuccess;
        }

        /// <summary>
        /// Runs one installer and returns the raw exit code.
        /// Caller interprets via ExitCodeClassifier.
        /// </summary>
        public static async Task<int> RunSingleInstallerAsync(
            ManifestFile file,
            string filePath,
            string[] silentArgs,
            string tempDir,
            Action<string> logInfo,
            Action<string> logError)
        {
            int timeoutMs = file.TimeoutMinutes * 60 * 1000;

            logInfo($"Installing: {file.Name}");
            logInfo($"  Type:        {file.InstallType} (detected via: {DescribeSource(file.DetectionSource)})");
            logInfo($"  Silent args: {(silentArgs.Length > 0 ? string.Join(" ", silentArgs) : "(none)")}");
            logInfo($"  Timeout:     {file.TimeoutMinutes} min");

            if (file.InstallType == TypeSquirrel)
            {
                logInfo("  ⚠️  NOTE: Squirrel/Electron installers may briefly show a window before");
                logInfo("      --silent takes effect. This is an upstream limitation, not a PackItPro bug.");
            }

            try
            {
                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                return ext is ".msi" or ".msp"
                    ? await RunMsiAsync(filePath, silentArgs, tempDir, timeoutMs, logInfo, logError)
                    : await RunExeAsync(filePath, silentArgs, timeoutMs, logInfo, logError);
            }
            catch (OperationCanceledException)
            {
                logError($"TIMEOUT: {file.Name} did not complete within {file.TimeoutMinutes} minutes.");
                return -1;
            }
            catch (Exception ex)
            {
                logError($"Exception running {file.Name}: {ex.Message} ({ex.GetType().Name})");
                return -1;
            }
        }

        /// <summary>
        /// Backward-compatible overload without tempDir (MSI verbose log skipped).
        /// </summary>
        public static Task<int> RunSingleInstallerAsync(
            ManifestFile file, string filePath, string[] silentArgs,
            Action<string> logInfo, Action<string> logError) =>
            RunSingleInstallerAsync(file, filePath, silentArgs, tempDir: "", logInfo, logError);

        /// <summary>
        /// Resolves silent args: manifest args take priority, InstallerDetector is fallback.
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

        // ── [3] Path traversal guard ──────────────────────────────────────────

        private static bool TryResolveSafePath(
            string tempDir, string fileName,
            out string fullPath, out string? error)
        {
            try
            {
                // Normalise so trailing slashes and mixed separators don't affect StartsWith
                string safeTempDir = Path.GetFullPath(tempDir).TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;

                fullPath = Path.GetFullPath(Path.Combine(tempDir, fileName));

                if (!fullPath.StartsWith(safeTempDir, StringComparison.OrdinalIgnoreCase))
                {
                    error = $"'{fileName}' resolves outside temp directory (possible path traversal)";
                    return false;
                }

                error = null;
                return true;
            }
            catch (Exception ex)
            {
                fullPath = string.Empty;
                error = $"invalid path '{fileName}': {ex.Message}";
                return false;
            }
        }

        // ── Private runners ───────────────────────────────────────────────────

        private static async Task<int> RunMsiAsync(
            string filePath,
            string[] silentArgs,
            string tempDir,
            int timeoutMs,
            Action<string> logInfo,
            Action<string> logError)
        {
            var argParts = new List<string> { $"/i \"{filePath}\"" };
            argParts.AddRange(silentArgs);

            // [2] MSI verbose log: /L*v captures property tables, action sequences,
            // and full error text — far more useful than exit codes alone.
            string msiLogPath = string.Empty;
            if (!string.IsNullOrEmpty(tempDir))
            {
                msiLogPath = Path.Combine(tempDir,
                    $"{Path.GetFileNameWithoutExtension(filePath)}_msi.log");
                argParts.Add($"/L*v \"{msiLogPath}\"");
                logInfo($"  MSI verbose log: {msiLogPath}");
            }

            string arguments = string.Join(" ", argParts);
            string workingDir = Path.GetDirectoryName(filePath) ?? Directory.GetCurrentDirectory();

            logInfo("  Command line:");
            logInfo($"    msiexec.exe {arguments}");
            logInfo($"  Working dir: {workingDir}");

            // msiexec routes output through Windows Installer logging, not console streams,
            // so stdout/stderr redirect is not useful here — /L*v handles it.
            var psi = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir,
            };

            int exitCode = await RunProcessWithoutCaptureAsync(
                psi, timeoutMs, logInfo, logError);

            if (!string.IsNullOrEmpty(msiLogPath) && File.Exists(msiLogPath))
                logInfo($"  MSI log: {FormatBytes(new FileInfo(msiLogPath).Length)} written to {msiLogPath}");

            return exitCode;
        }

        private static async Task<int> RunExeAsync(
            string filePath,
            string[] silentArgs,
            int timeoutMs,
            Action<string> logInfo,
            Action<string> logError)
        {
            string arguments = string.Join(" ", silentArgs);
            string workingDir = Path.GetDirectoryName(filePath) ?? Directory.GetCurrentDirectory();
            // Short name used as prefix on every captured output line
            string installerName = Path.GetFileName(filePath);

            logInfo("  Command line:");
            logInfo($"    \"{filePath}\" {arguments}");
            logInfo($"  Working dir: {workingDir}");

            // [1] Redirect stdout/stderr — many installers explain failures here only.
            var psi = new ProcessStartInfo
            {
                FileName = filePath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            return await RunProcessWithOutputCaptureAsync(
                psi, installerName, timeoutMs, logInfo, logError);
        }

        // ── Process runners ───────────────────────────────────────────────────

        /// <summary>
        /// Runs a process without capturing stdout/stderr (used for MSI which
        /// handles its own logging via /L*v).
        /// </summary>
        private static async Task<int> RunProcessWithoutCaptureAsync(
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
            int exitCode = await tcs.Task;
            logInfo($"  Exited with code: {exitCode}");
            return exitCode;
        }

        /// <summary>
        /// Runs a process with stdout/stderr captured into a memory buffer.
        /// On SUCCESS (ExitCodeClassifier.IsSuccess) the buffer is silently discarded —
        /// clean installs produce no [OUT]/[ERR] noise.
        /// On FAILURE the full buffer is flushed to the log so every output line is
        /// available for diagnosis.
        /// Every buffered line is prefixed with the installer filename so multi-installer
        /// logs remain readable without scrolling back to find the installer header.
        /// </summary>
        private static async Task<int> RunProcessWithOutputCaptureAsync(
            ProcessStartInfo psi,
            string installerName,    // short name for prefix, e.g. "setup.exe"
            int timeoutMs,
            Action<string> logInfo,
            Action<string> logError)
        {
            // Buffer for captured output. DataReceived fires on thread pool threads,
            // so all access is protected by _outputLock.
            var outputBuffer = new List<string>();
            var bufferLock = new object();

            using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
            using var cts = new CancellationTokenSource(timeoutMs);
            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            process.Exited += (s, e) => tcs.TrySetResult(process.ExitCode);

            // [1] Subscribe before Start(). Lines get the installer name baked in
            // at capture time so they're ready to write whether buffered or immediate.
            process.OutputDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    lock (bufferLock) outputBuffer.Add($"  [{installerName} OUT] {e.Data}");
            };
            process.ErrorDataReceived += (s, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    lock (bufferLock) outputBuffer.Add($"  [{installerName} ERR] {e.Data}");
            };

            using var _ = cts.Token.Register(() =>
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                tcs.TrySetCanceled();
            });

            process.Start();
            // [BeginXxx must be called after Start() — .NET requirement]
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            logInfo($"  PID: {process.Id}");

            int exitCode = await tcs.Task; // throws OperationCanceledException on timeout
            logInfo($"  Exited with code: {exitCode}");

            // [2] Flush or discard based on outcome
            List<string> captured;
            lock (bufferLock) { captured = new List<string>(outputBuffer); }

            bool succeeded = ExitCodeClassifier.IsSuccess(ExitCodeClassifier.Classify(exitCode));

            if (captured.Count == 0)
            {
                logInfo("  (no stdout/stderr output)");
            }
            else if (succeeded)
            {
                // Discard on success — keep the log concise
                logInfo($"  (stdout/stderr: {captured.Count} lines — suppressed on success)");
            }
            else
            {
                // Flush full buffer on failure — every line needed for diagnosis
                logInfo($"  stdout/stderr output ({captured.Count} lines):");
                foreach (var line in captured)
                    logInfo(line);
            }

            return exitCode;
        }

        // ── Utilities ─────────────────────────────────────────────────────────

        private static string DescribeSource(string source) => source switch
        {
            "header" => "header signature ✅",
            "manifest" => "user-specified ✅",
            _ => "extension only ⚠️",
        };

        private static string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";
            string[] s = { "B", "KB", "MB", "GB" };
            double v = bytes; int o = 0;
            while (v >= 1024 && o < s.Length - 1) { o++; v /= 1024; }
            return $"{v:0.##} {s[o]}";
        }
    }
}