// PackItPro/Services/UpdaterLauncher.cs - v1.0
//
// Replaces the running PackItPro.exe with a downloaded update and restarts.
//
// Why a separate script?
//   A running Windows exe is memory-mapped and locked by the OS. You cannot
//   overwrite it from within the same process. The standard pattern is:
//     1. Drop a small helper script into %TEMP%
//     2. Launch the script (it runs in a separate process)
//     3. Shut down the current process
//     4. The script waits for the current process to exit, then renames the
//        downloaded temp file over the old exe, then restarts the new exe
//
// Why PowerShell and not a second C# exe?
//   PowerShell is present on every supported Windows version (Win10+) and
//   doesn't require us to ship an extra binary. The script is ~20 lines and
//   does nothing beyond wait/rename/start -- easy to audit.
//
// Security considerations:
//   - The temp file was downloaded over HTTPS with EnsureSuccessStatusCode().
//   - The script is written to the user's own %TEMP% (no elevation needed).
//   - The rename target is the directory that contains the running exe, which
//     the user already has write access to (otherwise the app couldn't have
//     been launched from there).
//   - If anything fails the script writes to a log file in %TEMP% and exits
//     without doing anything destructive.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace PackItPro.Services
{
    public static class UpdaterLauncher
    {
        /// <summary>
        /// Writes a PowerShell updater script to %TEMP%, launches it detached,
        /// then returns so the caller can call Application.Current.Shutdown().
        ///
        /// The script will:
        ///   1. Wait up to 10 s for the current process to exit
        ///   2. Rename tempExePath over currentExePath (atomic on same drive)
        ///   3. Start the new exe with no arguments
        ///   4. Delete the script itself
        ///
        /// Throws InvalidOperationException if the script cannot be written or
        /// the process cannot be launched -- the caller should show an error
        /// dialog and NOT shut down if this throws.
        /// </summary>
        /// <param name="currentExePath">Full path of the running PackItPro.exe.</param>
        /// <param name="tempExePath">Full path of the downloaded .tmp file.</param>
        public static void LaunchUpdaterScript(string currentExePath, string tempExePath)
        {
            if (string.IsNullOrWhiteSpace(currentExePath))
                throw new ArgumentException("currentExePath must not be empty.", nameof(currentExePath));
            if (string.IsNullOrWhiteSpace(tempExePath))
                throw new ArgumentException("tempExePath must not be empty.", nameof(tempExePath));
            if (!File.Exists(tempExePath))
                throw new FileNotFoundException("Downloaded update file not found.", tempExePath);

            int currentPid = Environment.ProcessId;
            string logPath = Path.Combine(Path.GetTempPath(), "PackItPro_updater.log");
            string scriptPath = Path.Combine(Path.GetTempPath(), $"PackItPro_update_{Guid.NewGuid():N}.ps1");

            // Use single-quoted PS strings for paths to avoid escaping issues.
            // The only characters that need escaping inside PS single-quotes are
            // single-quotes themselves (doubled: '').
            string safeTemp = tempExePath.Replace("'", "''");
            string safeCurrent = currentExePath.Replace("'", "''");
            string safeLog = logPath.Replace("'", "''");
            string safeScript = scriptPath.Replace("'", "''");

            var sb = new StringBuilder();
            sb.AppendLine("# PackItPro auto-updater -- generated, do not edit");
            sb.AppendLine($"$pid_to_wait = {currentPid}");
            sb.AppendLine($"$temp_path   = '{safeTemp}'");
            sb.AppendLine($"$target_path = '{safeCurrent}'");
            sb.AppendLine($"$log_path    = '{safeLog}'");
            sb.AppendLine($"$script_path = '{safeScript}'");
            sb.AppendLine();
            sb.AppendLine("function Write-Log([string]$msg) {");
            sb.AppendLine("    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'");
            sb.AppendLine("    Add-Content -Path $log_path -Value \"[$ts] $msg\" -Encoding UTF8");
            sb.AppendLine("}");
            sb.AppendLine();
            sb.AppendLine("try {");
            // Wait for PackItPro to exit (up to 10 s)
            sb.AppendLine("    Write-Log 'Waiting for PackItPro to exit...'");
            sb.AppendLine("    $proc = Get-Process -Id $pid_to_wait -ErrorAction SilentlyContinue");
            sb.AppendLine("    if ($proc) { $proc.WaitForExit(10000) | Out-Null }");
            // Extra safety: 1 s sleep so file handles are fully released
            sb.AppendLine("    Start-Sleep -Milliseconds 1000");
            // Verify the downloaded file still exists
            sb.AppendLine("    if (-not (Test-Path $temp_path)) {");
            sb.AppendLine("        Write-Log 'ERROR: temp file not found, aborting update.'");
            sb.AppendLine("        exit 1");
            sb.AppendLine("    }");
            // Rename: Move-Item with -Force overwrites the target atomically on same drive
            sb.AppendLine("    Write-Log 'Replacing exe...'");
            sb.AppendLine("    Move-Item -Path $temp_path -Destination $target_path -Force");
            // Restart
            sb.AppendLine("    Write-Log 'Restarting PackItPro...'");
            sb.AppendLine("    Start-Process -FilePath $target_path");
            sb.AppendLine("    Write-Log 'Update complete.'");
            sb.AppendLine("} catch {");
            sb.AppendLine("    Write-Log \"FAILED: $_\"");
            // If rename failed, clean up the temp file to avoid disk clutter
            sb.AppendLine("    if (Test-Path $temp_path) { Remove-Item $temp_path -Force -ErrorAction SilentlyContinue }");
            sb.AppendLine("    exit 1");
            sb.AppendLine("} finally {");
            sb.AppendLine("    Remove-Item $script_path -Force -ErrorAction SilentlyContinue");
            sb.AppendLine("}");

            // Write with UTF-8 BOM so PowerShell 5 reads it correctly
            File.WriteAllText(scriptPath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            // Launch powershell.exe -WindowStyle Hidden so no console flickers
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{scriptPath}\"",
                UseShellExecute = true,   // required for WindowStyle Hidden
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            var proc = Process.Start(psi)
                ?? throw new InvalidOperationException(
                    "Failed to start the updater script. Process.Start returned null.");

            // Intentionally do NOT wait for the script -- caller shuts down next.
            _ = proc;
        }

        /// <summary>
        /// Returns the full path of the currently running exe.
        /// Safe for single-file apps -- never uses Assembly.Location.
        /// Returns null if the path cannot be determined (should not happen on .NET 6+).
        /// </summary>
        public static string? GetCurrentExePath()
        {
            string? path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
                return path;

            // Fallback: reconstruct from BaseDirectory + hardcoded exe name.
            // This branch should never be hit in a single-file publish on Windows.
            string candidate = Path.Combine(AppContext.BaseDirectory, "PackItPro.exe");
            return File.Exists(candidate) ? candidate : null;
        }
    }
}