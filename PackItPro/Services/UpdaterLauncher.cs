// PackItPro/Services/UpdaterLauncher.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace PackItPro.Services
{
    /// <summary>
    /// Writes a self-deleting PowerShell script to <c>%TEMP%</c> and launches it
    /// detached so it can replace running binaries after the process exits.
    ///
    /// The script replaces <c>PackItPro.exe</c> and, when provided,
    /// <c>StubInstaller.exe</c> atomically (same-drive rename), then restarts
    /// the main application.
    /// </summary>
    public static class UpdaterLauncher
    {
        /// <summary>
        /// Writes and launches the updater script.
        ///
        /// The script will:
        /// <list type="number">
        ///   <item>Wait up to 10 s for the current process to exit.</item>
        ///   <item>Replace <paramref name="currentExePath"/> with <paramref name="tempMainPath"/>.</item>
        ///   <item>Replace <paramref name="currentStubPath"/> with <paramref name="tempStubPath"/>
        ///         (skipped when either stub path is null or empty).</item>
        ///   <item>Start the updated <c>PackItPro.exe</c>.</item>
        ///   <item>Delete the script itself.</item>
        /// </list>
        ///
        /// Throws <see cref="InvalidOperationException"/> if the script cannot be
        /// written or the process cannot be started — the caller must NOT shut down
        /// if this throws.
        /// </summary>
        /// <param name="currentExePath">Full path of the running <c>PackItPro.exe</c>.</param>
        /// <param name="tempMainPath">Temp path of the downloaded <c>PackItPro.exe</c>.</param>
        /// <param name="currentStubPath">
        ///   Full path of the currently installed <c>StubInstaller.exe</c>, or null/empty
        ///   to skip stub replacement.
        /// </param>
        /// <param name="tempStubPath">
        ///   Temp path of the downloaded <c>StubInstaller.exe</c>, or null/empty
        ///   to skip stub replacement.
        /// </param>
        public static void LaunchUpdaterScript(
            string currentExePath,
            string tempMainPath,
            string? currentStubPath = null,
            string? tempStubPath = null)
        {
            if (string.IsNullOrWhiteSpace(currentExePath))
                throw new ArgumentException("currentExePath must not be empty.", nameof(currentExePath));
            if (string.IsNullOrWhiteSpace(tempMainPath))
                throw new ArgumentException("tempMainPath must not be empty.", nameof(tempMainPath));
            if (!File.Exists(tempMainPath))
                throw new FileNotFoundException("Downloaded PackItPro update file not found.", tempMainPath);

            // Validate stub paths together — both must be present, or neither is used.
            bool replaceStub = !string.IsNullOrWhiteSpace(currentStubPath)
                            && !string.IsNullOrWhiteSpace(tempStubPath);

            if (replaceStub && !File.Exists(tempStubPath))
                throw new FileNotFoundException("Downloaded StubInstaller update file not found.", tempStubPath);

            int pid = Environment.ProcessId;
            string logPath = Path.Combine(Path.GetTempPath(), "PackItPro_updater.log");
            string scriptPath = Path.Combine(Path.GetTempPath(), $"PackItPro_update_{Guid.NewGuid():N}.ps1");

            var sb = new StringBuilder();
            sb.AppendLine("# PackItPro auto-updater — generated, do not edit");
            sb.AppendLine($"$pid_to_wait   = {pid}");
            sb.AppendLine($"$main_temp     = '{Esc(tempMainPath)}'");
            sb.AppendLine($"$main_target   = '{Esc(currentExePath)}'");

            if (replaceStub)
            {
                sb.AppendLine($"$stub_temp     = '{Esc(tempStubPath!)}'");
                sb.AppendLine($"$stub_target   = '{Esc(currentStubPath!)}'");
            }

            sb.AppendLine($"$log_path      = '{Esc(logPath)}'");
            sb.AppendLine($"$script_path   = '{Esc(scriptPath)}'");
            sb.AppendLine();
            AppendLogFunction(sb);
            sb.AppendLine();
            sb.AppendLine("try {");

            // Wait for the main process to exit
            sb.AppendLine("    Write-Log 'Waiting for PackItPro to exit...'");
            sb.AppendLine("    $proc = Get-Process -Id $pid_to_wait -ErrorAction SilentlyContinue");
            sb.AppendLine("    if ($proc) { $proc.WaitForExit(10000) | Out-Null }");
            sb.AppendLine("    Start-Sleep -Milliseconds 1000");

            // Verify main temp file
            sb.AppendLine("    if (-not (Test-Path $main_temp)) {");
            sb.AppendLine("        Write-Log 'ERROR: PackItPro temp file not found, aborting.'");
            sb.AppendLine("        exit 1");
            sb.AppendLine("    }");

            // Replace PackItPro.exe
            sb.AppendLine("    Write-Log 'Replacing PackItPro.exe...'");
            sb.AppendLine("    Move-Item -Path $main_temp -Destination $main_target -Force");

            // Replace StubInstaller.exe (conditional block)
            if (replaceStub)
            {
                sb.AppendLine("    if (Test-Path $stub_temp) {");
                sb.AppendLine("        Write-Log 'Replacing StubInstaller.exe...'");
                sb.AppendLine("        Move-Item -Path $stub_temp -Destination $stub_target -Force");
                sb.AppendLine("    } else {");
                sb.AppendLine("        Write-Log 'WARN: StubInstaller temp file missing — skipping stub update.'");
                sb.AppendLine("    }");
            }

            // Restart
            sb.AppendLine("    Write-Log 'Restarting PackItPro...'");
            sb.AppendLine("    Start-Process -FilePath $main_target");
            sb.AppendLine("    Write-Log 'Update complete.'");
            sb.AppendLine("} catch {");
            sb.AppendLine("    Write-Log \"FAILED: $_\"");
            sb.AppendLine("    if (Test-Path $main_temp) { Remove-Item $main_temp -Force -ErrorAction SilentlyContinue }");

            if (replaceStub)
                sb.AppendLine("    if (Test-Path $stub_temp) { Remove-Item $stub_temp -Force -ErrorAction SilentlyContinue }");

            sb.AppendLine("    exit 1");
            sb.AppendLine("} finally {");
            sb.AppendLine("    Remove-Item $script_path -Force -ErrorAction SilentlyContinue");
            sb.AppendLine("}");

            // Write with UTF-8 BOM so PowerShell 5 reads it correctly
            File.WriteAllText(scriptPath, sb.ToString(),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{scriptPath}\"",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            var proc = Process.Start(psi)
                ?? throw new InvalidOperationException(
                    "Failed to start the updater script. Process.Start returned null.");

            _ = proc; // intentionally not awaited — caller shuts down next
        }

        /// <summary>
        /// Returns the full path of the running executable.
        /// Safe for single-file apps — never uses <c>Assembly.Location</c>.
        /// </summary>
        public static string? GetCurrentExePath()
        {
            string? path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) return path;

            // Fallback for edge cases (should not occur on .NET 6+ / Windows)
            string candidate = Path.Combine(AppContext.BaseDirectory, "PackItPro.exe");
            return File.Exists(candidate) ? candidate : null;
        }

        /// <summary>
        /// Returns the full path of <c>StubInstaller.exe</c> sitting next to the
        /// running executable, or <c>null</c> when it cannot be found.
        /// </summary>
        public static string? GetCurrentStubPath()
        {
            string? exePath = GetCurrentExePath();
            if (string.IsNullOrEmpty(exePath)) return null;

            string candidate = Path.Combine(
                Path.GetDirectoryName(exePath) ?? AppContext.BaseDirectory,
                "StubInstaller.exe");

            return File.Exists(candidate) ? candidate : null;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /// <summary>Escapes single quotes for PowerShell single-quoted strings.</summary>
        private static string Esc(string path) => path.Replace("'", "''");

        private static void AppendLogFunction(StringBuilder sb)
        {
            sb.AppendLine("function Write-Log([string]$msg) {");
            sb.AppendLine("    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'");
            sb.AppendLine("    Add-Content -Path $log_path -Value \"[$ts] $msg\" -Encoding UTF8");
            sb.AppendLine("}");
        }
    }
}