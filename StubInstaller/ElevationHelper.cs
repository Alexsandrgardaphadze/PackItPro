// StubInstaller/ElevationHelper.cs
// Admin detection and UAC elevation restart.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace StubInstaller
{
    internal static class ElevationHelper
    {
        internal static bool IsRunningAsAdmin()
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Relaunches this process via "runas" (UAC prompt), forwarding <paramref name="tempDir"/>
        /// and <paramref name="logPath"/> so the elevated child can resume from Step 5.
        /// Exits the current process on success; shows an error and exits(1) on denial.
        /// </summary>
        internal static void RestartElevated(string tempDir, string? logPath)
        {
            string? exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
            {
                StubUI.ShowError("Cannot determine the executable path needed for elevation.", "Elevation Error");
                Environment.Exit(1);
                return;
            }

            string args = BuildElevatedArgs(tempDir, logPath);
            StubLogger.Log($"Launching elevated: {exePath} {args}");

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = args,
                    UseShellExecute = true,
                    Verb = "runas",
                });
                Environment.Exit(0);
            }
            catch (Win32Exception)
            {
                StubUI.ShowError(
                    "Administrator rights are required but were denied.\n\nInstallation cancelled.",
                    "UAC Denied");
                Environment.Exit(1);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string BuildElevatedArgs(string tempDir, string? logPath)
        {
            // Start from the original command line, drop any stale --temp-dir / --log-path,
            // then append the fresh values.
            var sb = new StringBuilder();

            foreach (var a in Environment.GetCommandLineArgs().Skip(1))
            {
                if (a.StartsWith(Constants.ArgTempDir, StringComparison.OrdinalIgnoreCase)) continue;
                if (a.StartsWith(Constants.ArgLogPath, StringComparison.OrdinalIgnoreCase)) continue;
                sb.Append(a.Contains(' ') ? $"\"{a}\" " : $"{a} ");
            }

            sb.Append($"{Constants.ArgTempDir} \"{tempDir}\"");
            if (!string.IsNullOrEmpty(logPath))
                sb.Append($" {Constants.ArgLogPath} \"{logPath}\"");

            return sb.ToString();
        }
    }
}