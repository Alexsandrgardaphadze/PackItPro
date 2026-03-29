// StubInstaller/StubLogger.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace StubInstaller.Infrastrucure
{
    internal static class StubLogger
    {
        internal static string? LogPath;
        internal static bool ConsoleMode;

        private static readonly object _lock = new();
        private static readonly Encoding _utf8Bom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

        // ── Setup ─────────────────────────────────────────────────────────────

        internal static void DetectConsoleMode()
        {
            try { _ = Console.WindowHeight; ConsoleMode = true; }
            catch { ConsoleMode = false; }
        }

        internal static void WriteLogHeader(string version, string buildDate)
        {
            try
            {
                // Write with BOM so Notepad, VS Code, and Windows Event Viewer all
                // decode the emoji correctly without any viewer configuration.
                File.WriteAllText(LogPath!,
                    "========================================\n" +
                    "PackItPro Stub Installer Log\n" +
                    $"Stub version: {version}  Build: {buildDate}\n" +
                    $"Started:    {DateTime.Now:dd-MM-yyyy HH:mm:ss}\n" +
                    $"Executable: {Environment.ProcessPath}\n" +
                    "========================================\n\n",
                    _utf8Bom);
            }
            catch { }
        }

        internal static void AppendElevationSeparator()
        {
            var content =
                "\n========================================\n" +
                $"[ELEVATED RESUME] {DateTime.Now:dd-MM-yyyy HH:mm:ss}\n" +
                $"Process ID: {Process.GetCurrentProcess().Id}\n" +
                "========================================\n\n";

            lock (_lock)
            {
                try { File.AppendAllText(LogPath!, content, _utf8Bom); } catch { }
            }
        }

        // ── Logging ───────────────────────────────────────────────────────────

        internal static void Log(string message)
        {
            var entry = $"[{DateTime.Now:HH:mm:ss.fff}] {message}";

            if (!string.IsNullOrEmpty(LogPath))
                lock (_lock)
                {
                    try { File.AppendAllText(LogPath, entry + Environment.NewLine, _utf8Bom); } catch { }
                }

            if (ConsoleMode) Console.WriteLine(entry);
            Debug.WriteLine(entry);
        }

        internal static void LogError(string message, Exception? ex)
        {
            var sb = new StringBuilder($"❌ ERROR: {message}");
            if (ex != null)
            {
                sb.AppendLine().AppendLine($"  Type:    {ex.GetType().Name}");
                sb.AppendLine($"  Message: {ex.Message}");
                if (ex.StackTrace != null) sb.AppendLine($"  Stack:   {ex.StackTrace.Trim()}");
                if (ex.InnerException != null) sb.AppendLine($"  Inner:   {ex.InnerException.Message}");
            }
            Log(sb.ToString().TrimEnd());
        }

        // ── Desktop copy ──────────────────────────────────────────────────────

        internal static string? TryCopyLogToDesktop(string prefix)
        {
            if (string.IsNullOrEmpty(LogPath) || !File.Exists(LogPath))
                return null;
            try
            {
                string desktop = ResolveUserDesktop();
                if (string.IsNullOrEmpty(desktop)) return null;
                string destName = $"{prefix}{DateTime.Now:yyyyMMdd_HHmmss}.log";
                string destPath = Path.Combine(desktop, destName);
                File.Copy(LogPath, destPath, overwrite: true);
                return destPath;
            }
            catch { return null; }
        }

        /// <summary>
        /// Resolves the logged-in user's Desktop folder correctly even when the
        /// process is running elevated. When elevated, SpecialFolder.Desktop
        /// returns the administrator account's desktop (typically
        /// C:\Windows\System32\config\systemprofile\Desktop), not the actual
        /// user's desktop. We use the USERPROFILE environment variable instead,
        /// which is inherited from the non-elevated parent shell and always points
        /// to the real user's profile. Falls back to Public Desktop if unavailable.
        /// </summary>
        private static string ResolveUserDesktop()
        {
            // USERPROFILE is inherited from the interactive shell even when elevated
            string? userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (!string.IsNullOrEmpty(userProfile))
            {
                string candidate = Path.Combine(userProfile, "Desktop");
                if (Directory.Exists(candidate)) return candidate;
            }

            // Fallback 1: HOMEDRIVE + HOMEPATH
            string? homeDrive = Environment.GetEnvironmentVariable("HOMEDRIVE");
            string? homePath = Environment.GetEnvironmentVariable("HOMEPATH");
            if (!string.IsNullOrEmpty(homeDrive) && !string.IsNullOrEmpty(homePath))
            {
                string candidate = Path.Combine(homeDrive + homePath, "Desktop");
                if (Directory.Exists(candidate)) return candidate;
            }

            // Fallback 2: Public Desktop (visible to all users)
            string publicDesktop = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            if (Directory.Exists(publicDesktop)) return publicDesktop;

            // Last resort: SpecialFolder.Desktop (may be wrong when elevated but better than nothing)
            return Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        }
    }
}