// StubInstaller/StubLogger.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace StubInstaller
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
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string destName = $"{prefix}{DateTime.Now:yyyyMMdd_HHmmss}.log";
                string destPath = Path.Combine(desktop, destName);
                File.Copy(LogPath, destPath, overwrite: true);
                return destPath;
            }
            catch { return null; }
        }
    }
}