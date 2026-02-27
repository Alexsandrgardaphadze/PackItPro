// PackItPro/Services/ILogService.cs - v2.2
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace PackItPro.Services
{
    public enum LogLevel { Debug, Info, Warning, Error }

    public interface ILogService
    {
        void Debug(string message);
        void Info(string message);
        void Warning(string message);
        void Error(string message, Exception? ex = null);
    }

    /// <summary>
    /// Writes structured log entries to a file and Debug output simultaneously.
    /// Thread-safe. Disables itself on persistent write failure (e.g. full disk)
    /// rather than retrying indefinitely.
    /// </summary>
    public class FileLogService : ILogService
    {
        private readonly string _logPath;
        private readonly object _lock = new();
        private bool _disabled = false; // FIX: one-time fallback on IO failure

        public string LogPath => _logPath;

        public FileLogService(string logPath)
        {
            _logPath = logPath;

            // FIX: Only write the header if the file is new/empty.
            // Multiple packaging operations in one session must NOT produce
            // multiple headers in the same log file.
            bool isNew = !File.Exists(logPath) || new FileInfo(logPath).Length == 0;
            if (isNew)
            {
                WriteRaw(
                    "========================================\n" +
                    $"PackItPro Log — {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                    $"Machine: {Environment.MachineName} | User: {Environment.UserName}\n" +
                    "========================================\n");
            }
        }

        public void Debug(string message) => Write(LogLevel.Debug, message, null);
        public void Info(string message) => Write(LogLevel.Info, message, null);
        public void Warning(string message) => Write(LogLevel.Warning, message, null);
        public void Error(string message, Exception? ex = null) => Write(LogLevel.Error, message, ex);

        private void Write(LogLevel level, string message, Exception? ex)
        {
            var sb = new StringBuilder();
            sb.Append($"[{DateTime.Now:HH:mm:ss.fff}] [{level.ToString().ToUpper(),-7}] {message}");

            if (ex != null)
            {
                sb.AppendLine();
                sb.Append($"  {ex.GetType().Name}: {ex.Message}");
                if (ex.StackTrace != null)
                {
                    sb.AppendLine();
                    sb.Append($"  {ex.StackTrace.Trim()}");
                }
                if (ex.InnerException != null)
                {
                    sb.AppendLine();
                    sb.Append($"  Inner: {ex.InnerException.Message}");
                }
            }

            var entry = sb.ToString();
            System.Diagnostics.Debug.WriteLine($"[PackItPro] {entry}");
            WriteRaw(entry + "\n");
        }

        private void WriteRaw(string text)
        {
            if (_disabled) return;

            lock (_lock)
            {
                if (_disabled) return;
                try
                {
                    var dir = Path.GetDirectoryName(_logPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    File.AppendAllText(_logPath, text);
                }
                catch
                {
                    // FIX: Disk full or permissions error — disable logging permanently
                    // rather than burning CPU retrying on every subsequent log call.
                    _disabled = true;
                }
            }
        }
    }

    /// <summary>No-op logger for tests or when logging is not needed.</summary>
    public class NullLogService : ILogService
    {
        public static readonly NullLogService Instance = new();
        public void Debug(string message) { }
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message, Exception? ex = null) { }
    }
}