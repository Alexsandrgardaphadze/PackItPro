// StubInstaller/Program.Logging.cs
// Startup and completion banners written to the log file.
using StubInstaller.Core;
using StubInstaller.Infrastrucure;
using System;

namespace StubInstaller
{
    internal partial class Program
    {
        private static void LogBanner(bool isElevated, string? resumeTempDir, string? resumeLogPath)
        {
            StubLogger.Log("========================================");
            StubLogger.Log($"PackItPro Stub Installer v{Constants.StubVersion}" +
                           (isElevated ? " [ELEVATED]" : ""));
            StubLogger.Log($"Build:         {Constants.StubBuildDate}");
            StubLogger.Log("========================================");
            StubLogger.Log($"Time:          {DateTime.Now:dd-MM-yyyy HH:mm:ss}");
            StubLogger.Log($"OS:            {Environment.OSVersion}");
            StubLogger.Log($"64-bit:        {Environment.Is64BitOperatingSystem}");
            StubLogger.Log($"Process:       {Environment.ProcessPath}");
            StubLogger.Log($"Admin:         {ElevationHelper.IsRunningAsAdmin()}");
            if (isElevated)
            {
                StubLogger.Log($"Resumed temp:  {resumeTempDir}");
                StubLogger.Log($"Resumed log:   {resumeLogPath}");
            }
            StubLogger.Log("========================================");
        }

        private static void LogCompletionBanner(bool success, TimeSpan duration)
        {
            StubLogger.Log("");
            StubLogger.Log("========================================");
            StubLogger.Log("INSTALLATION COMPLETE");
            StubLogger.Log($"Success:         {success}");
            StubLogger.Log($"Reboot required: {_rebootRequired}");
            StubLogger.Log($"Total duration:  {duration.TotalSeconds:0.0}s");
            StubLogger.Log($"Finished:        {DateTime.Now:dd-MM-yyyy HH:mm:ss}");
            StubLogger.Log("========================================");
        }

        private static string BuildCompletionMessage(string packageName, bool success)
        {
            if (_rebootRequired)
                return $"✅ '{packageName}' installed successfully!\n\n" +
                       "⚠️ A system restart is required to complete the installation.";
            if (success)
                return $"✅ '{packageName}' installed successfully!";
            return $"⚠️ '{packageName}' completed with errors.\n\nLog: {StubLogger.LogPath}";
        }
    }
}