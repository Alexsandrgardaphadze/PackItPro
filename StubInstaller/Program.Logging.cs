// StubInstaller/Program.Logging.cs
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
    }
}