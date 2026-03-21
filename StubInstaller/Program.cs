// StubInstaller/Program.cs
// Entry point and logging setup only.
// All other logic is split into Program.*.cs partial class files.
using StubInstaller.Core;
using StubInstaller.Infrastrucure;
using StubInstaller.ViewModels;
using StubInstaller.Views;
using System;
using System.IO;
using System.Windows.Threading;
using WinForms = System.Windows.Forms;
using WpfApp = System.Windows.Application;

namespace StubInstaller
{
    internal partial class Program
    {
        private static bool _rebootRequired;

        [STAThread]
        static int Main(string[] args)
        {
            string? resumeTempDir = ArgParser.GetValue(args, Constants.ArgTempDir);
            string? resumeLogPath = ArgParser.GetValue(args, Constants.ArgLogPath);
            bool isElevatedResume = resumeTempDir != null && resumeLogPath != null;

            StubLogger.DetectConsoleMode();

            if (isElevatedResume)
            {
                StubLogger.LogPath = resumeLogPath!;
                StubLogger.AppendElevationSeparator();
            }
            else
            {
                StubLogger.LogPath = Path.Combine(
                    Path.GetTempPath(),
                    $"PackItPro_Stub_{DateTime.Now:yyyyMMdd_HHmmss_fff}.log");
                StubLogger.WriteLogHeader(Constants.StubVersion, Constants.StubBuildDate);
            }

            try
            {
                LogBanner(isElevatedResume, resumeTempDir, resumeLogPath);

                var preResult = RunPreInstallSteps(isElevatedResume, resumeTempDir);
                if (preResult.ExitCode.HasValue)
                    return preResult.ExitCode.Value;

                return RunWpfInstaller(preResult.TempDir!, preResult.Manifest!);
            }
            catch (Exception ex)
            {
                StubLogger.LogError("UNHANDLED EXCEPTION IN MAIN", ex);
                ShowError(
                    $"An unexpected error occurred.\n\nError: {ex.Message}\n\nLog: {StubLogger.LogPath}",
                    "Fatal Error");
                return 1;
            }
        }

        // ── Pre-install result ────────────────────────────────────────────────

        private sealed class PreInstallResult
        {
            /// <summary>Non-null means return this exit code immediately.</summary>
            public int? ExitCode { get; init; }
            public string? TempDir { get; init; }
            public PackageManifest? Manifest { get; init; }

            public static PreInstallResult Early(int code) => new() { ExitCode = code };
            public static PreInstallResult Ready(string tempDir, PackageManifest manifest)
                => new() { TempDir = tempDir, Manifest = manifest };
        }
    }
}