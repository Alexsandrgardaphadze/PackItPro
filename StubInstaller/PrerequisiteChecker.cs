// StubInstaller/PrerequisiteChecker.cs
// Checks system requirements before extraction begins.
// All three checks (disk space, Windows version, architecture) run up front so
// the user gets one clear error message instead of a mysterious mid-install failure.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace StubInstaller
{
    internal static class PrerequisiteChecker
    {
        // Win10 1903 — minimum build for most modern software.
        // Packages can tighten this via manifest.MinWindowsBuild.
        private const int DefaultMinWindowsBuild = 18362;

        // Added on top of the estimated package size to cover extraction overhead,
        // MSI temp files, and the install target itself.
        private const long HeadroomMB = 512;

        internal static PrereqResult Check(
            PackageManifest manifest,
            string tempExtractionPath,
            Action<string> log)
        {
            var failures = new List<string>();

            CheckDiskSpace(manifest, tempExtractionPath, log, failures);
            CheckWindowsVersion(manifest, log, failures);
            CheckArchitecture(manifest, log, failures);

            if (failures.Count == 0)
                return PrereqResult.Pass();

            string userMessage = failures.Count == 1
                ? failures[0]
                : "This package cannot be installed because:\n\n" +
                  string.Join("\n\n", failures.Select((f, i) => $"{i + 1}. {f}"));

            return PrereqResult.Fail(failures, userMessage);
        }

        // ── Individual checks ─────────────────────────────────────────────────

        private static void CheckDiskSpace(
            PackageManifest manifest,
            string tempExtractionPath,
            Action<string> log,
            List<string> failures)
        {
            long requiredMB = manifest.MinFreeDiskMB ?? EstimateRequiredDiskMB(tempExtractionPath);
            long availableMB = GetAvailableDiskMB(tempExtractionPath);
            long neededMB = requiredMB + HeadroomMB;

            log($"   Disk: {availableMB} MB available, {neededMB} MB needed " +
                $"({requiredMB} estimated + {HeadroomMB} MB headroom)");

            if (availableMB < neededMB)
                failures.Add(
                    $"Not enough disk space: {availableMB} MB available, {neededMB} MB needed. " +
                    $"Free at least {neededMB - availableMB} MB and try again.");
        }

        private static void CheckWindowsVersion(
            PackageManifest manifest,
            Action<string> log,
            List<string> failures)
        {
            int minBuild = manifest.MinWindowsBuild ?? DefaultMinWindowsBuild;
            int actualBuild = Environment.OSVersion.Version.Build;

            log($"   Windows build: {actualBuild} (required: ≥ {minBuild})");

            if (actualBuild >= minBuild) return;

            string versionName = minBuild switch
            {
                18362 => "Windows 10 version 1903",
                19041 => "Windows 10 version 2004",
                22000 => "Windows 11",
                22621 => "Windows 11 22H2",
                _ => $"build {minBuild}",
            };

            failures.Add(
                $"Windows is too old: you have build {actualBuild}, " +
                $"but {versionName} (build {minBuild}) is required. " +
                "Please update Windows and try again.");
        }

        private static void CheckArchitecture(
            PackageManifest manifest,
            Action<string> log,
            List<string> failures)
        {
            bool isX64 = Environment.Is64BitOperatingSystem;
            string required = manifest.RequiresX64 ? "x64" : "any";

            log($"   Architecture: {(isX64 ? "x64" : "x86")} (required: {required})");

            if (manifest.RequiresX64 && !isX64)
                failures.Add(
                    "This package requires a 64-bit (x64) version of Windows, " +
                    "but your system is running 32-bit.");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static long EstimateRequiredDiskMB(string tempPath)
        {
            try
            {
                long bytes = Directory
                    .GetFiles(tempPath, "*", SearchOption.AllDirectories)
                    .Sum(f => new FileInfo(f).Length);

                // ×2: one copy extracted here, one more when the installer runs
                return Math.Max(bytes * 2 / (1024 * 1024), 100);
            }
            catch { return 500; } // safe fallback if enumeration fails
        }

        private static long GetAvailableDiskMB(string pathOnDrive)
        {
            try
            {
                var root = Path.GetPathRoot(pathOnDrive) ?? "C:\\";
                var drive = new DriveInfo(root);
                return drive.AvailableFreeSpace / (1024 * 1024);
            }
            catch { return long.MaxValue; } // if we can't check, don't block install
        }
    }

    // ── Result type ───────────────────────────────────────────────────────────

    internal sealed class PrereqResult
    {
        public bool Passed { get; private init; }
        public IReadOnlyList<string> Failures { get; private init; } = Array.Empty<string>();
        public string UserMessage { get; private init; } = string.Empty;

        internal static PrereqResult Pass() => new() { Passed = true };

        internal static PrereqResult Fail(List<string> failures, string userMessage) => new()
        {
            Passed = false,
            Failures = failures,
            UserMessage = userMessage,
        };
    }
}