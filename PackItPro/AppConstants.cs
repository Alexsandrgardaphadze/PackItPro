// PackItPro/AppConstants.cs
using System;
using System.Collections.Generic;
namespace PackItPro
{
    internal static class AppConstants
    {
        // ── App identity ──────────────────────────────────────────────────────
        public const string AppName = "PackItPro";
        public const string CompanyName = "ZenQuant";

        // ── AppData file names ────────────────────────────────────────────────
        // All resolved at runtime as: Path.Combine(_appDataDir, XxxFileName)
        public const string SettingsFileName = "settings.json";
        public const string CacheFileName = "virusscancache.json";
        public const string TrustStoreFileName = "trusted_hashes.json";
        public const string LogFileName = "packitpro.log";
        public const string CrashLogFileName = "crash.log";

        // ── AppData sub-directories ───────────────────────────────────────────
        public const string LogsSubDir = "Logs";
        public const string CacheSubDir = "Cache";

        // ── GitHub repository ─────────────────────────────────────────────────
        public const string GitHubOwner = "Alexsandrgardaphadze";
        public const string GitHubRepo = "PackItPro";

        // ── Packaging limits ──────────────────────────────────────────────────
        public const int DefaultMaxFilesInList = 20;
        public const int MinFilesInList = 1;
        public const int MaxFilesInList = 50;

        // ── VirusTotal ────────────────────────────────────────────────────────
        public const int MinDetectionsToFlag = 1;
        public const int MaxDetectionsToFlag = 72;

        // ── Executable extensions scanned by VirusTotal ───────────────────────
        // Shared between VirusTotalClient and MainViewModel so both sides
        // stay in sync. Add new extensions here only.
        public static readonly IReadOnlyCollection<string> ExecutableExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                ".jar", ".msi", ".com", ".scr", ".pif", ".gadget",
                ".application", ".msc", ".cpl", ".hta", ".reg",
                ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh",
                ".lnk", ".inf", ".scf",
            };


        // ── Formatting helpers ────────────────────────────────────────────────────
        // Single implementation — reference this instead of duplicating in every class.
        // StubInstaller uses Util.FormatBytes (its own equivalent in the stub project).
        public static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int i = 0;
            double size = bytes;
            while (size >= 1024 && i < suffixes.Length - 1) { size /= 1024; i++; }
            return $"{size:0.##} {suffixes[i]}";
        }
    }
}