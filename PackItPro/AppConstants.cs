// PackItPro/AppConstants.cs
// Single source of truth for all magic strings, file names, and limits.
// Reference this instead of scattering literals across files — if a name
// ever changes, it changes here and the compiler catches every callsite.
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
    }
}
