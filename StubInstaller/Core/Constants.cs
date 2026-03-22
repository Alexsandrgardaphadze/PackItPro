// StubInstaller/Constants.cs
namespace StubInstaller.Core
{
    internal static class Constants
    {
        // ── Stub version — update with every release ──────────────────────────
        internal const string StubVersion = "1.4.0";
        internal const string StubBuildDate = "22-03-2026";

        // ── Command-line arguments ────────────────────────────────────────────
        internal const string ArgTempDir = "--temp-dir";
        internal const string ArgLogPath = "--log-path";

        // ── Well-known file names ─────────────────────────────────────────────
        internal const string ManifestFileName = "packitmeta.json";
        internal const string LogFileName = "install.log";
        internal const string DesktopLogPrefix = "PackItPro_install_log_";
    }
}