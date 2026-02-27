// StubInstaller/Constants.cs
// All shared string and numeric constants in one place.
// A rename or version bump is a single-line change that propagates everywhere.
namespace StubInstaller
{
    internal static class Constants
    {
        // ── Stub version — update with every release ──────────────────────────
        internal const string StubVersion = "1.3.4";
        internal const string StubBuildDate = "2026-02-27";

        // ── Command-line arguments ────────────────────────────────────────────
        internal const string ArgTempDir = "--temp-dir";
        internal const string ArgLogPath = "--log-path";

        // ── Well-known file names ─────────────────────────────────────────────
        internal const string ManifestFileName = "packitmeta.json";
        internal const string LogFileName = "install.log";
        internal const string DesktopLogPrefix = "PackItPro_install_log_";
    }
}