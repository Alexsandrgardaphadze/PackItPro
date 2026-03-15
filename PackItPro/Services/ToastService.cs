// PackItPro/Services/ToastService.cs
using Microsoft.Toolkit.Uwp.Notifications;
using System;
using System.Xml.Linq;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace PackItPro.Services
{
    public static class ToastService
    {
        private const string AppId = "PackItPro.SecurePackageBuilder";

        // ── Initialisation ────────────────────────────────────────────────────
        // Call once from App.xaml.cs OnStartup, before any Notify*() calls.
        public static void Initialize()
        {
            try
            {
                ToastNotificationManagerCompat.OnActivated += OnToastActivated;
            }
            catch { /* notification subsystem unavailable — continue silently */ }
        }

        private static void OnToastActivated(ToastNotificationActivatedEventArgsCompat e)
        {
            // Placeholder for deep-link handling (e.g. open output folder on click).
            // Currently no action needed.
        }

        // ── Core send helper ─────────────────────────────────────────────────
        // Builds a raw XML toast so we can include the <audio> element, which the
        // ToastContentBuilder fluent API omits by default (it emits no <audio> node
        // at all, so Windows plays no sound — the root cause of issue #5).
        private static void Send(string title, string body,
                                  string? audioSrc = "ms-winsoundevent:Notification.Default",
                                  bool audioSilent = false)
        {
            try
            {
                // Build minimal toast XML manually
                var audioElement = audioSilent
                    ? "<audio silent=\"true\"/>"
                    : $"<audio src=\"{audioSrc ?? "ms-winsoundevent:Notification.Default"}\"/>";

                string xml = $@"
<toast>
  <visual>
    <binding template=""ToastGeneric"">
      <text>{EscapeXml(title)}</text>
      <text>{EscapeXml(body)}</text>
    </binding>
  </visual>
  {audioElement}
</toast>";

                var doc = new XmlDocument();
                doc.LoadXml(xml);

                var toast = new ToastNotification(doc);
                ToastNotificationManagerCompat.CreateToastNotifier().Show(toast);
            }
            catch { /* never crash the app over a notification */ }
        }

        private static string EscapeXml(string? s) =>
            (s ?? "")
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;");

        // ── Public notification API ───────────────────────────────────────────

        /// <summary>Package was created successfully.</summary>
        /// <param name="fileName">Just the file name (shown in title). Optional.</param>
        /// <param name="outputPath">Full path (shown in body). Optional.</param>
        public static void NotifyPackageCreated(string? fileName = null, string? outputPath = null)
        {
            var title = fileName != null ? $"✅ Package Created — {fileName}" : "✅ Package Created";
            var body = outputPath != null ? $"Saved to: {outputPath}" : "Your .exe package is ready.";
            Send(title, body, audioSrc: "ms-winsoundevent:Notification.Mail");
        }

        /// <summary>VirusTotal scan has started (background, no focus steal).</summary>
        public static void NotifyScanStarted(int fileCount)
        {
            Send("🔍 Scan Started",
                 $"Checking {fileCount} file{(fileCount != 1 ? "s" : "")} with VirusTotal…",
                 audioSilent: true); // background op — no sound
        }

        /// <summary>All files came back clean.</summary>
        public static void NotifyScanClean(int fileCount)
        {
            Send("🛡️ All Files Clean",
                 $"{fileCount} file{(fileCount != 1 ? "s" : "")} passed VirusTotal scanning.",
                 audioSrc: "ms-winsoundevent:Notification.Default");
        }

        /// <summary>Scan detected threats.</summary>
        /// <param name="threatCount">Number of infected files.</param>
        /// <param name="totalFiles">Total files scanned (used in body text). Optional.</param>
        public static void NotifyScanThreatsFound(int threatCount, int totalFiles = 0)
        {
            var context = totalFiles > 0 ? $" out of {totalFiles}" : "";
            Send("⚠️ Threats Detected",
                 $"{threatCount} file{(threatCount != 1 ? "s" : "")}{context} flagged by VirusTotal. Check the file list.",
                 audioSrc: "ms-winsoundevent:Notification.Looping.Alarm2");
        }

        /// <summary>Update available.</summary>
        public static void NotifyUpdateAvailable(string? currentVersion, string? latestVersion, string? releaseUrl)
        {
            var body = $"Version {latestVersion ?? "unknown"} is available" +
                       (currentVersion != null ? $" (current: {currentVersion})" : "") + ".";
            Send("🚀 Update Available", body,
                 audioSrc: "ms-winsoundevent:Notification.Default");
        }

        /// <summary>A file was marked as trusted (false positive).</summary>
        public static void NotifyFileTrusted(string? fileName)
        {
            Send("🔒 File Trusted",
                 $"{fileName ?? "File"} has been marked as a false positive and will not be flagged again.",
                 audioSilent: true);
        }

        /// <summary>Trust was removed from a file.</summary>
        public static void NotifyTrustRemoved(string? fileName)
        {
            Send("🔓 Trust Removed",
                 $"{fileName ?? "File"} is no longer marked as trusted.",
                 audioSilent: true);
        }

        /// <summary>Non-fatal error the user should be aware of.</summary>
        public static void NotifyError(string message)
        {
            Send("❌ PackItPro Error", message,
                 audioSrc: "ms-winsoundevent:Notification.Looping.Alarm");
        }

        /// <summary>Packaging failed.</summary>
        public static void NotifyPackageFailed(string reason)
        {
            Send("❌ Packaging Failed", reason,
                 audioSrc: "ms-winsoundevent:Notification.Looping.Alarm");
        }
    }
}