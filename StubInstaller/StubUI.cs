using System.IO;
using System.Windows.Forms;

namespace StubInstaller
{
    internal static class StubUI
    {
        internal static void ShowError(string message, string title)
        {
            StubLogger.Log($"[UI ERROR] {title}: {message}");

            if (SilentMode.IsEnabled)
            {
                StubLogger.Log("[UI] Silent mode — error dialog suppressed.");
                return;
            }

            string? desktopPath = StubLogger.TryCopyLogToDesktop(Constants.DesktopLogPrefix);

            if (desktopPath != null)
            {
                message += $"\n\nLog saved to Desktop:\n{Path.GetFileName(desktopPath)}";
                try { Clipboard.SetText(desktopPath); } catch { }
            }
            else if (!string.IsNullOrEmpty(StubLogger.LogPath))
            {
                try
                {
                    Clipboard.SetText(StubLogger.LogPath);
                    message += "\n\n(Log path copied to clipboard)";
                }
                catch { }
            }

            MessageBox.Show(message, $"PackItPro — {title}",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        internal static void ShowCompletion(string message, bool success)
        {
            StubLogger.Log($"[UI COMPLETION] Success={success}: {message}");

            if (SilentMode.IsEnabled)
            {
                StubLogger.Log("[UI] Silent mode — completion dialog suppressed.");
                return;
            }

            if (!success)
            {
                string? desktopPath = StubLogger.TryCopyLogToDesktop(Constants.DesktopLogPrefix);
                if (desktopPath != null)
                    message += $"\n\nLog saved to Desktop:\n{Path.GetFileName(desktopPath)}";
            }

            MessageBox.Show(message, "PackItPro — Installation",
                MessageBoxButtons.OK,
                success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        // Always show — even in silent mode malware detection gets a dialog
        internal static void ShowMalwareDetected(string fileName)
        {
            string message =
                $"⚠️ Malware detected!\n\n" +
                $"The file '{fileName}' was flagged by your antivirus engine.\n\n" +
                $"Installation has been blocked to protect your system.\n\n" +
                $"If you believe this is a false positive, check your AV software\n" +
                $"and re-run with the file excluded from scanning.";

            StubLogger.Log($"[UI MALWARE] {message}");

            MessageBox.Show(message, "PackItPro — Malware Detected",
                MessageBoxButtons.OK, MessageBoxIcon.Stop);
        }
    }
}