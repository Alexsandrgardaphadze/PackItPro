// StubInstaller/StubUI.cs
// All user-visible WinForms dialogs in one place.
// Reads Constants.DesktopLogPrefix directly so callers don't have to pass it.
using System.IO;
using System.Windows.Forms;

namespace StubInstaller
{
    internal static class StubUI
    {
        /// <summary>
        /// Shows an error dialog and copies the log to the Desktop (falling back to
        /// clipboard) so users can find it without knowing where %TEMP% is.
        /// </summary>
        internal static void ShowError(string message, string title)
        {
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

        /// <summary>
        /// Shows the completion dialog. On failure, proactively copies the log
        /// to the Desktop so users can report it.
        /// </summary>
        internal static void ShowCompletion(string message, bool success)
        {
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
    }
}