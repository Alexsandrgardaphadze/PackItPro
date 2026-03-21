// StubInstaller/Program.Dialogs.cs
// Pre-WPF error dialogs — used only for fatal failures before the window opens.
// After the WPF window is running, errors are surfaced through the ViewModel.
using StubInstaller.Core;
using StubInstaller.Infrastrucure;
using System.IO;
using WinForms = System.Windows.Forms;

namespace StubInstaller
{
    internal partial class Program
    {
        /// <summary>
        /// Shows a WinForms error dialog and copies the log to the Desktop so
        /// users can find it without knowing where %TEMP% is.
        /// </summary>
        private static void ShowError(string message, string title)
        {
            try
            {
                string? desktopPath = StubLogger.TryCopyLogToDesktop(Constants.DesktopLogPrefix);
                if (desktopPath != null)
                {
                    message += $"\n\nLog saved to Desktop:\n{Path.GetFileName(desktopPath)}";
                    try { WinForms.Clipboard.SetText(desktopPath); } catch { }
                }
                else if (!string.IsNullOrEmpty(StubLogger.LogPath))
                {
                    try { WinForms.Clipboard.SetText(StubLogger.LogPath); } catch { }
                    message += "\n\n(Log path copied to clipboard)";
                }
            }
            catch { }

            WinForms.MessageBox.Show(message, $"PackItPro — {title}",
                WinForms.MessageBoxButtons.OK, WinForms.MessageBoxIcon.Error);
        }

        /// <summary>
        /// Shows the completion dialog. On failure, proactively copies the log
        /// to the Desktop so users can report it.
        /// Not called in the WPF flow — kept for the elevated-resume fallback path.
        /// </summary>
        private static void ShowCompletion(string message, bool success)
        {
            try
            {
                if (!success)
                {
                    string? desktopPath = StubLogger.TryCopyLogToDesktop(Constants.DesktopLogPrefix);
                    if (desktopPath != null)
                        message += $"\n\nLog saved to Desktop:\n{Path.GetFileName(desktopPath)}";
                }
            }
            catch { }

            WinForms.MessageBox.Show(message, "PackItPro — Installation",
                WinForms.MessageBoxButtons.OK,
                success ? WinForms.MessageBoxIcon.Information : WinForms.MessageBoxIcon.Warning);
        }
    }
}