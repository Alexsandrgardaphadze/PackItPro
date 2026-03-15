// PackItPro/Views/ScanResultsWindow.xaml.cs
using System.Windows;
using System.Windows.Media;

namespace PackItPro.Views
{
    public partial class ScanResultsWindow : Window
    {
        private ScanResultsWindow() => InitializeComponent();

        // ── Factory helpers ───────────────────────────────────────────────────

        public static void ShowInfected(Window? owner, int infected, int total, bool autoRemoved)
        {
            var w = new ScanResultsWindow { Owner = owner ?? Application.Current?.MainWindow };

            w.TitleText.Text = "Threats Detected";
            w.SubtitleText.Text = autoRemoved ? "Infected files were automatically removed" : "Review files marked as Infected";
            w.IconText.Text = "⚠";
            w.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 239, 68, 68));

            w.TotalText.Text = total.ToString();
            w.CleanText.Text = (total - infected).ToString();
            w.IssueText.Text = infected.ToString();
            w.IssueText.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));

            if (autoRemoved)
            {
                w.DetailText.Text = $"{infected} file(s) flagged by VirusTotal were automatically removed from the package list.";
                w.DetailBox.Visibility = Visibility.Visible;
            }
            else
            {
                w.DetailText.Text = "Files marked as Infected are still in the list. Remove them manually before packaging.";
                w.DetailBox.Visibility = Visibility.Visible;
            }

            w.ShowDialog();
        }

        public static void ShowErrors(Window? owner, int failed, int total)
        {
            var w = new ScanResultsWindow { Owner = owner ?? Application.Current?.MainWindow };

            w.TitleText.Text = "Scan Completed with Errors";
            w.SubtitleText.Text = "Some files could not be scanned";
            w.IconText.Text = "⚠";
            w.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 245, 158, 11));

            w.TotalText.Text = total.ToString();
            w.CleanText.Text = (total - failed).ToString();
            w.IssueText.Text = failed.ToString();
            w.IssueLabel.Text = "Errors";
            w.IssueText.Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11));

            w.DetailText.Text = "Check the application log for details on which files failed and why.";
            w.DetailBox.Visibility = Visibility.Visible;

            w.ShowDialog();
        }

        public static void ShowClean(Window? owner, int total, int skipped)
        {
            var w = new ScanResultsWindow { Owner = owner ?? Application.Current?.MainWindow };

            w.TitleText.Text = "All Files Clean";
            w.SubtitleText.Text = skipped > 0 ? $"{skipped} file(s) skipped (non-executable)" : "No threats found";

            w.TotalText.Text = total.ToString();
            w.CleanText.Text = (total - skipped).ToString();
            w.IssueText.Text = "0";
            w.IssueLabel.Text = "Threats";

            w.ShowDialog();
        }

        private void OkButton_Click(object sender, System.Windows.RoutedEventArgs e) => Close();
    }
}
