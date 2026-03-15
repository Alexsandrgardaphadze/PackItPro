// PackItPro/Views/FileAddResultWindow.xaml.cs
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace PackItPro.Views
{
    public partial class FileAddResultWindow : Window
    {
        private FileAddResultWindow() => InitializeComponent();

        /// <summary>
        /// Shows the file-add result dialog. At least one of successCount / skipReasons must be non-zero/non-empty.
        /// </summary>
        public static void Show(Window? owner, int successCount, int skippedCount, IReadOnlyList<string> skipReasons)
        {
            var w = new FileAddResultWindow
            {
                Owner = owner ?? Application.Current?.MainWindow
            };

            bool allSkipped = successCount == 0 && skippedCount > 0;

            // Header
            if (allSkipped)
            {
                w.TitleText.Text = "No Files Added";
                w.IconText.Text = "✕";
                w.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 239, 68, 68));
            }
            else if (skippedCount > 0)
            {
                w.TitleText.Text = "Files Added (with warnings)";
                w.IconText.Text = "⚠";
                w.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 245, 158, 11));
            }
            // else default green ✓

            // Success row
            if (successCount > 0)
            {
                w.SuccessCountText.Text = $"{successCount} file(s)";
                w.SuccessBox.Visibility = Visibility.Visible;
            }

            // Skipped row
            if (skippedCount > 0)
            {
                w.SkippedCountText.Text = $"{skippedCount} file(s)";
                w.SkippedBox.Visibility = Visibility.Visible;

                const int maxShown = 6;
                w.SkipReasonsList.ItemsSource = skipReasons.Take(maxShown).ToList();

                if (skipReasons.Count > maxShown)
                {
                    w.MoreSkippedText.Text = $"…and {skipReasons.Count - maxShown} more";
                    w.MoreSkippedText.Visibility = Visibility.Visible;
                }
            }

            w.ShowDialog();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e) => Close();
    }
}
