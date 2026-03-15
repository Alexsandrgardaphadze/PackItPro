// PackItPro/Views/AlertDialog.xaml.cs

using System.Windows;
using System.Windows.Media;

namespace PackItPro.Views
{
    public partial class AlertDialog : Window
    {
        public enum Kind { Success, Info, Warning, Error }

        private AlertDialog() => InitializeComponent();

        /// <summary>
        /// Shows a modal alert dialog with a single OK button.
        /// </summary>
        /// <param name="owner">Parent window (CenterOwner). Null → CenterScreen.</param>
        /// <param name="title">Bold title.</param>
        /// <param name="message">Body text (wraps automatically).</param>
        /// <param name="detail">Optional monospace detail block (e.g. file path, error text).</param>
        /// <param name="kind">Controls icon and accent colour.</param>
        public static void Show(
            Window? owner,
            string title,
            string message,
            string? detail = null,
            Kind kind = Kind.Info)
        {
            var dlg = new AlertDialog
            {
                Owner = owner ?? Application.Current?.MainWindow
            };

            dlg.TitleText.Text = title;
            dlg.MessageText.Text = message;

            if (!string.IsNullOrWhiteSpace(detail))
            {
                dlg.DetailText.Text = detail;
                dlg.DetailBox.Visibility = Visibility.Visible;
            }

            switch (kind)
            {
                case Kind.Success:
                    dlg.IconText.Text = "✓";
                    dlg.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 34, 197, 94));   // green
                    break;
                case Kind.Warning:
                    dlg.IconText.Text = "⚠";
                    dlg.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 245, 158, 11));  // amber
                    break;
                case Kind.Error:
                    dlg.IconText.Text = "✕";
                    dlg.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 239, 68, 68));   // red
                    break;
                default: // Info
                    dlg.IconText.Text = "ℹ";
                    dlg.IconBorder.Background = new SolidColorBrush(Color.FromArgb(50, 79, 70, 229));   // indigo
                    break;
            }

            dlg.ShowDialog();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e) => Close();
    }
}
