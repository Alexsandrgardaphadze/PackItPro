// Views/ConfirmDialog.xaml.cs
// Styled YesNo dialog. Replaces all MessageBox.Show(..., YesNo) calls in the app.
// Usage:
//   bool confirmed = ConfirmDialog.Show(
//       owner : this,
//       title  : "Delete API Key",
//       message: "Are you sure? Scanning will be disabled.",
//       kind   : ConfirmDialog.Kind.Danger);   // or .Warning / .Info
using System.Windows;

namespace PackItPro.Views
{
    public partial class ConfirmDialog : Window
    {
        public enum Kind { Warning, Danger, Info }

        private ConfirmDialog() => InitializeComponent();

        /// <summary>
        /// Shows a modal confirm dialog. Returns true if user clicked Yes/Confirm.
        /// </summary>
        /// <param name="owner">Parent window (for CenterOwner). Pass null for CenterScreen.</param>
        /// <param name="title">Bold title line.</param>
        /// <param name="message">Body text (wraps automatically).</param>
        /// <param name="confirmLabel">Label for the confirm button. Defaults to "Confirm".</param>
        /// <param name="cancelLabel">Label for the cancel button. Defaults to "Cancel".</param>
        /// <param name="kind">Controls the accent colour of the icon circle.</param>
        public static bool Show(
            Window? owner,
            string title,
            string message,
            string confirmLabel = "Confirm",
            string cancelLabel = "Cancel",
            Kind kind = Kind.Warning)
        {
            var dlg = new ConfirmDialog
            {
                Owner = owner ?? Application.Current?.MainWindow
            };

            dlg.TitleText.Text = title;
            dlg.MessageText.Text = message;
            dlg.YesButton.Content = confirmLabel;
            dlg.NoButton.Content = cancelLabel;

            // Icon + accent colour
            switch (kind)
            {
                case Kind.Danger:
                    dlg.IconText.Text = "🗑";
                    dlg.IconBorder.Background = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(50, 239, 68, 68));   // red-500 @ 20%
                    break;
                case Kind.Info:
                    dlg.IconText.Text = "ℹ";
                    dlg.IconBorder.Background = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(50, 79, 70, 229));   // indigo @ 20%
                    break;
                default: // Warning
                    dlg.IconText.Text = "⚠";
                    dlg.IconBorder.Background = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(50, 245, 158, 11));  // amber @ 20%
                    break;
            }

            return dlg.ShowDialog() == true;
        }

        private void YesButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void NoButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
