// PackItPro/Views/DisclaimerWindow.xaml.cs - v1.1
// Changes vs v1.0:
//   [1] Accept button disabled until user checks "I understand" checkbox.
//       Checkbox is unchecked by default — user must actively acknowledge.
//   [2] Cancel button has IsCancel="True" so ESC closes the dialog.
//   [3] Checkbox is focused on load for keyboard-first users.
//   [4] File scan summary (Files / Scanned / Unscanned / Infected / Trusted)
//       shown at the top so context is always visible.
//   [5] fileCount, scannedCount, infectedCount, trustedCount added to factory.
using System.Windows;

namespace PackItPro.Views
{
    public partial class DisclaimerWindow : Window
    {
        private bool _accepted;
        private bool _shouldSuppressFuture;

        // ---- Factory --------------------------------------------------------

        /// <summary>
        /// Shows the packaging disclaimer and returns whether the user accepted.
        /// suppressFuture is true when the user ticked "I understand" AND accepted.
        /// </summary>
        public static bool Show(
            Window? owner,
            out bool suppressFuture,
            int fileCount = 0,
            int scannedCount = 0,
            int infectedCount = 0,
            int trustedCount = 0,
            bool requiresAdmin = false,
            bool hasInfectedFiles = false,
            bool hasUnscannedFiles = false)
        {
            var win = new DisclaimerWindow(
                fileCount, scannedCount, infectedCount, trustedCount,
                requiresAdmin, hasInfectedFiles, hasUnscannedFiles)
            {
                Owner = owner
            };
            win.ShowDialog();
            suppressFuture = win._accepted && win._shouldSuppressFuture;
            return win._accepted;
        }

        // ---- Constructor ----------------------------------------------------

        private DisclaimerWindow(
            int fileCount,
            int scannedCount,
            int infectedCount,
            int trustedCount,
            bool requiresAdmin,
            bool hasInfectedFiles,
            bool hasUnscannedFiles)
        {
            InitializeComponent();

            // Populate summary strip
            int unscannedCount = System.Math.Max(0, fileCount - scannedCount - trustedCount);
            SummaryFilesText.Text = fileCount.ToString();
            SummaryScannedText.Text = scannedCount.ToString();
            SummaryUnscannedText.Text = unscannedCount.ToString();
            SummaryInfectedText.Text = infectedCount.ToString();
            SummaryTrustedText.Text = trustedCount.ToString();

            // Show contextual warning cards only when relevant
            if (hasUnscannedFiles)
                UnscannedWarningBorder.Visibility = Visibility.Visible;
            if (requiresAdmin)
                AdminWarningBorder.Visibility = Visibility.Visible;
            if (hasInfectedFiles)
                InfectedWarningBorder.Visibility = Visibility.Visible;

            // Focus the checkbox on load so keyboard users can act immediately
            Loaded += (_, _) => DoNotShowAgainBox.Focus();
        }

        // ---- Checkbox handlers ----------------------------------------------

        private void DoNotShowAgain_Checked(object sender, RoutedEventArgs e)
        {
            AcceptButton.IsEnabled = true;
        }

        private void DoNotShowAgain_Unchecked(object sender, RoutedEventArgs e)
        {
            AcceptButton.IsEnabled = false;
        }

        // ---- Button handlers ------------------------------------------------

        private void Accept_Click(object sender, RoutedEventArgs e)
        {
            _accepted = true;
            _shouldSuppressFuture = DoNotShowAgainBox.IsChecked == true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            _accepted = false;
            Close();
        }
    }
}