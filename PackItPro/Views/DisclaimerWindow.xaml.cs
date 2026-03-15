// PackItPro/Views/DisclaimerWindow.xaml.cs
using System.Windows;

namespace PackItPro.Views
{
    public partial class DisclaimerWindow : Window
    {
        private bool _accepted;

        // ---- Factory --------------------------------------------------------

        /// <summary>
        /// Shows the packaging disclaimer and returns whether the user accepted.
        /// suppressFuture is always false — the disclaimer shows on every pack.
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
            suppressFuture = false;
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

            // Show contextual warning cards only when relevant
            if (hasUnscannedFiles)
                UnscannedWarningBorder.Visibility = Visibility.Visible;
            if (requiresAdmin)
                AdminWarningBorder.Visibility = Visibility.Visible;
            if (hasInfectedFiles)
                InfectedWarningBorder.Visibility = Visibility.Visible;
        }

        // ---- Button handlers ------------------------------------------------

        private void Accept_Click(object sender, RoutedEventArgs e)
        {
            _accepted = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            _accepted = false;
            Close();
        }
    }
}
