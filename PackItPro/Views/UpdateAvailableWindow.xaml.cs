// PackItPro/Views/UpdateAvailableWindow.xaml.cs
using PackItPro.Services;
using System;
using System.Diagnostics;
using System.Threading;
using System.Windows;

namespace PackItPro.Views
{
    public partial class UpdateAvailableWindow : Window
    {
        private readonly UpdateService _updateService;
        private readonly UpdateCheckResult _result;
        private CancellationTokenSource? _downloadCts;
        private bool _downloadStarted;

        // ---- Factory --------------------------------------------------------

        /// <summary>
        /// Shows the update dialog and handles the full download+install flow.
        /// Safe to call from any thread -- marshals to UI thread internally.
        /// </summary>
        public static void Show(Window? owner, UpdateService updateService, UpdateCheckResult result)
        {
            var win = new UpdateAvailableWindow(updateService, result)
            {
                Owner = owner
            };
            win.ShowDialog();
        }

        // ---- Constructor ----------------------------------------------------

        private UpdateAvailableWindow(UpdateService updateService, UpdateCheckResult result)
        {
            InitializeComponent();
            _updateService = updateService;
            _result = result;

            PopulateFields();

            // Disable Install button if there is no direct download URL.
            // User can still open the releases page via the hyperlink.
            if (string.IsNullOrWhiteSpace(result.DownloadUrl))
            {
                InstallButton.IsEnabled = false;
                InstallButton.ToolTip =
                    "No PackItPro.exe asset is attached to this release.\n" +
                    "Use 'View on GitHub' to download manually.";
            }

            Closing += OnWindowClosing;
        }

        // ---- UI setup -------------------------------------------------------

        private void PopulateFields()
        {
            CurrentVersionText.Text = _result.CurrentVersion ?? "unknown";
            NewVersionText.Text = _result.LatestVersion ?? "unknown";

            if (_result.PublishedAt.HasValue)
            {
                SubtitleText.Text =
                    $"Published {_result.PublishedAt.Value.ToLocalTime():dd MMM yyyy}";
            }

            ReleaseNotesText.Text = string.IsNullOrWhiteSpace(_result.ReleaseNotes)
                ? "No release notes provided."
                : _result.ReleaseNotes.Trim();
        }

        // ---- Button handlers ------------------------------------------------

        private void Later_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void Install_Click(object sender, RoutedEventArgs e)
        {
            if (_downloadStarted) return;
            _downloadStarted = true;

            // Lock the UI for the duration of the download
            InstallButton.IsEnabled = false;
            LaterButton.IsEnabled = false;
            ProgressArea.Visibility = Visibility.Visible;
            DownloadProgress.IsIndeterminate = true;

            _downloadCts = new CancellationTokenSource();

            var progress = new Progress<DownloadProgress>(p =>
            {
                if (p.Percent >= 0)
                {
                    DownloadProgress.IsIndeterminate = false;
                    DownloadProgress.Value = p.Percent;
                }
                ProgressBytes.Text = FormatBytes(p.BytesReceived) +
                    (p.TotalBytes.HasValue ? $" / {FormatBytes(p.TotalBytes.Value)}" : "");
            });

            DownloadResult downloadResult;
            try
            {
                downloadResult = await _updateService.DownloadUpdateAsync(
                    _result.DownloadUrl!,
                    progress,
                    _downloadCts.Token);
            }
            catch (OperationCanceledException)
            {
                // User closed the window while downloading
                return;
            }

            if (!downloadResult.Success)
            {
                ResetToIdle();
                AlertDialog.Show(
                    this,
                    "Download Failed",
                    downloadResult.ErrorMessage ?? "Unknown error.",
                    kind: AlertDialog.Kind.Error);
                return;
            }

            // Download complete -- launch updater and exit
            ProgressLabel.Text = "Installing...";
            DownloadProgress.Value = 100;

            string? currentExe = UpdaterLauncher.GetCurrentExePath();
            if (string.IsNullOrEmpty(currentExe))
            {
                ResetToIdle();
                AlertDialog.Show(
                    this,
                    "Install Failed",
                    "Could not determine the path of the running executable.\n\n" +
                    "The update file has been downloaded but could not be applied automatically.\n\n" +
                    $"Downloaded file:\n{downloadResult.TempFilePath}",
                    kind: AlertDialog.Kind.Error);
                return;
            }

            try
            {
                UpdaterLauncher.LaunchUpdaterScript(currentExe, downloadResult.TempFilePath!);
            }
            catch (Exception ex)
            {
                ResetToIdle();
                AlertDialog.Show(
                    this,
                    "Install Failed",
                    "The update was downloaded but the installer script could not be launched.\n\n" +
                    "You can apply the update manually by replacing PackItPro.exe with the file below.",
                    detail: $"Script error: {ex.Message}\nDownloaded: {downloadResult.TempFilePath}",
                    kind: AlertDialog.Kind.Error);
                return;
            }

            // Script launched -- shut down so it can rename the file
            Application.Current.Shutdown();
        }

        private void OpenBrowser_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_result.ReleaseUrl)) return;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = _result.ReleaseUrl,
                    UseShellExecute = true
                });
            }
            catch { /* ignore -- browser open is best-effort */ }
        }

        // ---- Window closing -------------------------------------------------

        private void OnWindowClosing(object? sender,
            System.ComponentModel.CancelEventArgs e)
        {
            _downloadCts?.Cancel();
            _downloadCts?.Dispose();
        }

        // ---- Helpers --------------------------------------------------------

        private void ResetToIdle()
        {
            _downloadStarted = false;
            InstallButton.IsEnabled = !string.IsNullOrWhiteSpace(_result.DownloadUrl);
            LaterButton.IsEnabled = true;
            ProgressArea.Visibility = Visibility.Collapsed;
            DownloadProgress.Value = 0;
            DownloadProgress.IsIndeterminate = false;
            ProgressLabel.Text = "Downloading...";
            ProgressBytes.Text = "";
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:0.#} MB";
            if (bytes >= 1_024) return $"{bytes / 1_024.0:0.#} KB";
            return $"{bytes} B";
        }
    }
}
