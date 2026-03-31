// PackItPro/Views/UpdateAvailableWindow.xaml.cs
using PackItPro.Services;
using System;
using System.Diagnostics;
using System.Threading;
using System.Windows;

namespace PackItPro.Views
{
    /// <summary>
    /// Shows release information and drives the download-and-install flow for
    /// both <c>PackItPro.exe</c> and <c>StubInstaller.exe</c>.
    /// </summary>
    public partial class UpdateAvailableWindow : Window
    {
        private readonly UpdateService _updateService;
        private readonly UpdateCheckResult _result;
        private CancellationTokenSource? _downloadCts;
        private bool _downloadStarted;

        // ── Factory ───────────────────────────────────────────────────────────

        /// <summary>
        /// Shows the update dialog modally.
        /// Safe to call from any thread — marshals to the UI thread internally.
        /// </summary>
        public static void Show(Window? owner, UpdateService updateService, UpdateCheckResult result)
        {
            var win = new UpdateAvailableWindow(updateService, result) { Owner = owner };
            win.ShowDialog();
        }

        // ── Constructor ───────────────────────────────────────────────────────

        private UpdateAvailableWindow(UpdateService updateService, UpdateCheckResult result)
        {
            InitializeComponent();
            _updateService = updateService;
            _result = result;

            PopulateFields();

            // Disable Install when no main asset is attached to the release.
            if (string.IsNullOrWhiteSpace(result.DownloadUrl))
            {
                InstallButton.IsEnabled = false;
                InstallButton.ToolTip =
                    "No PackItPro.exe asset is attached to this release.\n" +
                    "Use 'View on GitHub' to download manually.";
            }

            Closing += OnWindowClosing;
        }

        // ── UI population ─────────────────────────────────────────────────────

        private void PopulateFields()
        {
            CurrentVersionText.Text = _result.CurrentVersion ?? "unknown";
            NewVersionText.Text = _result.LatestVersion ?? "unknown";

            if (_result.PublishedAt.HasValue)
                SubtitleText.Text = $"Published {_result.PublishedAt.Value.ToLocalTime():dd MMM yyyy}";

            ReleaseNotesText.Text = string.IsNullOrWhiteSpace(_result.ReleaseNotes)
                ? "No release notes provided."
                : _result.ReleaseNotes.Trim();
        }

        // ── Button handlers ───────────────────────────────────────────────────

        private void Later_Click(object sender, RoutedEventArgs e) => Close();

        private async void Install_Click(object sender, RoutedEventArgs e)
        {
            if (_downloadStarted) return;
            _downloadStarted = true;

            // Lock UI for the duration of the download
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
                ProgressBytes.Text = FormatBytes(p.BytesReceived)
                    + (p.TotalBytes.HasValue ? $" / {FormatBytes(p.TotalBytes.Value)}" : "");
            });

            DualDownloadResult downloadResult;
            try
            {
                downloadResult = await _updateService.DownloadUpdateAsync(
                    _result, progress, _downloadCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Window was closed while downloading — temp files already cleaned up
                return;
            }

            if (!downloadResult.Success)
            {
                ResetToIdle();
                AlertDialog.Show(this, "Download Failed",
                    downloadResult.ErrorMessage ?? "Unknown error.",
                    kind: AlertDialog.Kind.Error);
                return;
            }

            // ── Launch updater script then exit ───────────────────────────────
            ProgressLabel.Text = "Installing...";
            DownloadProgress.Value = 100;

            string? currentExe = UpdaterLauncher.GetCurrentExePath();
            if (string.IsNullOrEmpty(currentExe))
            {
                ResetToIdle();
                AlertDialog.Show(this, "Install Failed",
                    "Could not determine the path of the running executable.\n\n" +
                    "The update was downloaded but could not be applied automatically.\n\n" +
                    $"Downloaded file:\n{downloadResult.MainTempPath}",
                    kind: AlertDialog.Kind.Error);
                return;
            }

            // Resolve the installed stub path (may be null if stub was not shipped yet)
            string? currentStub = UpdaterLauncher.GetCurrentStubPath();

            try
            {
                UpdaterLauncher.LaunchUpdaterScript(
                    currentExePath: currentExe,
                    tempMainPath: downloadResult.MainTempPath!,
                    currentStubPath: currentStub,
                    tempStubPath: downloadResult.StubTempPath);
            }
            catch (Exception ex)
            {
                ResetToIdle();
                AlertDialog.Show(this, "Install Failed",
                    "The update was downloaded but the installer script could not be launched.\n\n" +
                    "You can apply the update manually by replacing the files below.",
                    detail: $"Script error: {ex.Message}" +
                            $"\nPackItPro:      {downloadResult.MainTempPath}" +
                            $"\nStubInstaller:  {downloadResult.StubTempPath ?? "not downloaded"}",
                    kind: AlertDialog.Kind.Error);
                return;
            }

            // Script is running — shut down so it can rename the files
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
            catch { /* browser open is best-effort */ }
        }

        // ── Window closing ────────────────────────────────────────────────────

        private void OnWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            _downloadCts?.Cancel();
            _downloadCts?.Dispose();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

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