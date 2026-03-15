// PackItPro/ViewModels/CommandHandlers/HelpHandler.cs
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class HelpHandler : CommandHandlerBase
    {
        private readonly UpdateService _updateService;
        private readonly StatusViewModel _status;
        private readonly ILogService _log;
        private bool _checkInProgress;

        public ICommand DocumentationCommand { get; }
        public ICommand GitHubCommand { get; }
        public ICommand ReportIssueCommand { get; }
        public ICommand CheckUpdatesCommand { get; }
        public ICommand AboutCommand { get; }

        private const string DocsUrl = "https://github.com/Alexsandrgardaphadze/PackItPro/wiki";
        private const string GitHubUrl = "https://github.com/Alexsandrgardaphadze/PackItPro";
        private const string IssuesUrl = "https://github.com/Alexsandrgardaphadze/PackItPro/issues/new";

        public HelpHandler(
            UpdateService updateService,
            StatusViewModel status,
            ILogService log)
        {
            _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            DocumentationCommand = new RelayCommand(_ => OpenUrl(DocsUrl));
            GitHubCommand = new RelayCommand(_ => OpenUrl(GitHubUrl));
            ReportIssueCommand = new RelayCommand(_ => OpenUrl(IssuesUrl));
            AboutCommand = new RelayCommand(_ => ShowAbout());
            CheckUpdatesCommand = new RelayCommand(
                _ => _ = CheckUpdatesAsync(userInitiated: true),
                _ => !_checkInProgress);
        }

        // ---- Manual check ---------------------------------------------------

        private async Task CheckUpdatesAsync(bool userInitiated)
        {
            if (_checkInProgress) return;
            _checkInProgress = true;
            RaiseCanExecuteChanged();

            string prevStatus = _status.Message;
            _status.Message = "Checking for updates...";
            _log.Info("Checking for updates...");

            UpdateCheckResult result;
            try
            {
                result = await _updateService.CheckAsync();
            }
            finally
            {
                _checkInProgress = false;
                _status.Message = prevStatus;
                RaiseCanExecuteChanged();
            }

            _log.Info($"Update check: success={result.Success} " +
                      $"available={result.UpdateAvailable} latest={result.LatestVersion}");

            if (!result.Success)
            {
                if (userInitiated)
                    AlertDialog.Show(
                        Application.Current.MainWindow,
                        "Update Check Failed",
                        result.ErrorMessage ?? "Unknown error.",
                        kind: AlertDialog.Kind.Warning);
                return;
            }

            if (result.NoReleasesPublished)
            {
                if (userInitiated)
                    AlertDialog.Show(
                        Application.Current.MainWindow,
                        "No Releases",
                        "No releases have been published for this project yet.",
                        kind: AlertDialog.Kind.Info);
                return;
            }

            if (!result.UpdateAvailable)
            {
                if (userInitiated)
                    AlertDialog.Show(
                        Application.Current.MainWindow,
                        "Up to Date",
                        $"PackItPro {result.CurrentVersion} is the latest version.",
                        kind: AlertDialog.Kind.Success);
                return;
            }

            // An update exists -- toast first, then show the download dialog
            ToastService.NotifyUpdateAvailable(
                result.CurrentVersion,
                result.LatestVersion,
                result.ReleaseUrl);

            UpdateAvailableWindow.Show(
                Application.Current.MainWindow,
                _updateService,
                result);
        }

        // ---- Silent startup check -------------------------------------------

        /// <summary>
        /// Call once from MainViewModel.InitializeAsync() -- fire and forget.
        /// Delays 8 s so the main window is fully visible before any dialog appears.
        /// Shows UpdateAvailableWindow only when an update is available.
        /// Completely silent on "up to date", network error, or no releases yet.
        /// </summary>
        public async Task CheckForUpdatesOnStartupAsync(CancellationToken ct = default)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(8), ct);

                _log.Info("Background update check (startup)...");
                var result = await _updateService.CheckAsync(ct);

                if (!result.Success || !result.UpdateAvailable) return;

                _log.Info($"Startup update check: {result.LatestVersion} available.");

                // Fire toast first (non-blocking, no focus steal), then show dialog
                ToastService.NotifyUpdateAvailable(
                    result.CurrentVersion,
                    result.LatestVersion,
                    result.ReleaseUrl);

                Application.Current.Dispatcher.Invoke(() =>
                    UpdateAvailableWindow.Show(
                        Application.Current.MainWindow,
                        _updateService,
                        result));
            }
            catch (OperationCanceledException) { /* app shutting down, ignore */ }
            catch (Exception ex)
            {
                _log.Error("Startup update check failed (non-fatal)", ex);
            }
        }

        // ---- Other commands -------------------------------------------------

        private static void ShowAbout()
        {
            var win = new AboutWindow
            {
                Owner = Application.Current?.MainWindow
            };
            win.ShowDialog();
        }

        private static void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch { /* best effort */ }
        }
    }
}