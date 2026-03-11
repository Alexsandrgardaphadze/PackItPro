// PackItPro/ViewModels/CommandHandlers/HelpHandler.cs - v2.3 (WITH UPDATE CHECK)
// Changes vs v2.2:
//   [1] Added CheckForUpdatesAsync method and command.
//       Queries GitHub API for latest release, compares version, offers download.
//   [2] Added UpdateService dependency injection.
//   [3] Added UpdateService reference to constructor.
//   [4] Added UpdateService to field list.
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.Diagnostics;
using System.Runtime.Intrinsics.X86;
using System.Security.Policy;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using static System.Net.WebRequestMethods;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class HelpHandler : CommandHandlerBase
    {
        private readonly UpdateService _updateService; // ✅ NEW DEPENDENCY
        private readonly StatusViewModel _status;
        private readonly ILogService _log;

        // Cancellation support for update check
        private CancellationTokenSource? _checkCts;

        public ICommand DocumentationCommand { get; }
        public ICommand GitHubCommand { get; }
        public ICommand ReportIssueCommand { get; }
        public ICommand CheckUpdatesCommand { get; } // ✅ NEW COMMAND
        public ICommand AboutCommand { get; }

        public HelpHandler(
            UpdateService updateService, // ✅ NEW PARAMETER
            StatusViewModel status,
            ILogService log)
        {
            _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService)); // ✅ STORE NEW DEPENDENCY
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            DocumentationCommand = new RelayCommand(ExecuteDocumentation);
            GitHubCommand = new RelayCommand(ExecuteGitHub);
            ReportIssueCommand = new RelayCommand(ExecuteReportIssue);
            CheckUpdatesCommand = new AsyncRelayCommand(ExecuteCheckUpdatesAsync, CanExecuteCheckUpdates); // ✅ NEW COMMAND INITIALIZATION
            AboutCommand = new RelayCommand(ExecuteAbout);

            // Subscribe to status changes for CanExecute updates
            _status.PropertyChanged += OnStatusPropertyChanged;
        }

        private void OnStatusPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(StatusViewModel.IsBusy))
                RaiseCanExecuteChanged();
        }

        private bool CanExecuteCheckUpdates(object? parameter) => !_status.IsBusy; // ✅ NEW: Disable while other operations run

        private async Task ExecuteCheckUpdatesAsync(object? parameter)
        {
            if (!CanExecuteCheckUpdates(parameter)) return;

            _status.Message = "Checking for updates...";
            _checkCts = new CancellationTokenSource(TimeSpan.FromSeconds(15)); // 15s timeout
            _log.Info($"[HelpHandler] Checking for updates. Current: {UpdateService.CurrentVersion}");

            try
            {
                var result = await _updateService.CheckAsync(_checkCts.Token);

                if (!result.Success)
                {
                    _log.Warning($"[HelpHandler] Update check failed: {result.ErrorMessage}");
                    AlertDialog.Show(
                        Application.Current?.MainWindow,
                        "Update Check Failed",
                        "Could not reach the update server. Check your internet connection.",
                        detail: result.ErrorMessage,
                        kind: AlertDialog.Kind.Warning);
                    return;
                }

                if (result.NoReleasesPublished)
                {
                    AlertDialog.Show(
                        Application.Current?.MainWindow,
                        "Up to Date",
                        $"You're running PackItPro {UpdateService.CurrentVersion}.\n" +
                        "No releases have been published yet — you already have the latest build.",
                        kind: AlertDialog.Kind.Info);
                    return;
                }

                _log.Info($"[HelpHandler] Latest: {result.LatestVersion}, Update available: {result.UpdateAvailable}");

                if (!result.UpdateAvailable)
                {
                    AlertDialog.Show(
                        Application.Current?.MainWindow,
                        "You're Up to Date",
                        $"PackItPro {result.CurrentVersion ?? UpdateService.CurrentVersion} is the latest version.",
                        kind: AlertDialog.Kind.Success);
                    return;
                }

                // Toast fires immediately; dialog appears on top
                if (!string.IsNullOrEmpty(result.ReleaseUrl))
                    ToastService.NotifyUpdateAvailable(result.CurrentVersion, result.LatestVersion, result.ReleaseUrl);

                var updateWindow = new UpdateAvailableWindow(
                    result.CurrentVersion ?? UpdateService.CurrentVersion,
                    result.LatestVersion,
                    result.PublishedAt?.UtcDateTime,
                    result.ReleaseNotes,
                    result.ReleaseUrl)
                {
                    Owner = Application.Current?.MainWindow
                };
                updateWindow.ShowDialog();

                if (updateWindow.ShouldDownload && !string.IsNullOrEmpty(result.ReleaseUrl))
                    OpenUrl(result.ReleaseUrl);
            }
            catch (OperationCanceledException)
            {
                _log.Warning("[HelpHandler] Update check timed out.");
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Request Timed Out",
                    "Update check timed out after 15 seconds.\nCheck your internet connection and try again.",
                    kind: AlertDialog.Kind.Warning);
            }
            finally
            {
                _status.Message = string.Empty; // Clear message
                _checkCts?.Dispose();
                _checkCts = null;
            }
        }

        private void ExecuteDocumentation(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo("https://github.com/Alexsandrgardaphadze/PackItPro/wiki") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(Application.Current?.MainWindow, "Cannot Open Browser",
                    "Could not open the documentation page.",
                    detail: "https://github.com/Alexsandrgardaphadze/PackItPro/wiki\n\n" + ex.Message,
                    kind: AlertDialog.Kind.Error);
            }
        }

        private void ExecuteGitHub(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo("https://github.com/Alexsandrgardaphadze/PackItPro") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(Application.Current?.MainWindow, "Cannot Open Browser",
                    "Could not open the GitHub repository.",
                    detail: "https://github.com/Alexsandrgardaphadze/PackItPro\n\n" + ex.Message,
                    kind: AlertDialog.Kind.Error);
            }
        }

        private void ExecuteReportIssue(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo("https://github.com/Alexsandrgardaphadze/PackItPro/issues") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(Application.Current?.MainWindow, "Cannot Open Browser",
                    "Could not open the issue tracker.",
                    detail: "https://github.com/Alexsandrgardaphadze/PackItPro/issues\n\n" + ex.Message,
                    kind: AlertDialog.Kind.Error);
            }
        }

        private void ExecuteAbout(object? parameter)
        {
            new AboutWindow { Owner = Application.Current?.MainWindow }.ShowDialog();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(Application.Current?.MainWindow, "Cannot Open Browser",
                    "Could not launch the browser. Visit the release page manually:",
                    detail: url + "\n\n" + ex.Message,
                    kind: AlertDialog.Kind.Error);
            }
        }

        private static string Truncate(string text, int max)
        {
            if (text.Length <= max) return text;
            return text[..max].TrimEnd() + "\n…(see release page for full notes)";
        }

        public override void Dispose()
        {
            _status.PropertyChanged -= OnStatusPropertyChanged;
            _checkCts?.Cancel();
            _checkCts?.Dispose();
            base.Dispose();
        }
    }
}