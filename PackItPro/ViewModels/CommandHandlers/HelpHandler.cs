// PackItPro/ViewModels/CommandHandlers/HelpHandler.cs - v2.3 (WITH UPDATE CHECK)
// Changes vs v2.2:
//   [1] Added CheckForUpdatesAsync method and command.
//       Queries GitHub API for latest release, compares version, offers download.
//   [2] Added UpdateService dependency injection.
//   [3] Added UpdateService reference to constructor.
//   [4] Added UpdateService to field list.
using PackItPro.Services;
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
                    MessageBox.Show(
                        $"Could not check for updates.\nError: {result.ErrorMessage}",
                        "PackItPro — Update Check Failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                if (result.NoReleasesPublished)
                {
                    MessageBox.Show(
                        $"You're running PackItPro {UpdateService.CurrentVersion}.\n" +
                        "No releases have been published yet — you already have the latest build.",
                        "PackItPro — Up to Date",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                _log.Info($"[HelpHandler] Latest: {result.LatestVersion}, Update available: {result.UpdateAvailable}");

                if (!result.UpdateAvailable)
                {
                    MessageBox.Show(
                        $"You're up to date!\n" +
                        $"Current version:  {result.CurrentVersion ?? UpdateService.CurrentVersion}\n" +
                        $"Latest release:   {result.LatestVersion ?? "unknown"}",
                        "PackItPro — Up to Date",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                string publishedWhen = result.PublishedAt.HasValue
                    ? $"\nPublished: {result.PublishedAt.Value.ToLocalTime():MMM d, yyyy}"
                    : "";

                string notes = !string.IsNullOrWhiteSpace(result.ReleaseNotes)
                    ? $"\nWhat's new:\n{Truncate(result.ReleaseNotes, 300)}"
                    : "";

                // Toast fires immediately; dialog appears on top
                if (!string.IsNullOrEmpty(result.ReleaseUrl))
                    ToastService.NotifyUpdateAvailable(result.CurrentVersion, result.LatestVersion, result.ReleaseUrl);

                var response = MessageBox.Show(
                    $"A new version of PackItPro is available!\n" +
                    $"Current version:  {result.CurrentVersion ?? UpdateService.CurrentVersion}\n" +
                    $"Latest version:   {result.LatestVersion ?? "unknown"}{publishedWhen}\n" +
                    $"{notes}\n" +
                    "Open the release page to download?",
                    "PackItPro — Update Available",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (response == MessageBoxResult.Yes && !string.IsNullOrEmpty(result.ReleaseUrl))
                    OpenUrl(result.ReleaseUrl);
            }
            catch (OperationCanceledException)
            {
                _log.Warning("[HelpHandler] Update check timed out.");
                MessageBox.Show(
                    "Update check timed out after 15 seconds.\nCheck your internet connection and try again.",
                    "PackItPro — Timeout",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
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
                MessageBox.Show(
                    $"Could not open documentation.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro/wiki\nError: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
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
                MessageBox.Show(
                    $"Could not open GitHub repository.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro\nError: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
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
                MessageBox.Show(
                    $"Could not open issue tracker.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro/issues\nError: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteAbout(object? parameter)
        {
            var version = UpdateService.CurrentVersion; // Use UpdateService for version
            MessageBox.Show(
                $"PackItPro {version}\n" +
                "A secure package builder for bundling multiple applications.\n" +
                "Still in development, but already close to finishing.\n" +
                "© 2026 Maybe all rights reserved.\n" +
                "GitHub: https://github.com/Alexsandrgardaphadze/PackItPro",
                "About PackItPro",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
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
                MessageBox.Show(
                    $"Could not open browser.\nVisit manually:\n{url}\nError: {ex.Message}",
                    "PackItPro",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
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