// PackItPro/ViewModels/CommandHandlers/HelpHandler.cs
using PackItPro.Services;
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
        private const string GitHubRepo = "https://github.com/Alexsandrgardaphadze/PackItPro";
        private const string DocumentationUrl = "https://github.com/Alexsandrgardaphadze/PackItPro/wiki";
        private const string ReportIssueUrl = "https://github.com/Alexsandrgardaphadze/PackItPro/issues/new";

        private readonly UpdateService _updateService;
        private readonly StatusViewModel _status;
        private readonly ILogService _log;

        private CancellationTokenSource? _checkCts;

        public ICommand DocumentationCommand { get; }
        public ICommand GitHubCommand { get; }
        public ICommand ReportIssueCommand { get; }
        public ICommand CheckUpdatesCommand { get; }
        public ICommand AboutCommand { get; }

        public HelpHandler(UpdateService updateService, StatusViewModel status, ILogService log)
        {
            _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            DocumentationCommand = new RelayCommand(_ => OpenUrl(DocumentationUrl));
            GitHubCommand = new RelayCommand(_ => OpenUrl(GitHubRepo));
            ReportIssueCommand = new RelayCommand(_ => OpenUrl(ReportIssueUrl));
            CheckUpdatesCommand = new AsyncRelayCommand(ExecuteCheckUpdatesAsync, _ => !_status.IsBusy);
            AboutCommand = new RelayCommand(_ => ExecuteAbout());

            _status.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(StatusViewModel.IsBusy))
                    RaiseCanExecuteChanged();
            };
        }

        // ── Check for Updates ─────────────────────────────────────────────────

        private async Task ExecuteCheckUpdatesAsync(object? _)
        {
            _status.Message = "Checking for updates...";
            _checkCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            _log.Info($"Checking for updates. Current: {UpdateService.CurrentVersion}");

            try
            {
                var result = await _updateService.CheckAsync(_checkCts.Token);

                if (!result.Success)
                {
                    _log.Warning($"Update check failed: {result.ErrorMessage}");
                    MessageBox.Show(
                        $"Could not check for updates.\n\n{result.ErrorMessage}",
                        "PackItPro — Update Check Failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                if (result.NoReleasesPublished)
                {
                    MessageBox.Show(
                        $"You're running PackItPro {UpdateService.CurrentVersion}.\n\n" +
                        "No releases have been published yet — you already have the latest build.",
                        "PackItPro — Up to Date",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                _log.Info($"Latest: {result.LatestVersion}, Newer: {result.UpdateAvailable}");

                if (!result.UpdateAvailable)
                {
                    MessageBox.Show(
                        $"You're up to date!\n\n" +
                        $"Current version:  {result.CurrentVersion}\n" +
                        $"Latest release:   {result.LatestVersion}",
                        "PackItPro — Up to Date",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                string publishedWhen = result.PublishedAt.HasValue
                    ? $"\nPublished: {result.PublishedAt.Value.ToLocalTime():MMM d, yyyy}"
                    : "";

                string notes = !string.IsNullOrWhiteSpace(result.ReleaseNotes)
                    ? $"\n\nWhat's new:\n{Truncate(result.ReleaseNotes, 300)}"
                    : "";

                var response = MessageBox.Show(
                    $"A new version of PackItPro is available!\n\n" +
                    $"Current version:  {result.CurrentVersion}\n" +
                    $"Latest version:   {result.LatestVersion}{publishedWhen}" +
                    $"{notes}\n\n" +
                    "Open the release page to download?",
                    "PackItPro — Update Available",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (response == MessageBoxResult.Yes)
                    OpenUrl(result.ReleaseUrl ?? GitHubRepo);
            }
            catch (OperationCanceledException)
            {
                _log.Warning("Update check timed out.");
                MessageBox.Show(
                    "Update check timed out after 15 seconds.\n\nCheck your internet connection and try again.",
                    "PackItPro — Timeout",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            finally
            {
                _status.SetStatusReady();
                _checkCts?.Dispose();
                _checkCts = null;
            }
        }

        // ── About ─────────────────────────────────────────────────────────────

        private void ExecuteAbout()
        {
            MessageBox.Show(
                $"PackItPro  {UpdateService.CurrentVersion}\n\n" +
                "Modern Windows installer packager.\n" +
                "Bundles multiple installers into a single self-extracting executable " +
                "with silent installation, integrity verification, and optional VirusTotal scanning.\n\n" +
                "GitHub: github.com/Alexsandrgardaphadze/PackItPro\n\n" +
                $"Runtime: .NET {Environment.Version}  |  OS: {Environment.OSVersion.VersionString}",
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
                    $"Could not open browser.\n\nVisit manually:\n{url}\n\nError: {ex.Message}",
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
            _checkCts?.Cancel();
            _checkCts?.Dispose();
            base.Dispose();
        }
    }
}