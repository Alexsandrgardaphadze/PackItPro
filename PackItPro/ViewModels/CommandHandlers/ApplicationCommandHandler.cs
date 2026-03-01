// PackItPro/ViewModels/CommandHandlers/ApplicationCommandHandler.cs
using PackItPro.Services;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class ApplicationCommandHandler : CommandHandlerBase
    {
        private readonly UpdateService _updateService;
        private readonly StatusViewModel _status;
        private readonly ILogService _log;

        private CancellationTokenSource? _checkCts;

        public ICommand CheckForUpdatesCommand { get; }
        public ICommand AboutCommand { get; }

        public ApplicationCommandHandler(
            UpdateService updateService,
            StatusViewModel status,
            ILogService log)
        {
            _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            CheckForUpdatesCommand = new AsyncRelayCommand(ExecuteCheckForUpdatesAsync, CanCheckForUpdates);
            AboutCommand = new RelayCommand(ExecuteAbout);

            _status.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(StatusViewModel.IsBusy))
                    RaiseCanExecuteChanged();
            };
        }

        private bool CanCheckForUpdates(object? _) => !_status.IsBusy;

        private async Task ExecuteCheckForUpdatesAsync(object? _)
        {
            _status.Message = "Checking for updates...";
            _checkCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            _log.Info($"Checking for updates. Current version: {UpdateService.CurrentVersion}");

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
                    _log.Info("No releases published on GitHub yet.");
                    MessageBox.Show(
                        $"You're running PackItPro {UpdateService.CurrentVersion}.\n\n" +
                        "No releases have been published yet — you already have the latest build.",
                        "PackItPro — Up to Date",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    return;
                }

                _log.Info($"Latest: {result.LatestVersion}, Current: {result.CurrentVersion}, Newer: {result.UpdateAvailable}");

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
                    ? $"\n\nWhat's new:\n{TruncateNotes(result.ReleaseNotes, 300)}"
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
                    OpenUrl(result.ReleaseUrl!);
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
                _status.Message = string.Empty;
                _checkCts?.Dispose();
                _checkCts = null;
            }
        }

        private void ExecuteAbout(object? _)
        {
            MessageBox.Show(
                $"PackItPro {UpdateService.CurrentVersion}\n\n" +
                "Modern Windows installer packager.\n" +
                "Combines multiple installers into a single self-extracting executable.\n\n" +
                "github.com/Alexsandrgardaphadze/PackItPro",
                "About PackItPro",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

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

        private static string TruncateNotes(string notes, int maxLength)
        {
            if (notes.Length <= maxLength) return notes;
            return notes[..maxLength].TrimEnd() + "\n…(see release page for full notes)";
        }

        public override void Dispose()
        {
            _checkCts?.Cancel();
            _checkCts?.Dispose();
            base.Dispose();
        }
    }
}