// ViewModels/CommandHandlers/SettingsHandler.cs
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    /// <summary>
    /// Handles all settings-related operations (Output Location, API Key, Cache, Logs)
    /// </summary>
    public class SettingsHandler : CommandHandlerBase
    {
        private readonly SettingsViewModel _settings;
        private readonly StatusViewModel _status;
        private readonly ErrorViewModel _error;
        private readonly VirusTotalClient? _virusTotalClient;
        private readonly string _cacheFilePath;
        private readonly string _appDataDir;
        private readonly ILogService _log;

        public ICommand SetOutputLocationCommand { get; }
        public ICommand SetVirusApiKeyCommand { get; }
        public ICommand ClearCacheCommand { get; }
        public ICommand ExportLogsCommand { get; }
        public ICommand PackItProSettingsCommand { get; }
        public ICommand ViewCacheCommand { get; }

        public SettingsHandler(
            SettingsViewModel settings,
            StatusViewModel status,
            ErrorViewModel error,
            VirusTotalClient? virusTotalClient,
            string cacheFilePath,
            string appDataDir,
            ILogService log)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _error = error ?? throw new ArgumentNullException(nameof(error));
            _virusTotalClient = virusTotalClient;
            _cacheFilePath = cacheFilePath ?? throw new ArgumentNullException(nameof(cacheFilePath));
            _appDataDir = appDataDir ?? throw new ArgumentNullException(nameof(appDataDir));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            SetOutputLocationCommand = new RelayCommand(async _ => await ExecuteSetOutputLocationAsync());
            SetVirusApiKeyCommand = new RelayCommand(ExecuteSetVirusApiKey);
            ClearCacheCommand = new RelayCommand(ExecuteClearCache);
            ExportLogsCommand = new RelayCommand(ExecuteExportLogs);
            PackItProSettingsCommand = new RelayCommand(ExecutePackItProSettings);
            ViewCacheCommand = new RelayCommand(ExecuteViewCache);
        }

        private async Task ExecuteSetOutputLocationAsync()
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select output folder for packages",
                SelectedPath = _settings.OutputLocation,
                ShowNewFolderButton = true
            };

            if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK ||
                string.IsNullOrWhiteSpace(dialog.SelectedPath))
                return;

            try
            {
                // Test write permissions
                var testFile = Path.Combine(dialog.SelectedPath, $"packitpro_test_{Guid.NewGuid()}.tmp");
                await File.WriteAllTextAsync(testFile, "test");
                File.Delete(testFile);

                _settings.OutputLocation = dialog.SelectedPath;
                await _settings.SaveSettingsAsync();
                _status.Message = $"Output location set to: {dialog.SelectedPath}";
            }
            catch (UnauthorizedAccessException)
            {
                _error.ShowError("Cannot write to selected folder. Please choose a location with write permissions.");
            }
            catch (Exception ex)
            {
                _log.Error("Output location validation failed", ex);
                _error.ShowError($"Invalid output location: {ex.Message}");
            }
        }

        private void ExecuteSetVirusApiKey(object? parameter)
        {
            var dialog = new InputDialog(
                "VirusTotal API Key",
                "Enter your 64-character VirusTotal API key:",
                _settings.VirusTotalApiKey);

            if (dialog.ShowDialog() != true) return;

            var key = dialog.Answer.Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                _error.ShowError("API key cannot be empty.");
                return;
            }

            if (key.Length != 64)
            {
                _error.ShowError(
                    "VirusTotal API keys must be exactly 64 characters long.\n\n" +
                    "Get your key from: https://www.virustotal.com/gui/user-settings/apikey");
                return;
            }

            _settings.VirusTotalApiKey = key;
            _virusTotalClient?.SetApiKey(key);
            _ = _settings.SaveSettingsAsync();

            MessageBox.Show(
                "API key saved successfully!\n\n" +
                "Note: Keys are stored locally and never transmitted by PackItPro.",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteClearCache(object? parameter)
        {
            var result = MessageBox.Show(
                "Clear VirusTotal scan cache?\n\nThis will force re-scanning of all files on next scan.",
                "Clear Cache",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            try
            {
                _virusTotalClient?.ClearCache();

                if (File.Exists(_cacheFilePath))
                    File.Delete(_cacheFilePath);

                MessageBox.Show(
                    "Scan cache cleared successfully.",
                    "Cache Cleared",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _log.Error("Cache clear failed", ex);
                _error.ShowError($"Failed to clear cache: {ex.Message}");
            }
        }

        private void ExecuteExportLogs(object? parameter)
        {
            var logPath = Path.Combine(_appDataDir, "packitpro.log");
            if (!File.Exists(logPath))
            {
                MessageBox.Show(
                    "No log file exists yet.",
                    "No Logs",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"PackItPro_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                File.Copy(logPath, dialog.FileName, overwrite: true);
                MessageBox.Show(
                    $"Logs exported to:\n{dialog.FileName}",
                    "Export Successful",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _log.Error("Log export failed", ex);
                _error.ShowError($"Failed to export logs: {ex.Message}");
            }
        }

        private void ExecutePackItProSettings(object? parameter)
        {
            MessageBox.Show(
                "Settings dialog not yet implemented.\n\nUse Settings menu for now.",
                "Settings",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteViewCache(object? parameter)
        {
            MessageBox.Show(
                "Cache viewer not yet implemented.",
                "View Cache",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }
}