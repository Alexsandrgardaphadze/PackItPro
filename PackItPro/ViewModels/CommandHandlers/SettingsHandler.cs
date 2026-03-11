// PackItPro/ViewModels/CommandHandlers/SettingsHandler.cs - v2.0 CUSTOM DIALOGS
// Changes vs v1.x:
//   - MessageBox.Show(..., YesNo) → ConfirmDialog.Show(...)
//   - MessageBox.Show(..., OK)    → AlertDialog.Show(...)
//   - ExecutePackItProSettings    → PackItProSettingsWindow (real editable UI)
//   - ExecuteViewCache            → CacheViewWindow (stats + Open in Notepad)
using PackItPro.Models;
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class SettingsHandler : CommandHandlerBase
    {
        private readonly SettingsViewModel _settings;
        private readonly StatusViewModel _status;
        private readonly ErrorViewModel _error;
        private readonly VirusTotalClient? _virusTotalClient;
        private readonly TrustStore? _trustStore;
        private readonly string _cacheFilePath;
        private readonly string _appDataDir;
        private readonly ILogService _log;

        public ICommand SetOutputLocationCommand { get; }
        public ICommand SetVirusApiKeyCommand { get; }
        public ICommand DeleteVirusApiKeyCommand { get; }
        public ICommand ClearCacheCommand { get; }
        public ICommand ExportLogsCommand { get; }
        public ICommand PackItProSettingsCommand { get; }
        public ICommand ViewCacheCommand { get; }

        public SettingsHandler(
            SettingsViewModel settings,
            StatusViewModel status,
            ErrorViewModel error,
            VirusTotalClient? virusTotalClient,
            TrustStore? trustStore,
            string cacheFilePath,
            string appDataDir,
            ILogService log)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _error = error ?? throw new ArgumentNullException(nameof(error));
            _virusTotalClient = virusTotalClient;
            _trustStore = trustStore;
            _cacheFilePath = cacheFilePath ?? throw new ArgumentNullException(nameof(cacheFilePath));
            _appDataDir = appDataDir ?? throw new ArgumentNullException(nameof(appDataDir));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            SetOutputLocationCommand = new RelayCommand(async _ => await ExecuteSetOutputLocationAsync());
            SetVirusApiKeyCommand = new RelayCommand(ExecuteSetVirusApiKey);
            DeleteVirusApiKeyCommand = new RelayCommand(ExecuteDeleteVirusApiKey);
            ClearCacheCommand = new RelayCommand(ExecuteClearCache);
            ExportLogsCommand = new RelayCommand(ExecuteExportLogs);
            PackItProSettingsCommand = new RelayCommand(ExecutePackItProSettings);
            ViewCacheCommand = new RelayCommand(ExecuteViewCache);
        }

        // ── Output Location ───────────────────────────────────────────────────

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
                // Write-permission test
                var testFile = Path.Combine(dialog.SelectedPath, $"packitpro_test_{Guid.NewGuid()}.tmp");
                await File.WriteAllTextAsync(testFile, "test");
                File.Delete(testFile);

                _settings.OutputLocation = dialog.SelectedPath;
                await _settings.SaveSettingsAsync();
                _status.Message = $"Output location set to: {dialog.SelectedPath}";
                _log.Info($"Output location changed to: {dialog.SelectedPath}");

                await Task.Delay(3000);
                _status.SetStatusReady();
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

        // ── VirusTotal API Key ────────────────────────────────────────────────

        private void ExecuteSetVirusApiKey(object? parameter)
        {
            var dialog = new VirusApiKeyWindow(_settings.VirusTotalApiKey);
            if (dialog.ShowDialog() != true) return;

            var key = dialog.ApiKey?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(key))
            {
                _error.ShowError("API key cannot be empty.");
                return;
            }

            if (key.Length != 64)
            {
                _error.ShowError(
                    "VirusTotal API keys must be exactly 64 characters long.\n\n" +
                    "Get your free key at: https://www.virustotal.com/gui/user-settings/apikey");
                return;
            }

            _settings.VirusTotalApiKey = key;
            _virusTotalClient?.SetApiKey(key);
            _ = _settings.SaveSettingsAsync();

            AlertDialog.Show(
                Application.Current?.MainWindow,
                "API Key Saved",
                "Your VirusTotal API key was saved successfully.\n\n" +
                "Keys are stored locally and never sent anywhere by PackItPro.",
                kind: AlertDialog.Kind.Success);

            _log.Info("VirusTotal API key updated.");
        }

        // ── Delete VirusTotal API Key ─────────────────────────────────────────

        private void ExecuteDeleteVirusApiKey(object? parameter)
        {
            if (!CredentialStore.HasStoredKey())
            {
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "No Key Found",
                    "No VirusTotal API key is currently stored.",
                    kind: AlertDialog.Kind.Info);
                return;
            }

            bool confirmed = ConfirmDialog.Show(
                Application.Current?.MainWindow,
                "Delete API Key",
                "Are you sure you want to delete the stored VirusTotal API key?\n\n" +
                "Scanning will be disabled until a new key is entered.",
                confirmLabel: "Delete",
                cancelLabel: "Keep",
                kind: ConfirmDialog.Kind.Danger);

            if (!confirmed) return;

            CredentialStore.SaveVirusTotalKey("");
            _settings.VirusTotalApiKey = "";
            _virusTotalClient?.SetApiKey("");
            _ = _settings.SaveSettingsAsync();

            _log.Info("VirusTotal API key deleted.");

            AlertDialog.Show(
                Application.Current?.MainWindow,
                "Key Deleted",
                "VirusTotal API key deleted successfully.",
                kind: AlertDialog.Kind.Success);
        }

        // ── Clear Cache ───────────────────────────────────────────────────────

        private void ExecuteClearCache(object? parameter)
        {
            string detail = "";
            if (File.Exists(_cacheFilePath))
            {
                var size = new FileInfo(_cacheFilePath).Length;
                detail = $"Cache file: {FormatBytes(size)}";
            }

            bool confirmed = ConfirmDialog.Show(
                Application.Current?.MainWindow,
                "Clear Scan Cache",
                "All cached VirusTotal scan results will be deleted.\n\n" +
                "The next scan will re-submit every file to VirusTotal.",
                confirmLabel: "Clear",
                cancelLabel: "Cancel",
                kind: ConfirmDialog.Kind.Warning);

            if (!confirmed) return;

            try
            {
                _virusTotalClient?.ClearCache();
                if (File.Exists(_cacheFilePath))
                    File.Delete(_cacheFilePath);

                _log.Info("VirusTotal scan cache cleared.");

                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Cache Cleared",
                    "Scan cache cleared successfully.",
                    kind: AlertDialog.Kind.Success);
            }
            catch (Exception ex)
            {
                _log.Error("Cache clear failed", ex);
                _error.ShowError($"Failed to clear cache: {ex.Message}");
            }
        }

        // ── Export Logs ───────────────────────────────────────────────────────

        private void ExecuteExportLogs(object? parameter)
        {
            var candidates = new[]
            {
                Path.Combine(_appDataDir, "packitpro.log"),
                Path.Combine(_appDataDir, "Logs", "packitpro.log"),
                Path.Combine(_appDataDir, "Logs", "crash.log"),
            };

            string? logPath = null;
            foreach (var candidate in candidates)
                if (File.Exists(candidate)) { logPath = candidate; break; }

            if (logPath == null)
            {
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "No Logs Found",
                    "No log file has been created yet.",
                    detail: "Looked in:\n" + string.Join("\n", candidates),
                    kind: AlertDialog.Kind.Info);
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
                _log.Info($"Log exported to: {dialog.FileName}");

                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Export Successful",
                    "Log file exported successfully.",
                    detail: dialog.FileName,
                    kind: AlertDialog.Kind.Success);
            }
            catch (Exception ex)
            {
                _log.Error("Log export failed", ex);
                _error.ShowError($"Failed to export log: {ex.Message}");
            }
        }

        // ── PackItPro Settings ────────────────────────────────────────────────

        private void ExecutePackItProSettings(object? parameter)
        {
            var settingsPath = Path.Combine(_appDataDir, "settings.json");

            var window = new PackItProSettingsWindow(_settings.SettingsModel, settingsPath, _trustStore)
            {
                Owner = Application.Current?.MainWindow
            };

            if (window.ShowDialog() != true) return;

            // Apply editable fields back to ViewModel
            _settings.OutputFileName = window.OutputFileName;
            _settings.SettingsModel.MinimumDetectionsToFlag = window.MinDetections;
            _settings.SettingsModel.VerifyIntegrity = window.VerifyIntegrity;
            _settings.SettingsModel.MaxFilesInList = window.MaxFiles;

            _ = _settings.SaveSettingsAsync();
            _log.Info("Advanced settings saved via PackItProSettingsWindow.");
        }

        // ── View Cache ────────────────────────────────────────────────────────

        private void ExecuteViewCache(object? parameter)
        {
            if (!File.Exists(_cacheFilePath))
            {
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Cache Empty",
                    "No scan cache exists yet.\n\n" +
                    "The cache is created automatically after your first VirusTotal scan.",
                    kind: AlertDialog.Kind.Info);
                return;
            }

            try
            {
                var fileInfo = new FileInfo(_cacheFilePath);
                string json = File.ReadAllText(_cacheFilePath);
                int entryCount = CountJsonTopLevelKeys(json);

                var window = new CacheViewWindow(
                    entryCount,
                    fileInfo.Length,
                    fileInfo.LastWriteTime,
                    _cacheFilePath)
                {
                    Owner = Application.Current?.MainWindow
                };

                window.ShowDialog();
            }
            catch (Exception ex)
            {
                _log.Error("View cache failed", ex);
                _error.ShowError($"Failed to read cache: {ex.Message}");
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static int CountJsonTopLevelKeys(string json)
        {
            int count = 0, depth = 0;
            bool inString = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (c == '"' && (i == 0 || json[i - 1] != '\\')) inString = !inString;
                if (inString) continue;
                if (c == '{') depth++;
                else if (c == '}') depth--;
                else if (c == ':' && depth == 1) count++;
            }
            return count;
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:0.##} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:0.##} KB";
            return $"{bytes} B";
        }
    }
}