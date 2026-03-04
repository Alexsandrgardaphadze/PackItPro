// PackItPro/ViewModels/CommandHandlers/SettingsHandler.cs
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.IO;
using System.Text;
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
                var testFile = Path.Combine(dialog.SelectedPath, $"packitpro_test_{Guid.NewGuid()}.tmp");
                await File.WriteAllTextAsync(testFile, "test");
                File.Delete(testFile);

                _settings.OutputLocation = dialog.SelectedPath;
                await _settings.SaveSettingsAsync();
                _status.Message = $"Output location set to: {dialog.SelectedPath}";
                _log.Info($"Output location changed to: {dialog.SelectedPath}");

                // FIX: Reset status after 3 seconds so the message doesn't linger forever
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
            var dialog = new InputDialog(
                "VirusTotal API Key",
                "Enter your 64-character VirusTotal API key:",
                _settings.VirusTotalApiKey);

            if (dialog.ShowDialog() != true) return;

            var key = dialog.Answer?.Trim() ?? "";
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

            MessageBox.Show(
                "API key saved successfully!\n\n" +
                "Keys are stored locally and never sent anywhere by PackItPro.",
                "VirusTotal API Key Saved",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            _log.Info("VirusTotal API key updated.");
        }

        // ── Clear Cache ───────────────────────────────────────────────────────

        private void ExecuteClearCache(object? parameter)
        {
            // Show cache info before asking to clear
            string sizeInfo = "";
            if (File.Exists(_cacheFilePath))
            {
                var size = new FileInfo(_cacheFilePath).Length;
                sizeInfo = $"\n\nCache file: {FormatBytes(size)}";
            }

            var result = MessageBox.Show(
                $"Clear VirusTotal scan cache?{sizeInfo}\n\n" +
                "All cached scan results will be deleted. The next scan will re-submit every file to VirusTotal.",
                "Clear Cache",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            try
            {
                _virusTotalClient?.ClearCache();
                if (File.Exists(_cacheFilePath))
                    File.Delete(_cacheFilePath);

                _log.Info("VirusTotal scan cache cleared.");
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
            {
                if (File.Exists(candidate)) { logPath = candidate; break; }
            }

            if (logPath == null)
            {
                MessageBox.Show(
                    $"No log file found yet.\n\nLooked in:\n{string.Join("\n", candidates)}",
                    "No Logs Found",
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
                _log.Info($"Log exported to: {dialog.FileName}");
                MessageBox.Show(
                    $"Log exported to:\n{dialog.FileName}",
                    "Export Successful",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _log.Error("Log export failed", ex);
                _error.ShowError($"Failed to export log: {ex.Message}");
            }
        }

        // ── PackItPro Settings ────────────────────────────────────────────────
        // Shows a dialog to edit all AppSettings fields that don't have
        // dedicated UI controls elsewhere.

        private void ExecutePackItProSettings(object? parameter)
        {
            var current = _settings.SettingsModel;

            var sb = new StringBuilder();
            sb.AppendLine("Current settings (edit settings.json to change advanced options):\n");
            sb.AppendLine($"  Output Location:          {current.OutputLocation}");
            sb.AppendLine($"  Output File Name:         {current.OutputFileName}");
            sb.AppendLine($"  Compression Level:        {current.CompressionLevel} (0=None, 1=Fast, 2=Max)");
            sb.AppendLine($"  Requires Admin:           {current.RequiresAdmin}");
            sb.AppendLine($"  Include Winget Updater:   {current.IncludeWingetUpdateScript}");
            sb.AppendLine($"  Verify Integrity:         {current.VerifyIntegrity}");
            sb.AppendLine($"  Scan With VirusTotal:     {current.ScanWithVirusTotal}");
            sb.AppendLine($"  Only Scan Executables:    {current.OnlyScanExecutables}");
            sb.AppendLine($"  Auto-Remove Infected:     {current.AutoRemoveInfectedFiles}");
            sb.AppendLine($"  Min Detections to Flag:   {current.MinimumDetectionsToFlag}");
            sb.AppendLine($"  Max Files in List:        {current.MaxFilesInList}");
            sb.AppendLine($"\nSettings file:\n  {Path.Combine(_appDataDir, "settings.json")}");

            var result = MessageBox.Show(
                sb.ToString() +
                "\n\nOpen the settings file in Notepad to edit advanced options?",
                "PackItPro Settings",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (result == MessageBoxResult.Yes)
            {
                var settingsPath = Path.Combine(_appDataDir, "settings.json");
                if (!File.Exists(settingsPath))
                {
                    // Write current settings to disk first so Notepad has something to open
                    _ = _settings.SaveSettingsAsync();
                    System.Threading.Thread.Sleep(200); // give Save a moment
                }

                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "notepad.exe",
                        Arguments = $"\"{settingsPath}\"",
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    _error.ShowError($"Could not open Notepad: {ex.Message}\n\nFile is at:\n{settingsPath}");
                }
            }
        }

        // ── View Cache ────────────────────────────────────────────────────────
        // Shows a human-readable summary of what's in the scan cache.

        private void ExecuteViewCache(object? parameter)
        {
            if (!File.Exists(_cacheFilePath))
            {
                MessageBox.Show(
                    "No scan cache exists yet.\n\n" +
                    "The cache is created automatically after your first VirusTotal scan.",
                    "Cache Empty",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            try
            {
                var fileInfo = new FileInfo(_cacheFilePath);
                string json = File.ReadAllText(_cacheFilePath);

                // Count entries — each top-level key is one cached file
                int entryCount = CountJsonTopLevelKeys(json);

                var result = MessageBox.Show(
                    $"VirusTotal Scan Cache\n\n" +
                    $"  Entries:     {entryCount} file(s)\n" +
                    $"  Cache size:  {FormatBytes(fileInfo.Length)}\n" +
                    $"  Last modified: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}\n" +
                    $"  Location:    {_cacheFilePath}\n\n" +
                    "Open cache file in Notepad to inspect individual entries?",
                    "View Cache",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (result == MessageBoxResult.Yes)
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "notepad.exe",
                        Arguments = $"\"{_cacheFilePath}\"",
                        UseShellExecute = true
                    });
                }
            }
            catch (Exception ex)
            {
                _log.Error("View cache failed", ex);
                _error.ShowError($"Failed to read cache: {ex.Message}");
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        // Rough JSON key counter — counts `"hash":` patterns as a proxy for entry count.
        // Avoids taking a full JSON library dependency just for a count.
        private static int CountJsonTopLevelKeys(string json)
        {
            // Each cache entry starts with a quoted SHA hash key.
            // Count occurrences of `":` after a `"` that follows `{` or `,` — good enough.
            int count = 0;
            bool inString = false;
            int depth = 0;
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