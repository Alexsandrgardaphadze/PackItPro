// PackItPro/ViewModels/MainViewModel.cs
using Microsoft.Win32;
using PackItPro.Services;
using PackItPro.Models;
using PackItPro.Views;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged, IDisposable
    {
        #region Fields and Initialization
        private readonly string _appDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PackItPro");

        private readonly string _cacheFilePath;
        private readonly HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
            ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
            ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf"
        };

        private VirusTotalClient? _virusTotalClient;
        private bool _isInitialized;

        // Sub-ViewModels (hierarchical MVVM structure)
        public FileListViewModel FileList { get; }
        public SettingsViewModel Settings { get; }
        public SummaryViewModel Summary { get; }
        public StatusViewModel Status { get; }

        // Commands (all properly typed and validated)
        public ICommand PackCommand { get; }
        public ICommand BrowseFilesCommand { get; }
        public ICommand SetOutputLocationCommand { get; }
        public ICommand SetVirusApiKeyCommand { get; }
        public ICommand ScanFilesCommand { get; }
        public ICommand ClearAllFilesCommand { get; }
        public ICommand ExportLogsCommand { get; }
        public ICommand ClearCacheCommand { get; }
        public ICommand ExitCommand { get; }

        public MainViewModel()
        {
            // Initialize paths first
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");
            EnsureAppDataDirectoryExists();

            // Initialize sub-ViewModels
            Settings = new SettingsViewModel(Path.Combine(_appDataDir, "settings.json"));
            FileList = new FileListViewModel(Settings.SettingsModel, _executableExtensions);
            Summary = new SummaryViewModel(FileList);
            Status = new StatusViewModel();

            // Initialize commands with proper can-execute logic
            PackCommand = new RelayCommand(ExecutePackCommand, CanExecutePack);
            BrowseFilesCommand = new RelayCommand(ExecuteBrowseFilesCommand);
            SetOutputLocationCommand = new RelayCommand(ExecuteSetOutputLocationCommand);
            SetVirusApiKeyCommand = new RelayCommand(ExecuteSetVirusApiKeyCommand);
            ScanFilesCommand = new RelayCommand(ExecuteScanFilesCommand, CanExecuteScan);
            ClearAllFilesCommand = new RelayCommand(ExecuteClearAllFilesCommand, CanExecuteClearAll);
            ExportLogsCommand = new RelayCommand(ExecuteExportLogsCommand);
            ClearCacheCommand = new RelayCommand(ExecuteClearCacheCommand);
            ExitCommand = new RelayCommand(ExecuteExitCommand);

            // Subscribe to property changes for UI state updates
            FileList.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(FileList.HasFiles))
                    ((RelayCommand)PackCommand).RaiseCanExecuteChanged();
            };

            Status.PropertyChanged += (s, e) =>
{
    if (e.PropertyName == nameof(Status.IsBusy))
    {
        if (PackCommand is RelayCommand packRelayCommand)
            packRelayCommand.RaiseCanExecuteChanged();

        if (ScanFilesCommand is RelayCommand scanRelayCommand)
            scanRelayCommand.RaiseCanExecuteChanged();
    }
};
        }

        private void EnsureAppDataDirectoryExists()
        {
            if (!Directory.Exists(_appDataDir))
                Directory.CreateDirectory(_appDataDir);
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            try
            {
                // 1. Load settings first
                await Settings.LoadSettingsAsync();

                // 2. Initialize VirusTotal client with loaded API key
                _virusTotalClient = new VirusTotalClient(_cacheFilePath, Settings.VirusTotalApiKey);

                // 3. Load scan cache
                await _virusTotalClient.LoadCacheAsync();

                _isInitialized = true;
                Status.SetStatusReady();
                LogInfo("MainViewModel initialized successfully");
            }
            catch (Exception ex)
            {
                LogError("Initialization failed", ex);
                Status.Message = "Failed to initialize application. Check logs for details.";
                MessageBox.Show(
                    "Application failed to initialize properly.\nSee logs for details.",
                    "Initialization Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        #endregion

        #region Command Execution (Async-Safe)
        private bool CanExecutePack(object? parameter) =>
            FileList.HasFiles && !Status.IsBusy && !string.IsNullOrWhiteSpace(Settings.OutputLocation);

        private async void ExecutePackCommand(object? parameter)
        {
            if (!CanExecutePack(parameter)) return;

            var saveDialog = new SaveFileDialog
            {
                Filter = "PackItPro Executable (*.exe)|*.exe",
                InitialDirectory = Settings.OutputLocation,
                FileName = $"{Settings.OutputFileName ?? "Package"}_{DateTime.Now:yyyyMMdd_HHmmss}.exe",
                DefaultExt = "exe",
                AddExtension = true
            };

            if (saveDialog.ShowDialog() != true) return;

            try
            {
                Status.SetStatusPacking();
                Status.Message = "Creating package...";

                // ✅ CRITICAL FIX: Use REAL Packager instead of placeholder PackagerService
                var outputPath = await Packager.CreatePackageAsync(
                    FileList.Items.Select(f => f.FilePath).ToList(),
                    Path.GetDirectoryName(saveDialog.FileName) ?? Settings.OutputLocation,
                    Path.GetFileNameWithoutExtension(saveDialog.FileName),
                    Settings.RequiresAdmin,
                    Settings.UseLZMACompression
                );

                Status.SetStatusReady();
                MessageBox.Show(
                    $"Package created successfully!\n\nLocation: {outputPath}",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (FileNotFoundException ex) when (ex.Message.Contains("StubInstaller.exe"))
            {
                HandleStubMissingError();
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("compare two elements"))
            {
                HandleHashingError(ex);
            }
            catch (Exception ex)
            {
                LogError("Packaging failed", ex);
                Status.Message = $"Packaging failed: {ex.Message}";
                MessageBox.Show(
                    $"Failed to create package:\n{ex.Message}\n\nCheck logs for details.",
                    "Packaging Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                Status.SetStatusReady();
            }
        }

        private void ExecuteBrowseFilesCommand(object? parameter)
        {
            var dialog = new OpenFileDialog
            {
                Multiselect = true,
                Title = "Select Files to Pack",
                Filter = "All Files (*.*)|*.*",
                CheckFileExists = true,
                CheckPathExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                FileList.AddFilesWithValidation(dialog.FileNames);

                // Auto-scan if enabled in settings
                if (Settings.ScanWithVirusTotal && !string.IsNullOrWhiteSpace(Settings.VirusTotalApiKey))
                {
                    ExecuteScanFilesCommand(null); // Fire-and-forget with internal error handling
                }
            }
        }

        private async void ExecuteSetOutputLocationCommand(object? parameter)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select output folder for packages",
                SelectedPath = Settings.OutputLocation,
                ShowNewFolderButton = true
            };

            var result = dialog.ShowDialog();
            if (result != System.Windows.Forms.DialogResult.OK || string.IsNullOrWhiteSpace(dialog.SelectedPath))
                return;

            try
            {
                // Validate write access
                var testFile = Path.Combine(dialog.SelectedPath, $"packitpro_test_{Guid.NewGuid()}.tmp");
                await File.WriteAllTextAsync(testFile, "test");
                File.Delete(testFile);

                Settings.OutputLocation = dialog.SelectedPath;
                await Settings.SaveSettingsAsync();
                Status.Message = $"Output location set to: {dialog.SelectedPath}";
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show(
                    "Cannot write to selected folder. Please choose a location with write permissions.",
                    "Permission Denied",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                LogError("Output location validation failed", ex);
                MessageBox.Show(
                    $"Invalid output location:\n{ex.Message}",
                    "Validation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteSetVirusApiKeyCommand(object? parameter)
        {
            var dialog = new InputDialog(
                "VirusTotal API Key",
                "Enter your 64-character VirusTotal API key:",
                Settings.VirusTotalApiKey);

            if (dialog.ShowDialog() != true) return;

            var key = dialog.Answer.Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                MessageBox.Show("API key cannot be empty.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (key.Length != 64)
            {
                MessageBox.Show(
                    "VirusTotal API keys must be exactly 64 characters long.\n\nGet your key from: https://www.virustotal.com/gui/user-settings/apikey",
                    "Invalid Key Length",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }

            Settings.VirusTotalApiKey = key;
            _virusTotalClient?.SetApiKey(key);
            _ = Settings.SaveSettingsAsync(); // Fire-and-forget save (non-critical)

            MessageBox.Show(
                "API key saved successfully!\n\nNote: Keys are stored locally and never transmitted by PackItPro.",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private bool CanExecuteScan(object? parameter) =>
            FileList.HasFiles && !Status.IsBusy && !string.IsNullOrWhiteSpace(Settings.VirusTotalApiKey);

        private async void ExecuteScanFilesCommand(object? parameter)
        {
            if (!CanExecuteScan(parameter)) return;

            try
            {
                Status.SetStatusScanning();
                await ExecuteScanFilesWithVirusTotal();
            }
            catch (Exception ex)
            {
                LogError("Scan operation failed", ex);
                Status.Message = $"Scan failed: {ex.Message}";
                MessageBox.Show(
                    $"Virus scan failed:\n{ex.Message}",
                    "Scan Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                Status.SetStatusReady();
            }
        }

        private void ExecuteClearAllFilesCommand(object? parameter)
        {
            if (FileList.Items.Count == 0) return;

            var result = MessageBox.Show(
                $"Remove all {FileList.Items.Count} files from the list?",
                "Confirm Clear",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
                FileList.ClearAllFilesCommand.Execute(null);
        }

        private bool CanExecuteClearAll(object? parameter) => FileList.HasFiles;

        private void ExecuteExportLogsCommand(object? parameter)
        {
            var logPath = Path.Combine(_appDataDir, "packitpro.log");
            if (!File.Exists(logPath))
            {
                MessageBox.Show("No log file exists yet.", "No Logs", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"PackItPro_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() == true)
            {
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
                    LogError("Log export failed", ex);
                    MessageBox.Show(
                        $"Failed to export logs:\n{ex.Message}",
                        "Export Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
        }

        private void ExecuteClearCacheCommand(object? parameter)
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
                LogError("Cache clear failed", ex);
                MessageBox.Show(
                    $"Failed to clear cache:\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteExitCommand(object? parameter)
        {
            // Save settings before exit
            _ = Settings.SaveSettingsAsync();
            Application.Current.Shutdown();
        }
        #endregion

        #region VirusTotal Scanning Logic
        private async Task ExecuteScanFilesWithVirusTotal()
        {
            if (_virusTotalClient == null || string.IsNullOrWhiteSpace(Settings.VirusTotalApiKey))
            {
                MessageBox.Show(
                    "VirusTotal API key is required for scanning.\nSet it in Settings > VirusTotal API Key.",
                    "API Key Required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var totalFiles = FileList.Items.Count(f =>
                !Settings.OnlyScanExecutables ||
                _executableExtensions.Contains(Path.GetExtension(f.FilePath)));

            if (totalFiles == 0)
            {
                MessageBox.Show(
                    "No scannable files found.\nEnable 'Scan all files' in settings to scan non-executables.",
                    "No Files to Scan",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            Status.Message = $"Scanning {totalFiles} file(s) with VirusTotal...";
            int processed = 0;
            var infectedFiles = new List<FileItemViewModel>();

            foreach (var item in FileList.Items)
            {
                // Skip non-executables if setting is enabled
                if (Settings.OnlyScanExecutables &&
                    !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                {
                    item.Status = FileStatusEnum.Skipped;
                    continue;
                }

                try
                {
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        Settings.VirusTotalApiKey,
                        Settings.OnlyScanExecutables,
                        Settings.MinimumDetectionsToFlag
                    );

                    item.Positives = result.Positives;
                    item.TotalScans = result.TotalScans;
                    item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                    if (result.IsInfected)
                        infectedFiles.Add(item);
                }
                catch (Exception ex)
                {
                    LogError($"Scan failed for {item.FileName}", ex);
                    item.Status = FileStatusEnum.ScanFailed;
                }
                finally
                {
                    processed++;
                    Status.ProgressPercentage = (double)processed / totalFiles * 100;
                }
            }

            // Handle infected files
            if (infectedFiles.Count > 0)
            {
                var message = $"{infectedFiles.Count} infected file(s) detected!";
                if (Settings.SettingsModel.AutoRemoveInfectedFiles)
                {
                    foreach (var file in infectedFiles)
                        FileList.Items.Remove(file);

                    message += $"\n\nAutomatically removed from package list.";
                }
                else
                {
                    message += $"\n\nReview files marked as 'Infected' before packaging.";
                }

                MessageBox.Show(
                    message,
                    "Security Alert",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                MessageBox.Show(
                    $"All {totalFiles} file(s) scanned clean!",
                    "Scan Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            // Save updated cache
            await _virusTotalClient.SaveCacheAsync();
            Status.Message = "Scan completed successfully";
        }
        #endregion

        #region Error Handling Helpers
        private void HandleStubMissingError()
        {
            var message = new StringBuilder();
            message.AppendLine("StubInstaller.exe not found!");
            message.AppendLine();
            message.AppendLine("To fix this:");
            message.AppendLine("1. Ensure StubInstaller.exe exists in your project directory");
            message.AppendLine("2. In Visual Studio:");
            message.AppendLine("   - Right-click StubInstaller.exe in Solution Explorer");
            message.AppendLine("   - Properties → 'Copy to Output Directory' = 'Copy always'");
            message.AppendLine("3. Rebuild the solution");
            message.AppendLine();
            message.AppendLine("Without this file, packaging cannot proceed.");

            MessageBox.Show(
                message.ToString(),
                "Missing Component",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            LogError("StubInstaller.exe missing", new FileNotFoundException("StubInstaller.exe not found in output directory"));
        }

        private void HandleHashingError(Exception ex)
        {
            MessageBox.Show(
                "Critical error during file hashing.\n\nThis usually happens when:" +
                "\n• Files are locked by another process" +
                "\n• Insufficient permissions to read files" +
                "\n• Corrupted file system\n\n" +
                "Try closing other applications and retry packaging.",
                "Hashing Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            LogError("File hashing failed", ex);
        }
        #endregion

        #region Logging
        private void LogError(string message, Exception ex)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:u}] ERROR: {message}\n{ex}\n\n";
                File.AppendAllText(Path.Combine(_appDataDir, "packitpro.log"), logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { /* Silent fail - don't crash on logging errors */ }
        }

        private void LogInfo(string message)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:u}] INFO: {message}\n";
                File.AppendAllText(Path.Combine(_appDataDir, "packitpro.log"), logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { /* Silent fail */ }
        }
        #endregion

        #region IDisposable Implementation
        private bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _virusTotalClient?.Dispose();
                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}