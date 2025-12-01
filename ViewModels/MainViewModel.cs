// ViewModels/MainViewModel.cs
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using PackItPro.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input; // For RelayCommand

namespace PackItPro.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged, IDisposable
    {
        #region Fields and Initialization
        private readonly string _appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PackItPro");
        private readonly string _cacheFilePath;
        private readonly SemaphoreSlim _scanSemaphore = new(4);
        private readonly HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
        ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
        ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf"
        };

        private HttpClient _httpClient = new(); // TODO: Consider using IHttpClientFactory or a singleton pattern for better lifecycle management
        private VirusTotalClient? _virusTotalClient;
        private PackagerService? _packagerService; // NEW: Instance of PackagerService

        // Properties holding sub-ViewModels
        public FileListViewModel FileList { get; }
        public SettingsViewModel Settings { get; }
        public SummaryViewModel Summary { get; }
        public StatusViewModel Status { get; }

        // Commands exposed for binding
        public ICommand PackCommand { get; }
        public ICommand BrowseFilesCommand { get; }
        public ICommand SetOutputLocationCommand { get; }
        public ICommand SetVirusApiKeyCommand { get; }
        public ICommand ExportLogsCommand { get; }
        public ICommand ViewCacheCommand { get; }
        public ICommand ClearCacheCommand { get; }
        public ICommand TestPackageCommand { get; }
        public ICommand ExportListCommand { get; }
        public ICommand DocumentationCommand { get; }
        public ICommand GitHubCommand { get; }
        public ICommand ReportIssueCommand { get; }
        public ICommand CheckUpdatesCommand { get; }
        public ICommand PackItProSettingsCommand { get; }
        public ICommand AboutCommand { get; }
        public ICommand ExitCommand { get; }
        public ICommand ClearAllFilesCommand { get; }
        public ICommand RetryCommand { get; }
        public ICommand DismissErrorCommand { get; }

        public MainViewModel()
        {
            // Initialize sub-ViewModels
            Settings = new SettingsViewModel(Path.Combine(_appDataDir, "settings.json"));
            FileList = new FileListViewModel(Settings, _executableExtensions); // Pass settings and extensions to FileListVM
            Summary = new SummaryViewModel(FileList); // Pass FileListVM to SummaryVM
            Status = new StatusViewModel(); // StatusVM is independent

            // Initialize paths
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");

            // Initialize services
            _virusTotalClient = new VirusTotalClient(_cacheFilePath, apiKey: null);
            _packagerService = new PackagerService(); // NEW: Initialize PackagerService

            // Initialize commands
            PackCommand = new RelayCommand(ExecutePackCommand, CanExecutePack);
            BrowseFilesCommand = new RelayCommand(ExecuteBrowseFilesCommand);
            SetOutputLocationCommand = new RelayCommand(ExecuteSetOutputLocationCommand);
            SetVirusApiKeyCommand = new RelayCommand(ExecuteSetVirusApiKeyCommand);
            ExportLogsCommand = new RelayCommand(ExecuteExportLogsCommand);
            ViewCacheCommand = new RelayCommand(ExecuteViewCacheCommand);
            ClearCacheCommand = new RelayCommand(ExecuteClearCacheCommand);
            TestPackageCommand = new RelayCommand(ExecuteTestPackageCommand);
            ExportListCommand = new RelayCommand(ExecuteExportListCommand);
            DocumentationCommand = new RelayCommand(ExecuteDocumentationCommand);
            GitHubCommand = new RelayCommand(ExecuteGitHubCommand);
            ReportIssueCommand = new RelayCommand(ExecuteReportIssueCommand);
            CheckUpdatesCommand = new RelayCommand(ExecuteCheckUpdatesCommand);
            PackItProSettingsCommand = new RelayCommand(ExecutePackItProSettingsCommand);
            AboutCommand = new RelayCommand(ExecuteAboutCommand);
            ExitCommand = new RelayCommand(ExecuteExitCommand);
            ClearAllFilesCommand = FileList.ClearAllFilesCommand; // Reuse command from FileListVM
            RetryCommand = new RelayCommand(ExecuteRetryCommand);
            DismissErrorCommand = new RelayCommand(ExecuteDismissErrorCommand);

            // Ensure directory exists
            if (!Directory.Exists(_appDataDir))
            {
                Directory.CreateDirectory(_appDataDir);
            }
        }

        public async Task InitializeAsync()
        {
            // Load settings first
            await Settings.LoadSettingsAsync();

            // Initialize VirusTotalClient with the loaded API key
            _virusTotalClient?.SetApiKey(Settings.VirusTotalApiKey);

            // Load VirusTotal cache using the client instance that was created after settings are loaded
            if (_virusTotalClient != null)
            {
                await _virusTotalClient.LoadCacheAsync();
            }
        }
        #endregion

        #region Command Implementations
        private bool CanExecutePack(object? parameter) => FileList.HasFiles && !Status.IsBusy; // Disable if no files or busy

        private async void ExecutePackCommand(object? parameter)
        {
            if (!CanExecutePack(parameter)) return;

            var saveDialog = new SaveFileDialog
            {
                Filter = "PackItPro Executable (.packitexe)|*.packitexe",
                InitialDirectory = Settings.OutputLocation,
                FileName = $"Package_{DateTime.Now:yyyyMMdd_HHmmss}.packitexe"
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    Status.SetStatusPacking(); // NEW: Set status before starting

                    var outputPath = await _packagerService?.CreatePackageAsync(
                        FileList.Items.Select(f => f.FilePath).ToList(),
                        Settings.OutputLocation,
                        Path.GetFileNameWithoutExtension(saveDialog.FileName),
                        Settings.RequiresAdmin, // NEW: Pass admin requirement from settings
                        Settings.IncludeWingetUpdateScript, // NEW: Pass includeWinget (as per XAML)
                        Settings.VerifyIntegrity, // NEW: Pass verifyIntegrity (as per XAML)
                        Settings.UseLZMACompression ? CompressionLevelEnum.Maximum : CompressionLevelEnum.Fast // NEW: Pass compressionLevel enum (as per XAML)
                    ) ?? throw new InvalidOperationException("PackagerService is not initialized.");

                    MessageBox.Show($"Package created successfully!\n{outputPath}",
                                  "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    LogError("Packager.CreatePackageAsync failed", ex);
                    Status.Message = $"Packaging failed: {ex.Message}"; // NEW: Update status message on error
                    MessageBox.Show($"Packaging failed: {ex.Message}",
                                  "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    Status.SetStatusReady(); // NEW: Reset status after completion
                }
            }
        }

        private void ExecuteBrowseFilesCommand(object? parameter)
        {
            var openFileDialog = new OpenFileDialog
            {
                Multiselect = true,
                Title = "Select Files to Pack"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                FileList.AddFilesWithValidation(openFileDialog.FileNames);
                // Trigger scan if setting is enabled
                if (Settings.IncludeWingetUpdateScript) // Assuming this checkbox triggers scanning initially (rename if needed)
                    _ = ExecuteScanFilesWithVirusTotal();
            }
        }

        private void ExecuteSetOutputLocationCommand(object? parameter)
        {
            var folderDialog = new CommonOpenFileDialog
            {
                IsFolderPicker = true,
                Title = "Select Output Folder",
                InitialDirectory = Settings.OutputLocation,
                EnsurePathExists = true
            };

            if (folderDialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                try
                {
                    var testFile = Path.Combine(folderDialog.FileName, "permission_test.tmp");
                    File.WriteAllText(testFile, "test");
                    File.Delete(testFile);

                    Settings.OutputLocation = folderDialog.FileName;
                    Settings.SaveSettingsAsync(); // Save settings after change
                }
                catch (UnauthorizedAccessException)
                {
                    MessageBox.Show("Write access denied to the selected directory.",
                        "Permission Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (Exception ex)
                {
                    LogError("Output location validation failed", ex);
                    MessageBox.Show($"Invalid output location: {ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExecuteSetVirusApiKeyCommand(object? parameter)
        {
            var dialog = new InputDialog(
                "VirusTotal API Key",
                "Enter your VirusTotal API key (64 characters):",
                Settings.VirusTotalApiKey
            );

            if (dialog.ShowDialog() == true)
            {
                var cleanedKey = dialog.Answer.Trim();
                if (string.IsNullOrEmpty(cleanedKey))
                {
                    MessageBox.Show("API key cannot be empty.",
                        "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (cleanedKey.Length != 64)
                {
                    MessageBox.Show("VirusTotal API keys must be 64 characters long.",
                        "Invalid Key", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                Settings.VirusTotalApiKey = cleanedKey;
                _virusTotalClient?.SetApiKey(cleanedKey); // Update client's API key
                Settings.SaveSettingsAsync(); // Save settings after change
                MessageBox.Show("API key updated successfully!",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // NEW: Add other command implementations here (ExportLogs, ViewCache, etc.)
        // For now, placeholder implementations:
        private void ExecuteExportLogsCommand(object? parameter)
        {
            var logPath = Path.Combine(_appDataDir, "packitpro.log");
            if (File.Exists(logPath))
            {
                var saveDialog = new SaveFileDialog
                {
                    Filter = "Log Files (*.log)|*.log|All Files (*.*)|*.*",
                    FileName = $"PackItPro_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
                };

                if (saveDialog.ShowDialog() == true)
                {
                    try
                    {
                        File.Copy(logPath, saveDialog.FileName, overwrite: true);
                        MessageBox.Show($"Logs exported to:\n{saveDialog.FileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        LogError("Log export failed", ex);
                        MessageBox.Show($"Failed to export logs: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            else
            {
                MessageBox.Show("No log file found to export.", "No Logs", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExecuteViewCacheCommand(object? parameter)
        {
            MessageBox.Show($"VirusTotal scan cache is located at:\n{_cacheFilePath}\n\nYou can open this file to view cached scan results.", "View Cache", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExecuteClearCacheCommand(object? parameter)
        {
            var result = MessageBox.Show(
                "Are you sure you want to clear the VirusTotal scan cache? This will force rescan of all files.",
                "Clear Cache",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                _virusTotalClient?.ClearCache(); // Clear the client's in-memory cache
                try
                {
                    if (File.Exists(_cacheFilePath))
                    {
                        File.Delete(_cacheFilePath);
                        LogInfo("VirusTotal scan cache file deleted.");
                    }
                }
                catch (Exception ex)
                {
                    LogError("Failed to delete cache file", ex);
                    MessageBox.Show($"Failed to delete cache file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                MessageBox.Show("VirusTotal scan cache cleared.", "Cache Cleared", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ExecuteTestPackageCommand(object? parameter)
        {
            MessageBox.Show("Package testing functionality is not yet implemented.", "Not Implemented", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExecuteExportListCommand(object? parameter)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Files in current package:");
            foreach (var item in FileList.Items)
            {
                sb.AppendLine($"- {item.FileName} ({item.Size})");
            }

            var saveDialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"Package_List_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(saveDialog.FileName, sb.ToString());
                    MessageBox.Show($"File list exported to:\n{saveDialog.FileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    LogError("File list export failed", ex);
                    MessageBox.Show($"Failed to export file list: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExecuteDocumentationCommand(object? parameter)
        {
            MessageBox.Show("Opening documentation...", "Documentation", MessageBoxButton.OK, MessageBoxImage.Information);
            // Process.Start(new ProcessStartInfo("https://your-documentation-url.com") { UseShellExecute = true }); // Example
        }

        private void ExecuteGitHubCommand(object? parameter)
        {
            MessageBox.Show("Opening GitHub repository...", "GitHub", MessageBoxButton.OK, MessageBoxImage.Information);
            // Process.Start(new ProcessStartInfo("https://github.com/your-username/your-repo") { UseShellExecute = true }); // Example
        }

        private void ExecuteReportIssueCommand(object? parameter)
        {
            MessageBox.Show("Opening issue reporting page...", "Report Issue", MessageBoxButton.OK, MessageBoxImage.Information);
            // Process.Start(new ProcessStartInfo("https://github.com/your-username/your-repo/issues/new") { UseShellExecute = true }); // Example
        }

        private void ExecuteCheckUpdatesCommand(object? parameter)
        {
            MessageBox.Show("Checking for updates...", "Check Updates", MessageBoxButton.OK, MessageBoxImage.Information);
            // Simulate update check
            // await Task.Delay(2000); // Simulate network call
            // MessageBox.Show("You are running the latest version.", "No Updates", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExecutePackItProSettingsCommand(object? parameter)
        {
            var settingsInfo = new StringBuilder();
            settingsInfo.AppendLine("Current PackItPro Settings:");
            settingsInfo.AppendLine($"- Output Location: {Settings.OutputLocation}");
            settingsInfo.AppendLine($"- VirusTotal API Key Set: {!string.IsNullOrEmpty(Settings.VirusTotalApiKey)}");
            settingsInfo.AppendLine($"- Only Scan Executables: {Settings.OnlyScanExecutables}");
            settingsInfo.AppendLine($"- Auto Remove Infected: {Settings.AutoRemoveInfectedFiles}");
            settingsInfo.AppendLine($"- Include Winget Update Script: {Settings.IncludeWingetUpdateScript}");
            settingsInfo.AppendLine($"- Use LZMA Compression: {Settings.UseLZMACompression}");
            settingsInfo.AppendLine($"- Requires Admin: {Settings.RequiresAdmin}");
            settingsInfo.AppendLine($"- Verify Integrity: {Settings.VerifyIntegrity}");

            MessageBox.Show(settingsInfo.ToString(), "PackItPro Settings", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExecuteAboutCommand(object? parameter)
        {
            MessageBox.Show("PackItPro v1.0\n\nA secure file packaging tool designed to bundle executable files into a single installer package with malware scanning capability.",
                "About PackItPro", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExecuteExitCommand(object? parameter)
        {
            Application.Current.Shutdown();
        }

        private void ExecuteRetryCommand(object? parameter)
        {
            // Implement logic to retry a failed operation (e.g., retry scan if a scan failed)
            // For now, just show a message
            MessageBox.Show("Retrying last operation...", "Retry", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExecuteDismissErrorCommand(object? parameter)
        {
            // Implement logic to dismiss an error message or clear the error state
            // For now, just clear the status message and hide the error panel
            Status.SetStatusReady(); // NEW: Reset status
            // Assuming ErrorPanel is handled in the View via binding or direct access
            // ErrorPanel?.Visibility = Visibility.Collapsed;
        }
        #endregion

        #region VirusTotal Integration (Refactored Call)
        private async Task ExecuteScanFilesWithVirusTotal()
        {
            if (Status.IsBusy) // Don't scan if already busy (packing or scanning)
            {
                LogInfo("Scan requested while already busy. Ignoring request.");
                return;
            }

            // NEW: Use the VirusTotalClient instance
            if (_virusTotalClient == null)
            {
                LogError("VirusTotalClient not initialized", new InvalidOperationException("VirusTotalClient is null"));
                MessageBox.Show("VirusTotal client is not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrEmpty(Settings.VirusTotalApiKey))
            {
                MessageBox.Show("VirusTotal API key is required for scanning. Please set it in Settings.",
                    "Configuration Required", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // NEW: Ensure API key is set in the client (should already be done on load, but re-set if key changed recently)
            _virusTotalClient.SetApiKey(Settings.VirusTotalApiKey);

            Status.SetStatusScanning(); // NEW: Set status before starting scan loop
            int totalFiles = FileList.Count;
            int processed = 0;

            var filesToRemove = new List<FileItemViewModel>();
            foreach (var item in FileList.Items)
            {
                try
                {
                    if (Settings.OnlyScanExecutables &&
                        !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                    {
                        item.Status = FileStatusEnum.Skipped;
                        continue;
                    }

                    // NEW: Use the client to scan the file
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        Settings.VirusTotalApiKey,
                        Settings.OnlyScanExecutables,
                        Settings.MinimumDetectionsToFlag
                    );

                    // NEW: Apply result to the item (properties like Positives, TotalScans are set too)
                    item.Positives = result.Positives;
                    item.TotalScans = result.TotalScans;
                    // The IsInfected property is calculated based on Status, which is set here
                    item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                    if (item.IsInfected && Settings.AutoRemoveInfectedFiles)
                        filesToRemove.Add(item);
                }
                catch (Exception ex)
                {
                    LogError($"Scan failed for {item.FileName}", ex);
                    item.Status = FileStatusEnum.ScanFailed;
                }
                finally
                {
                    processed++;
                    // Update progress percentage (this could be a property on StatusVM too)
                    Status.ProgressPercentage = (double)processed / totalFiles * 100;
                    // Could update progress text block here if needed via binding
                }
            }

            if (filesToRemove.Any())
            {
                var result = MessageBox.Show(
                    $"{filesToRemove.Count} infected files found. Remove them from the list?",
                    "Infected Files Detected",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    foreach (var infectedFile in filesToRemove)
                        FileList.Items.Remove(infectedFile);
                }
            }

            Status.SetStatusReady(); // NEW: Set status back to ready after scan completes
            Status.Message = "Scan completed"; // NEW: Update message

            // NEW: Save the updated cache via the client
            if (_virusTotalClient != null)
            {
                await _virusTotalClient.SaveCacheAsync();
            }
        }
        #endregion

        #region Error Handling
        private void LogError(string message, Exception ex)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:o}] {message}\n{ex}\n\n";
                var logPath = Path.Combine(_appDataDir, "packitpro.log"); // Log to AppData
                File.AppendAllText(logPath, logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { /* Ensure logging doesn't crash the app */ }
        }

        private void LogInfo(string message) // NEW helper for info logs
        {
            try
            {
                var logEntry = $"[{DateTime.Now:o}] [INFO] {message}\n";
                var logPath = Path.Combine(_appDataDir, "packitpro.log"); // Log to AppData
                File.AppendAllText(logPath, logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { /* Ensure logging doesn't crash the app */ }
        }
        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: Dispose managed state (managed objects).
                    _httpClient?.Dispose();
                    _scanSemaphore?.Dispose();
                    // NEW: Dispose the VirusTotalClient and PackagerService
                    _virusTotalClient?.Dispose();
                    _packagerService?.Dispose(); // NEW: Dispose PackagerService if it holds resources
                }

                // TODO: Free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: Set large fields to null.

                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // GC.SuppressFinalize(this);
        }
        #endregion

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}