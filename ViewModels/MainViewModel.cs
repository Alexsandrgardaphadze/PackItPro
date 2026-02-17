// ViewModels/MainViewModel.cs - COMPLETE FIXED VERSION
using Microsoft.Win32;
using PackItPro.Services;
using PackItPro.Models;
using PackItPro.Views;
using PackItPro.ViewModels.CommandHandlers;
// using PackItPro.ViewModels.Services;
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
        private VirusTotalCommandHandler? _virusTotalHandler;
        private readonly ILogService _logService;
        private bool _isInitialized;

        // ✅ NEW: Added ErrorViewModel
        public ErrorViewModel Error { get; }

        // Sub-ViewModels
        public FileListViewModel FileList { get; }
        public SettingsViewModel Settings { get; }
        public SummaryViewModel Summary { get; }
        public StatusViewModel Status { get; }

        // Commands
        public ICommand PackCommand { get; }
        public ICommand BrowseFilesCommand { get; }
        public ICommand SetOutputLocationCommand { get; }
        public ICommand SetVirusApiKeyCommand { get; }
        public ICommand ScanFilesCommand => _virusTotalHandler?.ScanFilesCommand ?? new RelayCommand(_ => { });
        public ICommand CancelScanCommand => _virusTotalHandler?.CancelScanCommand ?? new RelayCommand(_ => { });
        public ICommand ClearAllFilesCommand { get; }
        public ICommand ExportLogsCommand { get; }
        public ICommand ClearCacheCommand { get; }
        public ICommand ExitCommand { get; }
        public ICommand PackItProSettingsCommand { get; }
        public ICommand TestPackageCommand { get; }
        public ICommand ViewCacheCommand { get; }
        public ICommand ExportListCommand { get; }
        public ICommand DocumentationCommand { get; }
        public ICommand GitHubCommand { get; }
        public ICommand ReportIssueCommand { get; }
        public ICommand CheckUpdatesCommand { get; }
        public ICommand AboutCommand { get; }

        public MainViewModel()
        {
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");
            EnsureAppDataDirectoryExists();

            // Initialize log service
            var logPath = Path.Combine(_appDataDir, "packitpro.log");
            _logService = new FileLogService(logPath);

            // Initialize sub-ViewModels
            Settings = new SettingsViewModel(Path.Combine(_appDataDir, "settings.json"));
            FileList = new FileListViewModel(Settings.SettingsModel, _executableExtensions);
            Summary = new SummaryViewModel(FileList, Settings);  // ✅ Pass Settings to SummaryViewModel
            Status = new StatusViewModel();
            Error = new ErrorViewModel(); // ✅ Initialize ErrorViewModel

            // Initialize commands
            PackCommand = new RelayCommand(ExecutePackCommand, CanExecutePack);
            BrowseFilesCommand = new RelayCommand(ExecuteBrowseFilesCommand);
            SetOutputLocationCommand = new RelayCommand(ExecuteSetOutputLocationCommand);
            SetVirusApiKeyCommand = new RelayCommand(ExecuteSetVirusApiKeyCommand);
            ClearAllFilesCommand = new RelayCommand(ExecuteClearAllFilesCommand, CanExecuteClearAll);
            ExportLogsCommand = new RelayCommand(ExecuteExportLogsCommand);
            ClearCacheCommand = new RelayCommand(ExecuteClearCacheCommand);
            ExitCommand = new RelayCommand(ExecuteExitCommand);
            PackItProSettingsCommand = new RelayCommand(ExecutePackItProSettingsCommand);
            TestPackageCommand = new RelayCommand(ExecuteTestPackageCommand);
            ViewCacheCommand = new RelayCommand(ExecuteViewCacheCommand);
            ExportListCommand = new RelayCommand(ExecuteExportListCommand);
            DocumentationCommand = new RelayCommand(ExecuteDocumentationCommand);
            GitHubCommand = new RelayCommand(ExecuteGitHubCommand);
            ReportIssueCommand = new RelayCommand(ExecuteReportIssueCommand);
            CheckUpdatesCommand = new RelayCommand(ExecuteCheckUpdatesCommand);
            AboutCommand = new RelayCommand(ExecuteAboutCommand);

            // ✅ FIX: Use named methods instead of lambdas to prevent memory leaks
            FileList.PropertyChanged += OnFileListPropertyChanged;
            Status.PropertyChanged += OnStatusPropertyChanged;
        }

        // ✅ FIX: Named event handlers for proper cleanup
        private void OnFileListPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(FileList.HasFiles))
            {
                ((RelayCommand)PackCommand).RaiseCanExecuteChanged();
            }
        }

        private void OnStatusPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(Status.IsBusy))
            {
                ((RelayCommand)PackCommand).RaiseCanExecuteChanged();
            }
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
                await Settings.LoadSettingsAsync();
                LogInfo("Settings loaded successfully");

                _virusTotalClient = new VirusTotalClient(_cacheFilePath, Settings.VirusTotalApiKey);
                LogInfo("VirusTotal client initialized");

                await _virusTotalClient.LoadCacheAsync();
                LogInfo("Scan cache loaded");

                // Initialize VirusTotal handler
                _virusTotalHandler = new VirusTotalCommandHandler(
                    FileList,
                    Settings,
                    Status,
                    Error,
                    _virusTotalClient,
                    _logService,
                    _executableExtensions);
                LogInfo("VirusTotal handler initialized");

                _isInitialized = true;
                Status.SetStatusReady();
                LogInfo("MainViewModel initialized successfully");
            }
            catch (Exception ex)
            {
                LogError("Initialization failed", ex);
                Status.Message = "Failed to initialize application. Check logs for details.";

                // ✅ NEW: Use ErrorViewModel instead of MessageBox
                Error.ShowError(
                    "Application failed to initialize properly. See logs for details.",
                    retryAction: async () => await InitializeAsync()
                );
            }
        }
        #endregion

        #region Command Execution - Primary Commands
        private bool CanExecutePack(object? parameter) =>
            FileList.HasFiles && !Status.IsBusy && !string.IsNullOrWhiteSpace(Settings.OutputLocation);

        private async void ExecutePackCommand(object? parameter)
        {
            if (!CanExecutePack(parameter)) return;

            try
            {
                if (!Settings.ValidateSettings(out var errorMessage))
                {
                    Error.ShowError($"Invalid settings: {errorMessage}");
                    return;
                }

                var saveDialog = new SaveFileDialog
                {
                    Filter = "PackItPro Executable (*.exe)|*.exe",
                    InitialDirectory = Settings.OutputLocation,
                    FileName = $"{Settings.OutputFileName ?? "Package"}_{DateTime.Now:yyyyMMdd_HHmmss}.exe",
                    DefaultExt = "exe",
                    AddExtension = true
                };

                if (saveDialog.ShowDialog() != true) return;

                // ✅ NEW: Set initial status and start progress reporting
                Status.SetStatusPacking();
                Status.Message = "Preparing to create package...";
                Status.ProgressPercentage = 0;

                // ✅ NEW: Create progress reporter to update StatusViewModel
                var progress = new Progress<(int percentage, string message)>(report =>
                {
                    Status.ProgressPercentage = report.percentage;
                    Status.Message = report.message;
                    LogInfo($"Pack Progress: {report.percentage}% - {report.message}");
                });

                var outputPath = await Packager.CreatePackageAsync(
                    FileList.Items.Select(f => f.FilePath).ToList(),
                    Path.GetDirectoryName(saveDialog.FileName) ?? Settings.OutputLocation,
                    Path.GetFileNameWithoutExtension(saveDialog.FileName),
                    Settings.RequiresAdmin,
                    Settings.UseLZMACompression,
                    progress  // ✅ NEW: Pass progress reporter
                );

                Status.SetStatusReady();
                Status.Message = "Package created successfully!";
                Status.ProgressPercentage = 100;

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
            catch (IOException ex) when (ex.Message.Contains("in use"))
            {
                Error.ShowError(
                    $"Cannot package: A file is locked or in use.\n\nSolution: Close programs using these files and try again.",
                    retryAction: () => ExecutePackCommand(parameter)
                );
                LogError("Packaging failed - file locked", ex);
            }
            catch (Exception ex)
            {
                LogError("Packaging failed", ex);
                Status.Message = $"Packaging failed: {ex.Message}";
                Error.ShowError(
                    $"Failed to create package: {ex.Message}\n\nCheck logs for details.",
                    retryAction: () => ExecutePackCommand(parameter)
                );
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
                FileList.AddFilesWithValidation(dialog.FileNames, out var result);

                if (result.SkippedCount > 0)
                {
                    var message = $"Added {result.SuccessCount} file(s).\n\n";
                    message += $"Skipped {result.SkippedCount}:\n";
                    message += string.Join("\n", result.SkipReasons.Take(3));
                    if (result.SkipReasons.Count > 3)
                        message += $"\n...and {result.SkipReasons.Count - 3} more";

                    MessageBox.Show(message, "Files Added", MessageBoxButton.OK, MessageBoxImage.Information);
                }

                if (Settings.ScanWithVirusTotal && !string.IsNullOrWhiteSpace(Settings.VirusTotalApiKey))
                {
                    ScanFilesCommand.Execute(null);
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
                var testFile = Path.Combine(dialog.SelectedPath, $"packitpro_test_{Guid.NewGuid()}.tmp");
                await File.WriteAllTextAsync(testFile, "test");
                File.Delete(testFile);

                Settings.OutputLocation = dialog.SelectedPath;
                await Settings.SaveSettingsAsync();
                Status.Message = $"Output location set to: {dialog.SelectedPath}";
            }
            catch (UnauthorizedAccessException)
            {
                Error.ShowError("Cannot write to selected folder. Please choose a location with write permissions.");
            }
            catch (Exception ex)
            {
                LogError("Output location validation failed", ex);
                Error.ShowError($"Invalid output location: {ex.Message}");
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
                Error.ShowError("API key cannot be empty.");
                return;
            }

            if (key.Length != 64)
            {
                Error.ShowError("VirusTotal API keys must be exactly 64 characters long.\n\nGet your key from: https://www.virustotal.com/gui/user-settings/apikey");
                return;
            }

            Settings.VirusTotalApiKey = key;
            _virusTotalClient?.SetApiKey(key);
            _ = Settings.SaveSettingsAsync();

            MessageBox.Show(
                "API key saved successfully!\n\nNote: Keys are stored locally and never transmitted by PackItPro.",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
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
        #endregion

        #region Command Execution - Additional Commands
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
                    Error.ShowError($"Failed to export logs: {ex.Message}");
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
                Error.ShowError($"Failed to clear cache: {ex.Message}");
            }
        }

        private void ExecuteExitCommand(object? parameter)
        {
            _ = Settings.SaveSettingsAsync();
            Application.Current.Shutdown();
        }

        private void ExecutePackItProSettingsCommand(object? parameter)
        {
            MessageBox.Show(
                "Settings dialog not yet implemented.\n\nUse Settings menu for now.",
                "Settings",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteTestPackageCommand(object? parameter)
        {
            MessageBox.Show(
                "Test package feature not yet implemented.",
                "Test Package",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteViewCacheCommand(object? parameter)
        {
            MessageBox.Show(
                "Cache viewer not yet implemented.",
                "View Cache",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteExportListCommand(object? parameter)
        {
            if (FileList.Items.Count == 0)
            {
                MessageBox.Show(
                    "No files to export.",
                    "Export List",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                FileName = $"PackItPro_FileList_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var content = string.Join("\n", FileList.Items.Select(f => $"{f.FileName} - {f.Size}"));
                    File.WriteAllText(dialog.FileName, content);
                    MessageBox.Show(
                        $"File list exported to:\n{dialog.FileName}",
                        "Export Successful",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    LogError("File list export failed", ex);
                    Error.ShowError($"Failed to export list: {ex.Message}");
                }
            }
        }

        private void ExecuteDocumentationCommand(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/Alexsandrgardaphadze/PackItPro/wiki",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogError("Failed to open documentation", ex);
                MessageBox.Show(
                    "Could not open documentation.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro/wiki",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteGitHubCommand(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/Alexsandrgardaphadze/PackItPro",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogError("Failed to open GitHub", ex);
                MessageBox.Show(
                    "Could not open GitHub repository.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteReportIssueCommand(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/Alexsandrgardaphadze/PackItPro/issues",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                LogError("Failed to open issue tracker", ex);
                MessageBox.Show(
                    "Could not open issue tracker.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro/issues",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteCheckUpdatesCommand(object? parameter)
        {
            MessageBox.Show(
                "Update check feature not yet implemented.",
                "Check for Updates",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteAboutCommand(object? parameter)
        {
            MessageBox.Show(
                "PackItPro v0.5.1\n\n" +
                "A secure package builder for bundling multiple applications.\n\n" +
                "Still in development, but already close to finishing.\n\n" +
                "© 2025 Maybe all rights reserved.\n\n" +
                "GitHub: https://github.com/Alexsandrgardaphadze/PackItPro",
                "About PackItPro",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
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

            Error.ShowError(message.ToString());
            LogError("StubInstaller.exe missing", new FileNotFoundException("StubInstaller.exe not found"));
        }
        #endregion

        #region Logging
        private void LogError(string message, Exception ex) => _logService.Error(message, ex);

        private void LogInfo(string message) => _logService.Info(message);
        #endregion

        #region IDisposable Implementation
        private bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // ✅ Unsubscribe from events to prevent memory leaks
                if (FileList != null)
                    FileList.PropertyChanged -= OnFileListPropertyChanged;

                if (Status != null)
                    Status.PropertyChanged -= OnStatusPropertyChanged;

                // Dispose handlers and other resources
                _virusTotalHandler?.Dispose();
                _virusTotalClient?.Dispose();
                FileList?.Dispose();

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