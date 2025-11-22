// MainWindow.xaml.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input; // For ICommand
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Net.Http.Json;
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System.Security.Cryptography;
using System.Reflection; // For AppContext.BaseDirectory
using System.Security.Principal; // For WindowsIdentity, WindowsPrincipal

// Uncommon or special-case
// using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrayNotify; // This line is likely incorrect and removed


namespace PackItPro
{
    // RelayCommand for ICommand binding
    public class RelayCommand : ICommand
    {
        private readonly Action<object?> _execute;
        private readonly Func<object?, bool>? _canExecute;

        public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public event EventHandler? CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
        public void Execute(object? parameter) => _execute(parameter);
    }


    public partial class MainWindow : Window, IDisposable
    {
        #region Fields and Initialization
        private readonly ConcurrentDictionary<string, VirusScanResult> _scanCache = new();
        // TODO: Consider moving these to a dedicated settings/config class
        private readonly string _appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PackItPro");
        private readonly string _settingsFilePath;
        private readonly string _cacheFilePath;
        private readonly SemaphoreSlim _scanSemaphore = new(4);
        private readonly HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
        ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
        ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf"
        };

        private AppSettings _settings = new();
        private ObservableCollection<FileItem> _fileItems = new();
        private HttpClient _httpClient = new(); // TODO: Consider using IHttpClientFactory or a singleton pattern for better lifecycle management

        // NEW: Instance of the VirusTotalClient
        private VirusTotalClient? _virusTotalClient;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            FileListView.ItemsSource = _fileItems;

            // Initialize paths in AppData
            _settingsFilePath = Path.Combine(_appDataDir, "settings.json");
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");
            // Ensure directory exists
            if (!Directory.Exists(_appDataDir))
            {
                Directory.CreateDirectory(_appDataDir);
            }
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // NEW: Initialize VirusTotalClient FIRST, before loading settings/cache
                // This allows LoadSettingsAndCacheAsync to use the client instance for loading cache.
                _virusTotalClient = new VirusTotalClient(_cacheFilePath, apiKey: null); // Initialize with a dummy key or null, set it after loading settings

                await LoadSettingsAndCacheAsync(); // This will now correctly load the cache using the client instance

                // NEW: Apply the loaded API key to the client instance
                _virusTotalClient?.SetApiKey(_settings.VirusTotalApiKey);

                // NEW: Sync loaded settings to UI elements (after client is initialized and settings are loaded)
                SyncSettingsToUI();

                UpdateUIState();
            }
            catch (Exception ex)
            {
                LogError("Initialization failed", ex);
                MessageBox.Show($"Failed to initialize: {ex.Message}", "Startup Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region File Management
        private void AddFilesWithValidation(string[] paths)
        {
            var validFiles = paths
                .Where(p => File.Exists(p))
                .Select(p => new FileInfo(p))
                .Where(fi =>
                {
                    if (fi.Length == 0)
                    {
                        MessageBox.Show($"Skipped zero-byte file: {fi.Name}",
                            "Invalid File", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    // NEW: Check file extension against allowed list
                    if (_settings.OnlyScanExecutables && !_executableExtensions.Contains(fi.Extension))
                    {
                        MessageBox.Show($"Skipped non-executable file (or unsupported type): {fi.Name}",
                            "File Type Not Allowed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    return true;
                })
                .Select(fi => fi.FullName)
                .Take(20 - _fileItems.Count)
                .ToList();

            foreach (var file in validFiles)
            {
                var fileInfo = new FileInfo(file);
                var fileItem = new FileItem
                {
                    FileName = Path.GetFileName(file),
                    FilePath = file,
                    Size = FormatBytes(fileInfo.Length),
                    Status = "Pending Scan",
                    StatusColor = (SolidColorBrush)FindResource("AppStatusPendingColor"),
                    // RemoveCommand will be set after initialization
                };
                // NEW: Set the command after the object is initialized to avoid the closure issue
                fileItem.RemoveCommand = new RelayCommand((param) => RemoveFile(fileItem));
                _fileItems.Add(fileItem);
            }

            if (paths.Length > validFiles.Count)
            {
                MessageBox.Show($"Added {validFiles.Count} files (limit reached or invalid files skipped)",
                    "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            UpdateUIState();
        }

        private void RemoveFile(FileItem fileItem)
        {
            _fileItems.Remove(fileItem);
            UpdateUIState();
        }

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int suffixIndex = 0;
            double size = bytes;

            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }

            return $"{size:0.##} {suffixes[suffixIndex]}";
        }
        #endregion

        #region VirusTotal Integration (Refactored Call)
        private async Task ScanFilesWithVirusTotal()
        {
            // NEW: Use the VirusTotalClient instance
            if (_virusTotalClient == null)
            {
                LogError("VirusTotalClient not initialized", new InvalidOperationException("VirusTotalClient is null"));
                MessageBox.Show("VirusTotal client is not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrEmpty(_settings.VirusTotalApiKey))
            {
                MessageBox.Show("VirusTotal API key is required for scanning. Please set it in Settings.",
                    "Configuration Required", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // NEW: Ensure API key is set in the client (should already be done on load, but re-set if key changed recently)
            _virusTotalClient.SetApiKey(_settings.VirusTotalApiKey);

            StatusMessageTextBlock.Text = "Scanning files with VirusTotal...";
            ProcessProgressBar.Value = 0;
            ProgressPercentTextBlock.Text = "0%";

            var filesToRemove = new List<FileItem>();
            int totalFiles = _fileItems.Count;
            int processed = 0;

            foreach (var item in _fileItems)
            {
                try
                {
                    if (_settings.OnlyScanExecutables &&
                        !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                    {
                        item.Status = "Skipped Scan";
                        item.StatusColor = (SolidColorBrush)FindResource("AppTextTertiaryColor");
                        continue;
                    }

                    // NEW: Use the client to scan the file
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        _settings.VirusTotalApiKey, // Pass API key explicitly if needed, or let client manage it
                        _settings.OnlyScanExecutables,
                        _settings.MinimumDetectionsToFlag
                    );

                    // NEW: Apply result to the item
                    item.IsInfected = result.IsInfected; // Assuming VirusTotalClient calculates this
                    item.Status = item.IsInfected ?
                        $"Infected ({result.Positives}/{result.TotalScans})" :
                        "Clean";
                    item.StatusColor = item.IsInfected ? (SolidColorBrush)FindResource("AppStatusErrorColor") : (SolidColorBrush)FindResource("AppStatusCleanColor");

                    if (item.IsInfected && _settings.AutoRemoveInfectedFiles)
                        filesToRemove.Add(item);
                }
                catch (Exception ex)
                {
                    LogError($"Scan failed for {item.FileName}", ex);
                    item.Status = "Scan Failed";
                    item.StatusColor = (SolidColorBrush)FindResource("AppStatusWarningColor");
                }
                finally
                {
                    processed++;
                    UpdateProgress(processed, totalFiles, "Scanning");
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
                        _fileItems.Remove(infectedFile);
                }
            }

            UpdateUIState();
            StatusMessageTextBlock.Text = "Scan completed";
            // NEW: Save the updated cache via the client
            if (_virusTotalClient != null)
            {
                await _virusTotalClient.SaveCacheAsync();
            }
        }

        // REMOVED: QueryVirusTotal method (moved to VirusTotalClient)
        // REMOVED: ComputeSHA256 method (likely used by VirusTotalClient or Packager) - KEEP IF NEEDED ELSEWHERE, MOVE TO UTILS OTHERWISE
        #endregion

        #region Packaging Implementation (Refactored Call)
        private async void PackNow_Click(object sender, RoutedEventArgs e)
        {
            // Validate output filename ends with .packitexe
            string outputFileName = OutputFileNameTextBox.Text;
            if (string.IsNullOrEmpty(outputFileName))
            {
                outputFileName = $"Package_{DateTime.Now:yyyyMMdd_HHmmss}.packitexe";
            }
            else if (!outputFileName.EndsWith(".packitexe", StringComparison.OrdinalIgnoreCase))
            {
                outputFileName += ".packitexe";
            }

            var saveDialog = new SaveFileDialog
            {
                Filter = "PackItPro Executable (.packitexe)|*.packitexe",
                InitialDirectory = _settings.OutputLocation,
                FileName = outputFileName
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    Dispatcher.Invoke(() => PackButton.IsEnabled = false);
                    StatusMessageTextBlock.Text = "Creating .packitexe package...";
                    ProcessProgressBar.Value = 0;
                    ProgressPercentTextBlock.Text = "0%";

                    // NEW: Call the Packager class
                    // NEW: Pass admin requirement based on UI/Settings (example: reading the checkbox directly here, or use _settings.RequiresAdmin if bound correctly)
                    bool requiresAdmin = RequireAdminCheckBox.IsChecked == true; // Or _settings.RequiresAdmin if properly bound
                    var outputPath = await Packager.CreatePackageAsync(
                        _fileItems.Select(f => f.FilePath).ToList(),
                        _settings.OutputLocation,
                        Path.GetFileNameWithoutExtension(saveDialog.FileName),
                        requiresAdmin: requiresAdmin, // Use the value from the checkbox or settings
                        useLZMACompression: _settings.UseLZMACompression // <-- Added missing argument, relies on UI updating _settings
                    );

                    MessageBox.Show($"Package created successfully!\n{outputPath}",
                                  "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    // NEW: Log packaging error
                    LogError("Packager.CreatePackageAsync failed", ex);
                    MessageBox.Show($"Packaging failed: {ex.Message}",
                                  "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    ResetProgress();
                    PackButton.IsEnabled = true;
                }
            }
        }

        // REMOVED: Logic for creating payload.zip, calculating hash, embedding into stub (moved to Packager, ManifestGenerator, ResourceInjector)
        #endregion

        #region UI Management
        private void UpdateUIState()
        {
            Dispatcher.Invoke(() =>
            {
                PackButton.IsEnabled = _fileItems.Any();
                EmptyDropState.Visibility = _fileItems.Any() ? Visibility.Collapsed : Visibility.Visible;
                FileListView.Visibility = _fileItems.Any() ? Visibility.Visible : Visibility.Collapsed;
                UpdateSummary();
            });
        }

        private void UpdateSummary()
        {
            var totalSize = _fileItems.Sum(f => new FileInfo(f.FilePath).Length);
            FileCountTextBlock.Text = _fileItems.Count.ToString();
            TotalSizeTextBlock.Text = FormatBytes(totalSize);

            // Count clean files - Logic remains, but UI update is skipped if SafeFilesTextBlock is missing
            int cleanCount = _fileItems.Count(f => !f.IsInfected && f.Status != "Skipped Scan" && f.Status != "Scan Failed");
            int infectedCount = _fileItems.Count(f => f.IsInfected);

            // NEW: Check if SafeFilesTextBlock exists before trying to update it (Fixes error)
            if (SafeFilesTextBlock != null) // Assuming SafeFilesTextBlock exists in XAML
            {
                SafeFilesTextBlock.Text = cleanCount.ToString();
            }
            else
            {
                LogInfo($"UpdateSummary: Total Files = {_fileItems.Count}, Clean Files = {cleanCount}, Infected Files = {infectedCount}"); // Optional: Log for debugging if UI element is missing
            }

            StatusTextBlock.Text = _fileItems.Any(f => f.IsInfected) ?
                "Infected Files Detected" : "Ready";
            StatusTextBlock.Foreground = _fileItems.Any(f => f.IsInfected)
                    ? (SolidColorBrush)FindResource("AppStatusErrorColor")
                    : (SolidColorBrush)FindResource("AppStatusCleanColor");
        }

        // Updated UpdateProgress to accept operation type
        private void UpdateProgress(int processed, int total, string operationType)
        {
            Dispatcher.Invoke(() =>
            {
                var percentage = (double)processed / total * 100;
                var animation = new DoubleAnimation(
                    ProcessProgressBar.Value,
                    percentage,
                    new Duration(TimeSpan.FromMilliseconds(300)));
                ProcessProgressBar.BeginAnimation(ProgressBar.ValueProperty, animation);
                ProgressPercentTextBlock.Text = $"{(int)percentage}% ({operationType})"; // Add operation type label
            });
        }

        private void ResetProgress()
        {
            Dispatcher.Invoke(() =>
            {
                ProcessProgressBar.Value = 0;
                ProgressPercentTextBlock.Text = "0%";
                StatusMessageTextBlock.Text = "Ready to create .packitexe package";
            });
        }
        #endregion

        #region Event Handlers
        private void DropArea_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                // Safe brush retrieval with fallback
                var hoverBrush = TryFindResource("AppDropAreaHoverColor") as SolidColorBrush
                                 ?? new SolidColorBrush(Colors.LightBlue);

                DropAreaBorder.BorderBrush = hoverBrush;

                var color = hoverBrush.Color;
                DropAreaBorder.Background = new SolidColorBrush(Color.FromArgb(30, color.R, color.G, color.B)); // Use R, G, B from named color
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }

            e.Handled = true;
        }

        private void DropArea_DragLeave(object sender, DragEventArgs e)
        {
            // Safe brush retrieval with fallback
            var defaultBorderBrush = TryFindResource("AppBorderColor") as SolidColorBrush
                                     ?? new SolidColorBrush(Colors.Gray);
            var defaultBackgroundBrush = TryFindResource("AppPanelColor") as SolidColorBrush
                                         ?? new SolidColorBrush(Colors.Black);

            DropAreaBorder.BorderBrush = defaultBorderBrush;
            DropAreaBorder.Background = defaultBackgroundBrush;
            e.Handled = true;
        }

        private void DropArea_Drop(object sender, DragEventArgs e)
        {
            DropArea_DragLeave(sender, e);
            if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
            {
                AddFilesWithValidation(files);
                if (IncludeWingetUpdaterCheckBox.IsChecked == true) // NEW: Changed from ScanWithVirusTotalCheckBox
                    _ = ScanFilesWithVirusTotal();
            }
        }

        private void BrowseFiles_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Multiselect = true,
                Title = "Select Files to Pack"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                AddFilesWithValidation(openFileDialog.FileNames);
                if (IncludeWingetUpdaterCheckBox.IsChecked == true) // NEW: Changed from ScanWithVirusTotalCheckBox
                    _ = ScanFilesWithVirusTotal();
            }
        }

        // RemoveFile_Click is no longer used due to ICommand binding
        // private void RemoveFile_Click(object sender, RoutedEventArgs e) { ... }

        private void ClearAllFiles_Click(object sender, RoutedEventArgs e)
        {
            _fileItems.Clear();
            UpdateUIState();
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void SetOutputLocation_Click(object sender, RoutedEventArgs e)
        {
            var folderDialog = new CommonOpenFileDialog
            {
                IsFolderPicker = true,
                Title = "Select Output Folder",
                InitialDirectory = _settings.OutputLocation,
                EnsurePathExists = true // Critical: Ensure selected path exists
            };

            if (folderDialog.ShowDialog() == CommonFileDialogResult.Ok)
            {
                try
                {
                    // Verify write permissions before saving
                    var testFile = Path.Combine(folderDialog.FileName, "permission_test.tmp");
                    File.WriteAllText(testFile, "test");
                    File.Delete(testFile);

                    _settings.OutputLocation = folderDialog.FileName;
                    SaveSettings();
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

        private void SetVirusApiKey_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new InputDialog(
                "VirusTotal API Key",
                "Enter your VirusTotal API key (64 characters):",
                _settings.VirusTotalApiKey
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

                _settings.VirusTotalApiKey = cleanedKey;
                // NEW: Update the client's API key if it exists
                if (_virusTotalClient != null)
                {
                    _virusTotalClient.SetApiKey(cleanedKey);
                }
                SaveSettings();
                MessageBox.Show("API key updated successfully!",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // NEW: Add the missing PackItProSettings_Click method
        private void PackItProSettings_Click(object sender, RoutedEventArgs e)
        {
            // You can add a more detailed settings dialog here if needed
            // For now, just show a message about the current settings
            var settingsInfo = new StringBuilder();
            settingsInfo.AppendLine("Current PackItPro Settings:");
            settingsInfo.AppendLine($"- Output Location: {_settings.OutputLocation}");
            settingsInfo.AppendLine($"- VirusTotal API Key Set: {!string.IsNullOrEmpty(_settings.VirusTotalApiKey)}");
            settingsInfo.AppendLine($"- Only Scan Executables: {_settings.OnlyScanExecutables}");
            settingsInfo.AppendLine($"- Auto Remove Infected: {_settings.AutoRemoveInfectedFiles}");
            // NEW: Added Winget setting
            settingsInfo.AppendLine($"- Include Winget Update Script: {_settings.IncludeWingetUpdateScript}");
            // NEW: Added LZMA setting
            settingsInfo.AppendLine($"- Use LZMA Compression: {_settings.UseLZMACompression}");
            // NEW: Added RequiresAdmin setting
            settingsInfo.AppendLine($"- Requires Admin: {_settings.RequiresAdmin}");

            MessageBox.Show(settingsInfo.ToString(), "PackItPro Settings", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("PackItPro v1.0\n\nA secure file packaging tool designed to bundle executable files into a single installer package with malware scanning capability.",
                "About PackItPro", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        #endregion

        #region Settings Synchronization (NEW)
        // NEW: Method to sync settings object values to UI controls (Handles potentially missing XAML elements)
        private void SyncSettingsToUI()
        {
            // Check if UI elements exist before setting their properties
            if (RequireAdminCheckBox != null) RequireAdminCheckBox.IsChecked = _settings.RequiresAdmin;
            if (IncludeWingetUpdaterCheckBox != null) IncludeWingetUpdaterCheckBox.IsChecked = _settings.IncludeWingetUpdateScript;
            // NEW: Handle potentially missing checkboxes gracefully
            if (UseLZMACompressionCheckBox != null) UseLZMACompressionCheckBox.IsChecked = _settings.UseLZMACompression;
            if (OnlyScanExecutablesCheckBox != null) OnlyScanExecutablesCheckBox.IsChecked = _settings.OnlyScanExecutables;
            if (AutoRemoveInfectedFilesCheckBox != null) AutoRemoveInfectedFilesCheckBox.IsChecked = _settings.AutoRemoveInfectedFiles;
            // Add other settings syncs here as needed, checking for null UI elements
        }

        // NEW: Event handlers for each checkbox to update the settings object and save (Handles potentially missing XAML elements)
        private void RequireAdminCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == true) // Check if sender is CheckBox and is checked
            {
                _settings.RequiresAdmin = true;
                SaveSettings(); // Save settings immediately when changed
            }
        }

        private void RequireAdminCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == false) // Check if sender is CheckBox and is unchecked
            {
                _settings.RequiresAdmin = false;
                SaveSettings(); // Save settings immediately when changed
            }
        }

        private void IncludeWingetUpdaterCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == true)
            {
                _settings.IncludeWingetUpdateScript = true;
                SaveSettings();
            }
        }

        private void IncludeWingetUpdaterCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == false)
            {
                _settings.IncludeWingetUpdateScript = false;
                SaveSettings();
            }
        }

        // NEW: Handle potentially missing checkboxes gracefully
        private void UseLZMACompressionCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == true)
            {
                _settings.UseLZMACompression = true;
                SaveSettings();
            }
        }

        private void UseLZMACompressionCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == false)
            {
                _settings.UseLZMACompression = false;
                SaveSettings();
            }
        }

        private void OnlyScanExecutablesCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == true)
            {
                _settings.OnlyScanExecutables = true;
                SaveSettings();
            }
        }

        private void OnlyScanExecutablesCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == false)
            {
                _settings.OnlyScanExecutables = false;
                SaveSettings();
            }
        }

        private void AutoRemoveInfectedFilesCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == true)
            {
                _settings.AutoRemoveInfectedFiles = true;
                SaveSettings();
            }
        }

        private void AutoRemoveInfectedFilesCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox cb && cb.IsChecked == false)
            {
                _settings.AutoRemoveInfectedFiles = false;
                SaveSettings();
            }
        }

        // Add other checkbox event handlers similarly...
        #endregion

        #region Missing Event Handlers (NEW)
        // NEW: Placeholder methods for event handlers referenced in XAML but missing in code-behind
        // These prevent the build errors. You can implement the actual logic later.

        private void ExportLogs_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to export logs
            // For now, just show a message
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

        private void ViewCache_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to view the scan cache (e.g., show a list of cached hashes and results in a new window)
            // For now, just show a message with the cache path
            MessageBox.Show($"VirusTotal scan cache is located at:\n{_cacheFilePath}\n\nYou can open this file to view cached scan results.", "View Cache", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ClearCache_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to clear the scan cache
            // For now, just confirm and clear the dictionary
            var result = MessageBox.Show(
                "Are you sure you want to clear the VirusTotal scan cache? This will force rescan of all files.",
                "Clear Cache",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                _scanCache.Clear();
                _virusTotalClient?.ClearCache(); // Also clear the client's in-memory cache if it exists
                // Optionally delete the cache file on disk
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

        private void TestPackage_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to test the generated package (e.g., run it in a sandboxed environment if possible)
            // For now, just show a message
            MessageBox.Show("Package testing functionality is not yet implemented.", "Not Implemented", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExportList_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to export the list of added files (e.g., as a text file)
            // For now, just show a message
            var sb = new StringBuilder();
            sb.AppendLine("Files in current package:");
            foreach (var item in _fileItems)
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

        private void Documentation_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to open documentation (e.g., a web page or a local PDF/HTML file)
            // For now, just show a message
            MessageBox.Show("Opening documentation...", "Documentation", MessageBoxButton.OK, MessageBoxImage.Information);
            // Process.Start(new ProcessStartInfo("https://your-documentation-url.com") { UseShellExecute = true }); // Example
        }

        private void GitHub_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to open the GitHub repository
            // For now, just show a message
            MessageBox.Show("Opening GitHub repository...", "GitHub", MessageBoxButton.OK, MessageBoxImage.Information);
            // Process.Start(new ProcessStartInfo("https://github.com/your-username/your-repo") { UseShellExecute = true }); // Example
        }

        private void ReportIssue_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to report an issue (e.g., open GitHub Issues page or an email client)
            // For now, just show a message
            MessageBox.Show("Opening issue reporting page...", "Report Issue", MessageBoxButton.OK, MessageBoxImage.Information);
            // Process.Start(new ProcessStartInfo("https://github.com/your-username/your-repo/issues/new") { UseShellExecute = true }); // Example
        }

        private void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to check for updates
            // For now, just show a message
            MessageBox.Show("Checking for updates...", "Check Updates", MessageBoxButton.OK, MessageBoxImage.Information);
            // Simulate update check
            // await Task.Delay(2000); // Simulate network call
            // MessageBox.Show("You are running the latest version.", "No Updates", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Retry_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to retry a failed operation (e.g., retry scan if a scan failed)
            // For now, just show a message
            MessageBox.Show("Retrying last operation...", "Retry", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void DismissError_Click(object sender, RoutedEventArgs e)
        {
            // Implement logic to dismiss an error message or clear the error state
            // For now, just clear the status message
            StatusMessageTextBlock.Text = "Ready to create .packitexe package";
            ProcessingProgressBar.Visibility = Visibility.Collapsed; // Hide the inline progress bar if it was shown for an error
        }
        #endregion

        #region Settings and Cache Management
        private async Task LoadSettingsAndCacheAsync()
        {
            try
            {
                if (File.Exists(_settingsFilePath)) // Use new path
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath);
                    _settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }

                // NEW: Load VirusTotal cache using the client instance that was created before this call
                if (_virusTotalClient != null)
                {
                    await _virusTotalClient.LoadCacheAsync();
                }
            }
            catch (Exception ex)
            {
                LogError("Settings load failed", ex);
                _settings = new AppSettings();
                // Optionally clear the client's cache if loading failed
                if (_virusTotalClient != null)
                {
                    _virusTotalClient.ClearCache();
                }
            }
        }

        private void SaveSettings()
        {
            try
            {
                // Ensure directory exists before saving
                var dirPath = Path.GetDirectoryName(_settingsFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                {
                    Directory.CreateDirectory(dirPath);
                }

                File.WriteAllText(_settingsFilePath, // Use new path
                    JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                LogError("Failed to save settings", ex);
            }
        }

        // REMOVED: SaveVirusScanCache method (now handled by VirusTotalClient)
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
                    // NEW: Dispose the VirusTotalClient
                    _virusTotalClient?.Dispose();
                }

                // TODO: Free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: Set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: Override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~MainWindow() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: Uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }

    #region Model Classes
    public class FileItem : INotifyPropertyChanged
    {
        private string _fileName = string.Empty;
        private string _filePath = string.Empty;
        private string _size = "0 KB";
        private string _status = "Pending";
        private SolidColorBrush _statusColor = Brushes.Gray; // Will be set via code
        private bool _isInfected;

        // ICommand for remove button
        public ICommand RemoveCommand { get; set; } = null!; // Initialized in AddFilesWithValidation

        public string FileName
        {
            get => _fileName;
            set { _fileName = value; OnPropertyChanged(); }
        }

        public string FilePath
        {
            get => _filePath;
            set { _filePath = value; OnPropertyChanged(); }
        }

        public string Size
        {
            get => _size;
            set { _size = value; OnPropertyChanged(); }
        }

        public string Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); }
        }

        public SolidColorBrush StatusColor
        {
            get => _statusColor;
            set { _statusColor = value; OnPropertyChanged(); }
        }

        public bool IsInfected
        {
            get => _isInfected;
            set { _isInfected = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    // REMOVED: VirusScanResult, VirusTotalFileReport, VirusTotalFileData, etc. (Moved to VirusTotalClient or kept if used elsewhere)
    #endregion

    #region Helper Classes
    public class InputDialog : Window
    {
        public string Answer { get; private set; } = string.Empty; // Initialize to non-null

        public InputDialog(string title, string question, string defaultAnswer = "")
        {
            Title = title;
            Width = 400;
            Height = 150;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            Background = (SolidColorBrush)Application.Current.FindResource("AppBackgroundColor");

            var grid = new Grid { Margin = new Thickness(10) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var questionText = new TextBlock
            {
                Text = question,
                Margin = new Thickness(0, 0, 0, 10),
                Foreground = (SolidColorBrush)Application.Current.FindResource("AppTextColor")
            };
            grid.Children.Add(questionText);
            Grid.SetRow(questionText, 0);

            var answerBox = new TextBox
            {
                Text = defaultAnswer,
                Margin = new Thickness(0, 0, 0, 15),
                Background = (SolidColorBrush)Application.Current.FindResource("AppBackgroundColor"),
                Foreground = (SolidColorBrush)Application.Current.FindResource("AppTextColor"),
                BorderBrush = (SolidColorBrush)Application.Current.FindResource("AppBorderColor"),
                Padding = new Thickness(8, 5, 8, 5)
            };
            grid.Children.Add(answerBox);
            Grid.SetRow(answerBox, 1);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var style = new Style(typeof(Button))
            {
                Setters = {
                new Setter(Button.BackgroundProperty, (SolidColorBrush)Application.Current.FindResource("AppPrimaryColor")),
                new Setter(Button.ForegroundProperty, (SolidColorBrush)Application.Current.FindResource("AppTextColor")),
                new Setter(Button.BorderThicknessProperty, new Thickness(0)),
                new Setter(Button.PaddingProperty, new Thickness(15, 8, 15, 8)),
                new Setter(Button.MarginProperty, new Thickness(5, 0, 0, 0))
            }
            };

            var okButton = new Button
            {
                Content = "OK",
                IsDefault = true,
                Style = style
            };
            okButton.Click += (s, e) => {
                Answer = answerBox.Text;
                DialogResult = true;
            };

            var cancelButton = new Button
            {
                Content = "Cancel",
                IsCancel = true,
                Style = style
            };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            grid.Children.Add(buttonPanel);
            Grid.SetRow(buttonPanel, 2);

            Content = grid;
            answerBox.Focus();
        }
    }
    #endregion

}