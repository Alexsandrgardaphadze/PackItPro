#nullable enable
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
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace PackItPro
{
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

    public class AppSettings
    {
        public string OutputLocation { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public string VirusTotalApiKey { get; set; } = "";
        public bool OnlyScanExecutables { get; set; } = true;
        public bool AutoRemoveInfectedFiles { get; set; } = true;
        public int MinimumDetectionsToFlag { get; set; } = 1;
        public bool IncludeWingetUpdateScript { get; set; } = false;
    }

    public partial class MainWindow : Window, IDisposable
    {
        #region Fields and Initialization
        private readonly ConcurrentDictionary<string, VirusScanResult> _scanCache = new();
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
        private HttpClient _httpClient = new();
        private readonly SemaphoreSlim _rateLimitSemaphore = new(4, 4);
        private VirusTotalScanner? _virusTotalScanner;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            FileListView.ItemsSource = _fileItems;

            _settingsFilePath = Path.Combine(_appDataDir, "settings.json");
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");

            if (!Directory.Exists(_appDataDir))
            {
                Directory.CreateDirectory(_appDataDir);
            }
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await LoadSettingsAndCacheAsync();
                _virusTotalScanner = new VirusTotalScanner(_settings.VirusTotalApiKey, _scanCache);
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
                .Where(p => File.Exists(p)) // file exists
                .Select(p => new FileInfo(p))
                .Where(fi =>
                {
                    // Skip zero-byte files
                    if (fi.Length == 0)
                    {
                        MessageBox.Show($"Skipped zero-byte file: {fi.Name}",
                            "Invalid File", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    // Skip files larger than 4 GB
                    if (fi.Length > 4L * 1024 * 1024 * 1024)
                    {
                        MessageBox.Show($"Skipped file over 4 GB: {fi.Name}",
                            "File Too Large", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    // Skip non-executables if setting is enabled
                    if (_settings.OnlyScanExecutables && !_executableExtensions.Contains(fi.Extension))
                    {
                        MessageBox.Show($"Skipped non-executable file: {fi.Name}",
                            "File Type Not Allowed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    // Skip duplicates
                    if (_fileItems.Any(item => string.Equals(item.FilePath, fi.FullName, StringComparison.OrdinalIgnoreCase)))
                    {
                        MessageBox.Show($"Skipped duplicate file: {fi.Name}",
                            "Duplicate File", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    return true;
                })
                .Select(fi => fi.FullName)
                .Take(20 - _fileItems.Count) // respect max 20 files
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
                    StatusColor = TryFindResource("AppStatusPendingColor") as SolidColorBrush
                                  ?? new SolidColorBrush(Colors.Gray)
                };
                fileItem.RemoveCommand = new RelayCommand((param) => RemoveFile(fileItem));
                _fileItems.Add(fileItem);
            }

            if (paths.Length > validFiles.Count)
            {
                MessageBox.Show($"Added {validFiles.Count} files (limit reached, duplicates or invalid files skipped)",
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

        #region VirusTotal Integration
        private async Task ScanFilesWithVirusTotal()
        {
            if (string.IsNullOrEmpty(_settings.VirusTotalApiKey))
            {
                MessageBox.Show("VirusTotal API key is required for scanning. Please set it in Settings.",
                    "Configuration Required", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (_virusTotalScanner == null)
            {
                _virusTotalScanner = new VirusTotalScanner(_settings.VirusTotalApiKey, _scanCache);
            }

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

                    await _scanSemaphore.WaitAsync();
                    try
                    {
                        var result = await _virusTotalScanner.ScanFileAsync(item.FilePath);
                        ApplyScanResult(item, result);

                        if (item.IsInfected && _settings.AutoRemoveInfectedFiles)
                            filesToRemove.Add(item);
                    }
                    finally
                    {
                        _scanSemaphore.Release();
                    }
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
            SaveVirusScanCache();
        }

        private VirusScanResult ApplyScanResult(FileItem item, VirusScanResult result)
        {
            item.IsInfected = result.Positives >= _settings.MinimumDetectionsToFlag;
            item.Status = item.IsInfected ?
                $"Infected ({result.Positives}/{result.TotalScans})" :
                "Clean";
            item.StatusColor = item.IsInfected ?
                (SolidColorBrush)FindResource("AppStatusErrorColor") :
                (SolidColorBrush)FindResource("AppStatusCleanColor");
            return result;
        }
        #endregion

        #region Packaging Implementation
        private async void PackNow_Click(object sender, RoutedEventArgs e)
        {
            string outputFileName = OutputFileNameTextBox.Text;
            if (string.IsNullOrEmpty(outputFileName))
                outputFileName = $"Package_{DateTime.Now:yyyyMMdd_HHmmss}";

            if (!outputFileName.EndsWith(".packitexe", StringComparison.OrdinalIgnoreCase))
                outputFileName += ".packitexe";

            try
            {
                PackButton.IsEnabled = false;
                StatusMessageTextBlock.Text = "Creating .packitexe package...";
                ProcessProgressBar.Value = 0;
                ProgressPercentTextBlock.Text = "0%";

                var outputPath = await Packager.CreatePackageAsync(
                    _fileItems.Select(f => f.FilePath).ToList(),
                    _settings.OutputLocation,
                    Path.GetFileNameWithoutExtension(outputFileName),
                    requiresAdmin: false
                );

                MessageBox.Show($"Package created successfully!\n{outputPath}",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                LogError("Packaging failed", ex);
                MessageBox.Show($"Packaging failed: {ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ResetProgress();
                PackButton.IsEnabled = true;
            }
        }
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

            bool hasInfected = _fileItems.Any(f => f.IsInfected);
            StatusTextBlock.Text = hasInfected ? "Infected Files Detected" : "Ready";

            // Safely get the brushes from resources
            var errorBrush = FindResource("AppStatusErrorColor") as SolidColorBrush;
            var cleanBrush = FindResource("AppStatusCleanColor") as SolidColorBrush;

            // Fallback in case the resource isn't found
            if (errorBrush == null) errorBrush = new SolidColorBrush(Colors.Red);
            if (cleanBrush == null) cleanBrush = new SolidColorBrush(Colors.Green);

            StatusTextBlock.Foreground = hasInfected ? errorBrush : cleanBrush;
        }


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
                ProgressPercentTextBlock.Text = $"{(int)percentage}% ({operationType})";
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
                DropAreaBorder.Background = new SolidColorBrush(Color.FromArgb(30, color.R, color.G, color.B));
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }

            e.Handled = true;
        }


        private void DropArea_DragLeave(object sender, DragEventArgs e)
        {
            DropAreaBorder.BorderBrush = (SolidColorBrush)FindResource("AppBorderColor");
            DropAreaBorder.Background = (SolidColorBrush)FindResource("AppPanelColor");
            e.Handled = true;
        }

        private void DropArea_Drop(object sender, DragEventArgs e)
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Handled = true;
                return;
            }

            var droppedPaths = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (droppedPaths == null || droppedPaths.Length == 0)
            {
                e.Handled = true;
                return;
            }

            try
            {
                AddFilesWithValidation(droppedPaths);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error processing dropped files:\n{ex.Message}",
                                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                // Reset hover styling
                var defaultBorderBrush = TryFindResource("AppDropAreaBorderColor") as SolidColorBrush
                                         ?? new SolidColorBrush(Colors.Gray);
                DropAreaBorder.BorderBrush = defaultBorderBrush;
                DropAreaBorder.Background = new SolidColorBrush(Colors.Transparent);
                e.Handled = true;
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
                if (ScanWithVirusTotalCheckBox.IsChecked == true)
                    _ = ScanFilesWithVirusTotal();
            }
        }

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
            var folderDialog = new System.Windows.Forms.FolderBrowserDialog
            {
                SelectedPath = _settings.OutputLocation,
                Description = "Select output folder for .packitexe files"
            };

            if (folderDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                _settings.OutputLocation = folderDialog.SelectedPath;
                SaveSettings();
                MessageBox.Show("Output location updated!", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
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
                _virusTotalScanner = new VirusTotalScanner(_settings.VirusTotalApiKey, _scanCache);
                SaveSettings();
                MessageBox.Show("API key updated successfully!",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("PackItPro v0.2.0\n\nA secure file packaging tool with VirusTotal scanning.",
                "About PackItPro", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        #endregion

        #region Settings and Cache Management
        private async Task LoadSettingsAndCacheAsync()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath);
                    _settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }

                if (File.Exists(_cacheFilePath))
                {
                    var cacheJson = await File.ReadAllTextAsync(_cacheFilePath);
                    var cache = JsonSerializer.Deserialize<List<VirusScanResult>>(cacheJson);
                    if (cache != null)
                    {
                        foreach (var item in cache)
                        {
                            _scanCache[item.FileHash] = item;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Settings load failed", ex);
                _settings = new AppSettings();
            }
        }

        private void SaveSettings()
        {
            try
            {
                var dirPath = Path.GetDirectoryName(_settingsFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                {
                    Directory.CreateDirectory(dirPath);
                }

                File.WriteAllText(_settingsFilePath,
                    JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                LogError("Failed to save settings", ex);
            }
        }

        private void SaveVirusScanCache()
        {
            try
            {
                var dirPath = Path.GetDirectoryName(_cacheFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                {
                    Directory.CreateDirectory(dirPath);
                }

                File.WriteAllText(_cacheFilePath,
                    JsonSerializer.Serialize(_scanCache.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                LogError("Failed to save scan cache", ex);
            }
        }
        #endregion

        #region Error Handling
        private void LogError(string message, Exception ex)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:o}] {message}\n{ex}\n\n";
                var logPath = Path.Combine(_appDataDir, "packitpro.log");
                File.AppendAllText(logPath, logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { }
        }

        private void LogInfo(string message)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:o}] [INFO] {message}\n";
                var logPath = Path.Combine(_appDataDir, "packitpro.log");
                File.AppendAllText(logPath, logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { }
        }
        #endregion

        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _httpClient?.Dispose();
                    _scanSemaphore?.Dispose();
                    _rateLimitSemaphore?.Dispose();
                    _virusTotalScanner?.Dispose();
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
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
        private SolidColorBrush _statusColor = Brushes.Gray;
        private bool _isInfected;

        public ICommand RemoveCommand { get; set; } = null!;

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

    public class VirusScanResult
    {
        public string FileHash { get; set; } = string.Empty;
        public int Positives { get; set; }
        public int TotalScans { get; set; }
        public DateTime ScanDate { get; set; } = DateTime.UtcNow;
        public string? Error { get; set; }
    }
    #endregion

    #region Helper Classes
    public class InputDialog : Window
    {
        public string Answer { get; private set; } = string.Empty;

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