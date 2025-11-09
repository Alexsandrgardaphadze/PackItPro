// System namespaces
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

// WPF namespaces
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Media3D;
using System.Net.Http.Json;

// Third-party libraries
using ICSharpCode.SharpZipLib.Zip;
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;

// Needed for cryptographic hashing like SHA256
using System.Security.Cryptography;

// Uncommon or special-case
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrayNotify;


namespace PackItPro
{
    public class AppSettings
    {
        public string OutputLocation { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public string VirusTotalApiKey { get; set; } = "";
        public bool OnlyScanExecutables { get; set; } = true;
        public bool AutoRemoveInfectedFiles { get; set; } = true;
        public int MinimumDetectionsToFlag { get; set; } = 1;
    }



public partial class MainWindow : Window
    {
        #region Fields and Initialization
        private readonly ConcurrentDictionary<string, VirusScanResult> _scanCache = new();
        private readonly string _cacheFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "virusscancache.json");
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

        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            FileListView.ItemsSource = _fileItems;
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await LoadSettingsAndCacheAsync();
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

                    return true;
                })
                .Select(fi => fi.FullName)
                .Take(20 - _fileItems.Count)
                .ToList();

            foreach (var file in validFiles)
            {
                var fileInfo = new FileInfo(file);
                _fileItems.Add(new FileItem
                {
                    FileName = Path.GetFileName(file),
                    FilePath = file,
                    Size = FormatBytes(fileInfo.Length),
                    Status = "Pending Scan",
                    StatusColor = Brushes.Gray
                });
            }

            if (paths.Length > validFiles.Count)
            {
                MessageBox.Show($"Added {validFiles.Count} files (limit reached or invalid files skipped)",
                    "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }

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
                        item.StatusColor = Brushes.LightGray;
                        continue;
                    }

                    string hash = ComputeSHA256(item.FilePath);
                    VirusScanResult result;

                    if (_scanCache.TryGetValue(hash, out var cachedResult))
                    {
                        result = ApplyScanResult(item, cachedResult);
                    }
                    else
                    {
                        await _scanSemaphore.WaitAsync();
                        try
                        {
                            // Add delay every few files to respect API rate limits
                            if (_scanCache.Count % 4 == 0)
                                await Task.Delay(15000);

                            result = await QueryVirusTotal(item.FilePath, hash);
                            _scanCache[hash] = result;
                            ApplyScanResult(item, result);
                        }
                        finally
                        {
                            _scanSemaphore.Release();
                        }
                    }

                    if (item.IsInfected && _settings.AutoRemoveInfectedFiles)
                        filesToRemove.Add(item);
                }
                catch (Exception ex)
                {
                    LogError($"Scan failed for {item.FileName}", ex);
                    item.Status = "Scan Failed";
                    item.StatusColor = Brushes.Orange;
                }
                finally
                {
                    processed++;
                    UpdateProgress(processed, totalFiles);
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
            item.StatusColor = item.IsInfected ? Brushes.OrangeRed : Brushes.LimeGreen;
            return result;
        }

        private async Task<VirusScanResult> QueryVirusTotal(string filePath, string hash)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-apikey", _settings.VirusTotalApiKey);

                var reportResponse = await _httpClient.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hash}");

                if (reportResponse.IsSuccessStatusCode)
                {
                    var report = await reportResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>()
                    ?? throw new InvalidDataException("Invalid VirusTotal response");

                    if (report.Data?.Attributes?.LastAnalysisStats == null)
                        throw new InvalidDataException("Missing analysis data in VirusTotal response");
                    return new VirusScanResult
                    {
                        FileHash = hash,
                        Positives = report.Data.Attributes.LastAnalysisStats.Malicious,
                        TotalScans = report.Data.Attributes.LastAnalysisStats.Total,
                        ScanDate = DateTime.UtcNow
                    };
                }

                // File not previously scanned, upload it
                using var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                using var formData = new MultipartFormDataContent();
                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                var uploadResponse = await _httpClient.PostAsync(
                    "https://www.virustotal.com/api/v3/files", formData);
                uploadResponse.EnsureSuccessStatusCode();

                var analysisId = (await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>()).Data.Id;

                // Poll for results
                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(5000);
                    var analysisResponse = await _httpClient.GetAsync(
                        $"https://www.virustotal.com/api/v3/analyses/{analysisId}");

                    if (analysisResponse.IsSuccessStatusCode)
                    {
                        var analysis = await analysisResponse.Content.ReadFromJsonAsync<VirusTotalFileReport>();
                        return new VirusScanResult
                        {
                            FileHash = hash,
                            Positives = analysis.Data.Attributes.LastAnalysisStats.Malicious,
                            TotalScans = analysis.Data.Attributes.LastAnalysisStats.Total,
                            ScanDate = DateTime.UtcNow
                        };
                    }
                }

                throw new TimeoutException("VirusTotal analysis timed out");
            }
            catch (Exception ex)
            {
                LogError("VirusTotal query failed", ex);
                return new VirusScanResult
                {
                    FileHash = hash,
                    Positives = 0,
                    TotalScans = 0,
                    Error = ex.Message,
                    ScanDate = DateTime.UtcNow
                };
            }
        }

        private string ComputeSHA256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
        #endregion

        #region Packaging Implementation
        private async void PackNow_Click(object sender, RoutedEventArgs e)
        {
            if (OutputFormatComboBox.SelectedIndex == 1)
            {
                var stubPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
                if (!File.Exists(stubPath))
                {
                    MessageBox.Show("Stub installer not found. Please reinstall the application.",
                        "Missing Component", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }

            var saveDialog = new SaveFileDialog
            {
                Filter = OutputFormatComboBox.SelectedIndex == 0
                    ? "PackItPro Files (.pipack)|*.pipack"
                    : "Safe Executable (.safeexe)|*.safeexe",
                InitialDirectory = _settings.OutputLocation,
                FileName = string.IsNullOrEmpty(OutputFileNameTextBox.Text)
                    ? $"Package_{DateTime.Now:yyyyMMdd_HHmmss}"
                    : OutputFileNameTextBox.Text
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    Dispatcher.Invoke(() => PackButton.IsEnabled = false);
                    StatusMessageTextBlock.Text = "Creating package...";
                    bool isSafeExe = saveDialog.FileName.EndsWith(".safeexe");
                    byte[] signature = Encoding.UTF8.GetBytes("PIPACKv1");

                    using (var fs = new FileStream(saveDialog.FileName, FileMode.Create))
                    {
                        if (!isSafeExe)
                            await fs.WriteAsync(signature, 0, signature.Length);

                        using var zipStream = new ZipOutputStream(fs);
                        {
                            zipStream.SetLevel(9);
                            int totalFiles = _fileItems.Count;
                            int processed = 0;

                            foreach (var fileItem in _fileItems)
                            {
                                var entry = new ZipEntry(Path.GetFileName(fileItem.FilePath))
                                {
                                    DateTime = DateTime.Now,
                                    Size = new FileInfo(fileItem.FilePath).Length
                                };

                                zipStream.PutNextEntry(entry);
                                using var fileStream = File.OpenRead(fileItem.FilePath);
                                await fileStream.CopyToAsync(zipStream);
                                zipStream.CloseEntry();

                                processed++;
                                UpdateProgress(processed, totalFiles);
                            }
                        }
                    }

                    if (isSafeExe)
                    {
                        var stubPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
                        var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tmp");
                        try
                        {
                            // Use FileStream with FileShare.None to lock the file during operation
                            using (var stubStream = new FileStream(stubPath, FileMode.Open, FileAccess.Read, FileShare.None))
                            using (var tempStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                await stubStream.CopyToAsync(tempStream);
                            }

                            // Append package data to temp file
                            using (var tempStream = new FileStream(tempFile, FileMode.Append, FileAccess.Write, FileShare.None))
                            using (var packageStream = new FileStream(saveDialog.FileName, FileMode.Open, FileAccess.Read, FileShare.None))
                            {
                                await packageStream.CopyToAsync(tempStream);
                            }

                            // Atomic replacement
                            File.Replace(tempFile, saveDialog.FileName, null);
                        }
                        catch
                        {
                            if (File.Exists(tempFile))
                                File.Delete(tempFile);
                            throw;
                        }
                    }

                    MessageBox.Show($"Package created successfully!\n{saveDialog.FileName}",
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
            StatusTextBlock.Text = _fileItems.Any(f => f.IsInfected) ?
                "Infected Files Detected" : "Ready";
            StatusTextBlock.Foreground = _fileItems.Any(f => f.IsInfected)
                    ? Brushes.OrangeRed
                    : Brushes.LimeGreen;
        }

        private void UpdateProgress(int processed, int total)
        {
            Dispatcher.Invoke(() =>
            {
                var animation = new DoubleAnimation(
                    ProcessProgressBar.Value,
                    (double)processed / total * 100,
                    new Duration(TimeSpan.FromMilliseconds(300)));
                ProcessProgressBar.BeginAnimation(ProgressBar.ValueProperty, animation);
                ProgressPercentTextBlock.Text = $"{processed}/{total}";
            });
        }

        private void ResetProgress()
        {
            Dispatcher.Invoke(() =>
            {
                ProcessProgressBar.Value = 0;
                ProgressPercentTextBlock.Text = "0%";
                StatusMessageTextBlock.Text = "Ready to pack files";
            });
        }
        #endregion

        #region Event Handlers
        private void DropArea_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                DropAreaBorder.BorderBrush = new SolidColorBrush(Colors.DodgerBlue);
                DropAreaBorder.Background = new SolidColorBrush(Color.FromArgb(30, 30, 144, 255));
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void DropArea_DragLeave(object sender, DragEventArgs e)
        {
            DropAreaBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(63, 63, 90));
            DropAreaBorder.Background = new SolidColorBrush(Color.FromRgb(37, 37, 54));
            e.Handled = true;
        }

        private void DropArea_Drop(object sender, DragEventArgs e)
        {
            DropArea_DragLeave(sender, e);
            if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
            {
                AddFilesWithValidation(files);
                if (ScanWithVirusTotalCheckBox.IsChecked == true)
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
                if (ScanWithVirusTotalCheckBox.IsChecked == true)
                    _ = ScanFilesWithVirusTotal();
            }
        }

        private void RemoveFile_Click(object sender, RoutedEventArgs e)
        {
            if (((Button)sender).DataContext is FileItem fileItem)
            {
                _fileItems.Remove(fileItem);
                UpdateUIState();
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
                SaveSettings();
                MessageBox.Show("API key updated successfully!",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("PackItPro v1.0\n\nA secure file packaging tool designed to bundle executable files into a single installer package with malware scanning capability.",
                "About PackItPro", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        #endregion

        #region Settings and Cache Management
        private async Task LoadSettingsAndCacheAsync()
        {
            try
            {
                if (File.Exists("settings.json"))
                {
                    var json = await File.ReadAllTextAsync("settings.json");
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
                File.WriteAllText("settings.json",
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
                File.AppendAllText("packitpro.log", logEntry);
                Debug.WriteLine(logEntry);
            }
            catch { /* Ensure logging doesn't crash the app */ }
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

    public class VirusTotalFileReport
    {
        public VirusTotalFileData? Data { get; set; }
    }

    public class VirusTotalFileData
    {
        public string? Id { get; set; }
        public VirusTotalFileAttributes? Attributes { get; set; }
    }

    public class VirusTotalFileAttributes
    {
        public VirusTotalAnalysisStats? LastAnalysisStats { get; set; }
    }

    public class VirusTotalAnalysisStats
    {
        public int Malicious { get; set; }
        public int Total { get; set; }
    }

    public class VirusTotalUploadResponse
    {
        public VirusTotalUploadData? Data { get; set; }
    }

    public class VirusTotalUploadData
    {
        public string? Id { get; set; }
    }
    #endregion

    #region Helper Classes
    public class InputDialog : Window
    {
        public string Answer { get; private set; }

        public InputDialog(string title, string question, string defaultAnswer = "")
        {
            Title = title;
            Width = 400;
            Height = 150;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            Background = new SolidColorBrush(Color.FromRgb(30, 30, 47));

            var grid = new Grid { Margin = new Thickness(10) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var questionText = new TextBlock
            {
                Text = question,
                Margin = new Thickness(0, 0, 0, 10),
                Foreground = Brushes.White
            };
            grid.Children.Add(questionText);
            Grid.SetRow(questionText, 0);

            var answerBox = new TextBox
            {
                Text = defaultAnswer,
                Margin = new Thickness(0, 0, 0, 15),
                Background = new SolidColorBrush(Color.FromRgb(30, 30, 47)),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(63, 63, 90)),
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
                new Setter(Button.BackgroundProperty, new SolidColorBrush(Color.FromRgb(0, 120, 215))),
                new Setter(Button.ForegroundProperty, Brushes.White),
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
