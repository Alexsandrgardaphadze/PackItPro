using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection; // For Assembly
using System.Security.Cryptography;
using System.Security.Principal; // For WindowsPrincipal, WindowsIdentity, WindowsBuiltInRole
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

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
        public bool IncludeWingetUpdateScript { get; set; } = false; // New setting
        public bool UseLZMACompression { get; set; } = true; // New setting
    }

    // Manifest model - Updated to include SHA256Checksum
    public class PackageManifest
    {
        public string Version { get; set; } = "1.0";
        public string PackageName { get; set; } = "MySoftwareBundle";
        public List<ManifestFile> Files { get; set; } = new List<ManifestFile>();
        public bool Cleanup { get; set; } = true;
        public string? AutoUpdateScript { get; set; } // Optional script name
        public string? SHA256Checksum { get; set; } // NEW: Add SHA256Checksum for integrity verification
    }

    public class ManifestFile
    {
        public string Name { get; set; } = "";
        public string InstallType { get; set; } = "exe"; // e.g., exe, msi, appx
        public string[]? SilentArgs { get; set; } // Changed to string[]
        public bool RequiresAdmin { get; set; } = false;
        public int InstallOrder { get; set; } = 0;
        // TODO: Add WingetId field for mapping during packaging/update
        // public string? WingetId { get; set; }
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

        // NEW: SemaphoreSlim for rate limiting (4 concurrent requests)
        private readonly SemaphoreSlim _rateLimitSemaphore = new(4, 4);

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
                        item.StatusColor = (SolidColorBrush)FindResource("AppTextTertiaryColor");
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
                            // NEW: Use SemaphoreSlim for rate limiting, await the permit
                            await _rateLimitSemaphore.WaitAsync();

                            try
                            {
                                result = await QueryVirusTotal(item.FilePath, hash);
                                _scanCache[hash] = result;
                                ApplyScanResult(item, result);
                            }
                            finally
                            {
                                // NEW: Always release the rate limit permit
                                _rateLimitSemaphore.Release();
                            }
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
            item.StatusColor = item.IsInfected ? (SolidColorBrush)FindResource("AppStatusErrorColor") : (SolidColorBrush)FindResource("AppStatusCleanColor");
            return result;
        }

        private async Task<VirusScanResult> QueryVirusTotal(string filePath, string hash)
        {
            // NEW: Acquire rate limit permit *before* making the request
            // This is handled by the caller (ScanFilesWithVirusTotal) using the semaphore.

            try
            {
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-apikey", _settings.VirusTotalApiKey);

                var reportResponse = await _httpClient.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hash}"); // Fixed URL

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
                    "https://www.virustotal.com/api/v3/files", formData); // Fixed URL
                uploadResponse.EnsureSuccessStatusCode();

                var analysisId = (await uploadResponse.Content.ReadFromJsonAsync<VirusTotalUploadResponse>()).Data.Id;

                // Poll for results
                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(5000);
                    var analysisResponse = await _httpClient.GetAsync(
                        $"https://www.virustotal.com/api/v3/analyses/{analysisId}"); // Fixed URL

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
            // NEW: Validate stub installer exists in AppData or base directory
            var stubPath = Path.Combine(_appDataDir, "StubInstaller.exe");
            if (!File.Exists(stubPath))
            {
                // Fallback to base directory (old location) if not found in AppData
                stubPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
                if (!File.Exists(stubPath))
                {
                    MessageBox.Show("Stub installer (StubInstaller.exe) not found in application directory or AppData. Please ensure the stub is present.",
                        "Missing Component", MessageBoxButton.OK, MessageBoxImage.Error);
                    // TODO: Implement stub installer creation/download mechanism or clear error message.
                    return;
                }
                else
                {
                    LogInfo("StubInstaller.exe found in base directory. Consider moving to AppData.");
                }
            }

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
                string tempPayloadPath = null; // Initialize outside try to access in finally
                string tempFinalPath = null; // Initialize outside try to access in finally
                try
                {
                    Dispatcher.Invoke(() => PackButton.IsEnabled = false);
                    StatusMessageTextBlock.Text = "Creating .packitexe package...";
                    ProcessProgressBar.Value = 0;
                    ProgressPercentTextBlock.Text = "0%";

                    // Create the package payload (zip file)
                    tempPayloadPath = Path.GetTempFileName();
                    try
                    {
                        using (var fs = new FileStream(tempPayloadPath, FileMode.Create))
                        using (var zipStream = new ZipOutputStream(fs))
                        {
                            // NEW: Clarify compression setting
                            if (_settings.UseLZMACompression)
                            {
                                // TODO: Implement LZMA using SevenZipSharp or SharpCompress
                                // For now, using Deflate with highest level as a placeholder.
                                // SharpZipLib's ZipOutputStream doesn't support LZMA natively.
                                zipStream.SetLevel(9); // Highest compression for Deflate
                                LogInfo("Using Deflate (level 9) as LZMA placeholder. Consider using SevenZipSharp for true LZMA.");
                            }
                            else
                            {
                                zipStream.SetLevel(0); // No compression
                            }

                            int totalFiles = _fileItems.Count + (_settings.IncludeWingetUpdateScript ? 2 : 1); // +1 for manifest, +1 for winget script if included
                            int processed = 0;

                            // Add the manifest file
                            var manifest = new PackageManifest
                            {
                                PackageName = Path.GetFileNameWithoutExtension(saveDialog.FileName),
                                Files = _fileItems.Select((f, i) => new ManifestFile
                                {
                                    Name = Path.GetFileName(f.FilePath),
                                    InstallType = GetInstallTypeFromExtension(Path.GetExtension(f.FilePath)),
                                    SilentArgs = GetDefaultSilentArgs(Path.GetExtension(f.FilePath)), // Use string[] now
                                    RequiresAdmin = false, // Could be configurable per file later
                                    InstallOrder = i
                                    // TODO: Add WingetId mapping here if available
                                }).ToList()
                            };

                            if (_settings.IncludeWingetUpdateScript)
                            {
                                manifest.AutoUpdateScript = "update_all.bat";
                            }

                            // NEW: Calculate directory hash for integrity check (Step 2a)
                            var tempExtractionDir = Path.Combine(Path.GetTempPath(), "PackItPro_Packaging_" + Guid.NewGuid().ToString());
                            Directory.CreateDirectory(tempExtractionDir); // Create temp dir for hashing prep

                            try
                            {
                                // Copy files to temp dir for hashing calculation
                                foreach (var fileItem in _fileItems)
                                {
                                    var destPath = Path.Combine(tempExtractionDir, Path.GetFileName(fileItem.FilePath));
                                    File.Copy(fileItem.FilePath, destPath, overwrite: true);
                                }

                                // Add the *initial* manifest (without hash) to temp dir for hashing calculation
                                string tempManifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
                                File.WriteAllText(Path.Combine(tempExtractionDir, "packitmeta.json"), tempManifestJson);

                                // Add Winget script if enabled, to temp dir for hashing calculation
                                if (_settings.IncludeWingetUpdateScript)
                                {
                                    string wingetScriptContent = @"@echo off
REM This is a placeholder for Winget updates.
REM In a real scenario, you would call winget upgrade for each installed package.
REM You need to map the bundled installer filenames to their respective Winget IDs.
REM Example (hardcoded, needs mapping):
REM winget upgrade --id Microsoft.Edge
REM winget upgrade --id VideoLAN.VLC
REM A more robust solution would read the packitmeta.json and look up Winget IDs stored there.
echo Placeholder: Winget update script would run here based on packitmeta.json.
pause
";
                                    File.WriteAllText(Path.Combine(tempExtractionDir, "update_all.bat"), wingetScriptContent);
                                }

                                // Calculate the hash of the temp directory contents
                                var calculatedDirHash = Convert.ToBase64String(ComputeDirectoryHash(tempExtractionDir));
                                LogInfo($"Calculated directory hash for integrity check: {calculatedDirHash}");

                                // NOW, update the manifest object with the calculated hash
                                manifest.SHA256Checksum = calculatedDirHash;
                            }
                            finally
                            {
                                // Clean up the temporary directory used for hash calculation
                                if (Directory.Exists(tempExtractionDir))
                                {
                                    Directory.Delete(tempExtractionDir, true);
                                }
                            }


                            string manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
                            var manifestEntry = new ZipEntry("packitmeta.json")
                            {
                                DateTime = DateTime.Now,
                                Size = Encoding.UTF8.GetByteCount(manifestJson)
                            };
                            zipStream.PutNextEntry(manifestEntry);
                            using (var manifestStream = new MemoryStream(Encoding.UTF8.GetBytes(manifestJson)))
                            {
                                await manifestStream.CopyToAsync(zipStream);
                            }
                            zipStream.CloseEntry();
                            processed++;
                            UpdateProgress(processed, totalFiles, "Packing");

                            // Add files from the list
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
                                UpdateProgress(processed, totalFiles, "Packing");
                            }

                            // Add Winget update script if enabled
                            if (_settings.IncludeWingetUpdateScript)
                            {
                                // NEW: Placeholder script with TODO comment
                                string wingetScriptContent = @"@echo off
REM This is a placeholder for Winget updates.
REM In a real scenario, you would call winget upgrade for each installed package.
REM You need to map the bundled installer filenames to their respective Winget IDs.
REM Example (hardcoded, needs mapping):
REM winget upgrade --id Microsoft.Edge
REM winget upgrade --id VideoLAN.VLC
REM A more robust solution would read the packitmeta.json and look up Winget IDs stored there.
echo Placeholder: Winget update script would run here based on packitmeta.json.
pause
";
                                var scriptEntry = new ZipEntry("update_all.bat")
                                {
                                    DateTime = DateTime.Now,
                                    Size = Encoding.UTF8.GetByteCount(wingetScriptContent)
                                };
                                zipStream.PutNextEntry(scriptEntry);
                                using (var scriptStream = new MemoryStream(Encoding.UTF8.GetBytes(wingetScriptContent)))
                                {
                                    await scriptStream.CopyToAsync(zipStream);
                                }
                                zipStream.CloseEntry();
                                processed++;
                                UpdateProgress(processed, totalFiles, "Packing");
                            }
                        }

                        // Create the final .packitexe by combining stub and payload
                        tempFinalPath = Path.GetTempFileName();
                        using (var finalStream = new FileStream(tempFinalPath, FileMode.Create))
                        using (var stubStream = new FileStream(stubPath, FileMode.Open, FileAccess.Read))
                        using (var payloadStream = new FileStream(tempPayloadPath, FileMode.Open, FileAccess.Read))
                        {
                            // NEW: Copy stub first with progress update
                            var stubLength = stubStream.Length;
                            var buffer = new byte[8192]; // 8KB buffer
                            int read;
                            long totalBytesRead = 0;
                            StatusMessageTextBlock.Text = "Embedding stub installer...";
                            while ((read = await stubStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                await finalStream.WriteAsync(buffer, 0, read);
                                totalBytesRead += read;
                                // Update progress based on stub size
                                var stubProgress = (double)totalBytesRead / stubLength * 50; // Assume stub is ~50% of final file for progress estimation
                                UpdateProgress((int)stubProgress, 100, "Embedding Stub");
                            }
                            UpdateProgress(50, 100, "Embedding Stub"); // Mark stub copy as ~50%

                            // NEW: Then append payload with progress update
                            var payloadLength = payloadStream.Length;
                            totalBytesRead = 0;
                            StatusMessageTextBlock.Text = "Appending payload...";
                            while ((read = await payloadStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                await finalStream.WriteAsync(buffer, 0, read);
                                totalBytesRead += read;
                                // Update progress based on payload size, starting from 50%
                                var payloadProgress = 50 + (double)totalBytesRead / payloadLength * 50; // Remaining 50%
                                UpdateProgress((int)payloadProgress, 100, "Appending Payload");
                            }
                            UpdateProgress(100, 100, "Finalizing"); // Mark as complete
                        }

                        // Move temp file to final location
                        File.Move(tempFinalPath, saveDialog.FileName, overwrite: true);
                    }
                    catch (Exception innerEx) // NEW: Catch block for the inner try
                    {
                        LogError("Inner packaging process failed", innerEx);
                        throw; // Re-throw to be caught by the outer catch
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
                    // NEW: Ensure temporary files are deleted even if an exception occurs
                    if (!string.IsNullOrEmpty(tempPayloadPath) && File.Exists(tempPayloadPath))
                    {
                        try { File.Delete(tempPayloadPath); } catch { /* Ignore errors during cleanup */ }
                    }
                    if (!string.IsNullOrEmpty(tempFinalPath) && File.Exists(tempFinalPath))
                    {
                        try { File.Delete(tempFinalPath); } catch { /* Ignore errors during cleanup */ }
                    }
                    ResetProgress();
                    PackButton.IsEnabled = true;
                }
            }
        }

        // NEW: Helper function to compute directory hash (Step 2a)
        private static byte[] ComputeDirectoryHash(string directoryPath)
        {
            using var sha256 = SHA256.Create();
            var fileHashes = new List<byte[]>();

            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files); // Sort filenames to ensure consistent order

            foreach (var filePath in files)
            {
                var fileContentHash = ComputeFileHash(filePath);
                var relativePath = Path.GetRelativePath(directoryPath, filePath);
                var pathBytes = Encoding.UTF8.GetBytes(relativePath.ToLowerInvariant());

                using var tempStream = new MemoryStream();
                tempStream.Write(pathBytes, 0, pathBytes.Length);
                tempStream.Write(fileContentHash, 0, fileContentHash.Length);
                tempStream.Position = 0;

                var combinedHash = sha256.ComputeHash(tempStream);
                fileHashes.Add(combinedHash);
            }

            fileHashes.Sort((x, y) => Comparer<byte[]>.Default.Compare(x, y));

            using var finalStream = new MemoryStream();
            foreach (var hash in fileHashes)
            {
                finalStream.Write(hash, 0, hash.Length);
            }
            finalStream.Position = 0;

            return sha256.ComputeHash(finalStream);
        }

        // NEW: Helper function to compute file hash
        private static byte[] ComputeFileHash(string filePath)
        {
            using var fileStream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(fileStream);
        }


        private string GetInstallTypeFromExtension(string ext)
        {
            switch (ext.ToLower())
            {
                case ".msi":
                    return "msi";
                case ".exe":
                    return "exe";
                case ".appx":
                case ".appxbundle":
                    return "appx";
                default:
                    return "file"; // Generic file type
            }
        }

        // NEW: Return string[] for silent args
        private string[]? GetDefaultSilentArgs(string ext)
        {
            switch (ext.ToLower())
            {
                case ".msi":
                    return new[] { "/quiet", "/norestart" };
                case ".exe":
                    // Return an array of common silent flags. The stub installer can try them sequentially.
                    return new[] { "/S", "/silent", "/quiet", "/SILENT", "/VERYSILENT" };
                default:
                    return null;
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
            // Count clean files - Logic remains, but UI update is skipped
            int cleanCount = _fileItems.Count(f => !f.IsInfected && f.Status != "Skipped Scan" && f.Status != "Scan Failed");
            // Log the count if SafeFilesTextBlock is missing
            LogInfo($"UpdateSummary: Total Files = {_fileItems.Count}, Clean Files = {cleanCount}"); // Optional: Log for debugging

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
                DropAreaBorder.BorderBrush = (SolidColorBrush)FindResource("AppDropAreaHoverColor");
                // NEW: Use named resource instead of hardcoded Color.FromArgb
                var brush = (SolidColorBrush)FindResource("AppDropAreaHoverColor");
                var color = brush.Color;
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
            DropAreaBorder.BorderBrush = (SolidColorBrush)FindResource("AppBorderColor");
            DropAreaBorder.Background = (SolidColorBrush)FindResource("AppPanelColor");
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
                SaveSettings();
                MessageBox.Show("API key updated successfully!",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

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
            settingsInfo.AppendLine($"- Include Winget Update Script: {_settings.IncludeWingetUpdateScript}");
            settingsInfo.AppendLine($"- Use LZMA Compression: {_settings.UseLZMACompression}");

            MessageBox.Show(settingsInfo.ToString(), "PackItPro Settings", MessageBoxButton.OK, MessageBoxImage.Information);
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
                if (File.Exists(_settingsFilePath)) // Use new path
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath);
                    _settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }

                if (File.Exists(_cacheFilePath)) // Use new path
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

        private void SaveVirusScanCache()
        {
            try
            {
                // Ensure directory exists before saving
                var dirPath = Path.GetDirectoryName(_cacheFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                {
                    Directory.CreateDirectory(dirPath);
                }

                File.WriteAllText(_cacheFilePath, // Use new path
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
                    _rateLimitSemaphore?.Dispose(); // NEW: Dispose the rate limit semaphore
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