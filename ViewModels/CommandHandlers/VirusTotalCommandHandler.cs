// ViewModels/CommandHandlers/VirusTotalCommandHandler.cs
using PackItPro.Models;
using PackItPro.Services;
// using PackItPro.ViewModels.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class VirusTotalCommandHandler : CommandHandlerBase
    {
        private readonly FileListViewModel _fileList;
        private readonly SettingsViewModel _settings;
        private readonly StatusViewModel _status;
        private readonly ErrorViewModel _error;
        private readonly VirusTotalClient _virusTotalClient;
        private readonly ILogService _logService;
        private readonly HashSet<string> _executableExtensions;

        // Cancellation support
        private CancellationTokenSource? _scanCancellationTokenSource;
        private DateTime _lastProgressUpdate = DateTime.MinValue;
        private const int ProgressUpdateIntervalMs = 100; // Max 10 updates/second

        public ICommand ScanFilesCommand { get; }
        public ICommand CancelScanCommand { get; }

        public VirusTotalCommandHandler(
            FileListViewModel fileList,
            SettingsViewModel settings,
            StatusViewModel status,
            ErrorViewModel error,
            VirusTotalClient virusTotalClient,
            ILogService logService,
            HashSet<string> executableExtensions)
        {
            _fileList = fileList ?? throw new ArgumentNullException(nameof(fileList));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _error = error ?? throw new ArgumentNullException(nameof(error));
            _virusTotalClient = virusTotalClient ?? throw new ArgumentNullException(nameof(virusTotalClient));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _executableExtensions = executableExtensions ?? throw new ArgumentNullException(nameof(executableExtensions));

            // ✅ FIX: Use async wrapper to avoid async void
            ScanFilesCommand = new RelayCommand(async _ => await ExecuteScanFilesCommandAsync(null), CanExecuteScan);
            CancelScanCommand = new RelayCommand(_ => CancelScan(), CanCancelScan);

            // Subscribe to status changes for CanExecute updates
            _status.PropertyChanged += OnStatusPropertyChanged;
        }

        private void OnStatusPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(StatusViewModel.IsBusy))
            {
                RaiseCanExecuteChanged();
            }
        }

        private bool CanExecuteScan(object? parameter) =>
            _fileList.HasFiles && !_status.IsBusy && !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey);

        private bool CanCancelScan(object? parameter) => _status.IsBusy && _scanCancellationTokenSource != null;

        private void CancelScan()
        {
            _scanCancellationTokenSource?.Cancel();
            _logService.Info("Scan cancellation requested by user");
        }

        // ✅ FIX: Changed from async void to async Task
        private async Task ExecuteScanFilesCommandAsync(object? parameter)
        {
            if (!CanExecuteScan(parameter)) return;

            try
            {
                _status.SetStatusScanning();
                await ExecuteScanFilesWithVirusTotalAsync();
            }
            catch (OperationCanceledException)
            {
                _status.Message = "Scan cancelled by user";
                _logService.Info("Virus scan was cancelled");
            }
            catch (Exception ex)
            {
                _logService.Error("Scan operation failed", ex);
                _status.Message = $"Scan failed: {ex.Message}";
                _error.ShowError(
                    $"Virus scan failed: {ex.Message}",
                    // ✅ FIX: Use fire-and-forget properly with _ discard
                    retryAction: () => _ = ExecuteScanFilesCommandAsync(parameter));
            }
            finally
            {
                _status.SetStatusReady();
                _scanCancellationTokenSource?.Dispose();
                _scanCancellationTokenSource = null;
            }
        }

        private async Task ExecuteScanFilesWithVirusTotalAsync()
        {
            // ✅ FIX: Fail-fast with proper error message
            if (_virusTotalClient == null)
                throw new InvalidOperationException("VirusTotal client not initialized. Call InitializeAsync() first.");

            if (string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
            {
                _error.ShowError("VirusTotal API key is required for scanning.\nSet it in Settings > VirusTotal API Key.");
                return;
            }

            var totalFiles = _fileList.Items.Count(f =>
                !_settings.OnlyScanExecutables ||
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

            // ✅ NEW: Initialize cancellation token for this scan
            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource = new CancellationTokenSource();
            var cancellationToken = _scanCancellationTokenSource.Token;

            _status.Message = $"Scanning {totalFiles} file(s) with VirusTotal...";
            int processed = 0;
            int failedCount = 0;
            int skippedCount = 0;  // ✅ NEW: Track skipped files
            var infectedFiles = new List<FileItemViewModel>();

            try
            {
                foreach (var item in _fileList.Items)
                {
                    // ✅ CHECK: Allow cancellation at loop start
                    cancellationToken.ThrowIfCancellationRequested();

                    // Skip non-executables if setting is enabled
                    if (_settings.OnlyScanExecutables &&
                        !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                    {
                        item.Status = FileStatusEnum.Skipped;
                        skippedCount++;  // ✅ NEW: Increment skipped counter
                        processed++;
                        
                        // ✅ NEW: Provide immediate feedback to user
                        _status.Message = $"Scanning {totalFiles} file(s)... ({skippedCount} skipped)";
                        UpdateProgress(processed, totalFiles);
                        continue;
                    }

                    try
                    {
                        // ✅ NEW: Pass cancellation token to scan method
                        var result = await _virusTotalClient.ScanFileAsync(
                            item.FilePath,
                            _settings.VirusTotalApiKey,
                            _settings.OnlyScanExecutables,
                            _settings.MinimumDetectionsToFlag,
                            cancellationToken);

                        item.Positives = result.Positives;
                        item.TotalScans = result.TotalScans;
                        item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                        if (result.IsInfected)
                            infectedFiles.Add(item);

                        // ✅ NEW: Enhanced logging for successful scans
                        _logService.Info($"Scanned {item.FileName}: {result.Positives}/{result.TotalScans} detections - Status: {item.Status}");
                    }
                    catch (OperationCanceledException)
                    {
                        throw; // Re-throw to be handled by outer try-catch
                    }
                    catch (Exception ex)
                    {
                        _logService.Error($"Scan failed for {item.FileName}", ex);
                        item.Status = FileStatusEnum.ScanFailed;
                        failedCount++;
                    }
                    finally
                    {
                        processed++;
                        // ✅ NEW: Throttle progress updates
                        UpdateProgress(processed, totalFiles);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // User cancelled the scan
                throw;
            }

            // Handle infected files
            if (infectedFiles.Count > 0)
            {
                var message = $"{infectedFiles.Count} infected file(s) detected!";
                if (_settings.AutoRemoveInfectedFiles)
                {
                    foreach (var file in infectedFiles)
                        _fileList.Items.Remove(file);

                    message += $"\n\nAutomatically removed from package list.";
                }
                else
                {
                    message += $"\n\nReview files marked as 'Infected' before packaging.";
                }

                MessageBox.Show(message, "Security Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (failedCount > 0)
            {
                MessageBox.Show(
                    $"Scan completed with errors:\n{failedCount} file(s) failed to scan.\n\nCheck logs for details.",
                    "Scan Completed with Errors",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                MessageBox.Show(
                    $"All {totalFiles} file(s) scanned clean!" + (skippedCount > 0 ? $"\n({skippedCount} skipped)" : ""),
                    "Scan Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            // Save updated cache
            await _virusTotalClient.SaveCacheAsync();
            _status.Message = failedCount > 0 ? "Scan completed with errors" : "Scan completed successfully";
        }

        // ✅ NEW: Throttle progress updates to prevent UI overload
        private void UpdateProgress(int processed, int totalFiles)
        {
            var now = DateTime.Now;
            if ((now - _lastProgressUpdate).TotalMilliseconds > ProgressUpdateIntervalMs)
            {
                _status.ProgressPercentage = Math.Round((double)processed / totalFiles * 100, 1);
                _lastProgressUpdate = now;
            }
        }

        public override void Dispose()
        {
            _status.PropertyChanged -= OnStatusPropertyChanged;
            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource?.Dispose();
            base.Dispose();
        }
    }
}