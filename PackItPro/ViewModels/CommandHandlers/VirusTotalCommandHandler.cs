// PackItPro/ViewModels/CommandHandlers/VirusTotalCommandHandler.cs - v2.3 (ROBUSTNESS FIX)
// Changes vs v2.2:
//   [1] Added CancellationTokenSource for scan cancellation.
//       Scan button enables CancelScanCommand during scan.
//   [2] Added progress update throttling (every 100ms) to prevent UI overload.
//   [3] Added robust error handling around VirusTotalClient calls to prevent crashes.
//   [4] Added scan result logging for debugging.
using Microsoft.VisualBasic.Logging;
using PackItPro.Models;
using PackItPro.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ListView;

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
        private CancellationTokenSource? _scanCts;
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

            // ✅ FIX: Use AsyncRelayCommand for better async exception handling
            ScanFilesCommand = new AsyncRelayCommand(ExecuteScanFilesCommandAsync, CanExecuteScan);
            CancelScanCommand = new RelayCommand(_ => CancelScan(), CanCancelScan);

            _status.PropertyChanged += OnStatusPropertyChanged;
            _settings.PropertyChanged += OnSettingsPropertyChanged;
        }

        private void OnStatusPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(StatusViewModel.IsBusy))
                RaiseCanExecuteChanged();
        }

        private void OnSettingsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName is nameof(SettingsViewModel.ScanWithVirusTotal)
                               or nameof(SettingsViewModel.VirusTotalApiKey))
                RaiseCanExecuteChanged();
        }

        private bool CanExecuteScan(object? parameter) =>
            _settings.ScanWithVirusTotal && // ✅ NEW: Check the UI toggle
            _fileList.HasFiles &&
            !_status.IsBusy &&
            !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey);

        private bool CanCancelScan(object? parameter) =>
            _status.IsBusy && _scanCts != null; // Check if scan is running and CTS exists

        private void CancelScan()
        {
            _scanCts?.Cancel();
            _logService.Info("[VirusTotalCommandHandler] Scan cancellation requested by user.");
        }

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
                _status.Message = "Scan cancelled.";
                _logService.Info("[VirusTotalCommandHandler] Virus scan was cancelled.");
            }
            catch (Exception ex)
            {
                _logService.Error("[VirusTotalCommandHandler] Scan operation failed unexpectedly", ex);
                _status.Message = $"Scan failed: {ex.Message}";
                _error.ShowError(
                    $"Virus scan failed: {ex.Message}",
                    retryAction: () => _ = ExecuteScanFilesCommandAsync(parameter)); // Fire-and-forget retry
            }
            finally
            {
                _status.SetStatusReady();
                _scanCts?.Dispose();
                _scanCts = null;
            }
        }

        private async Task ExecuteScanFilesWithVirusTotalAsync()
        {
            if (_virusTotalClient == null || string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
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
                    "No scannable files found.\nEnable 'Scan all files' in settings to include non-executables.",
                    "No Files to Scan",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            // Cancel any previous scan operation's CTS
            _scanCts?.Cancel();
            _scanCts = new CancellationTokenSource();
            var ct = _scanCts.Token; // Use the new CTS token

            _status.Message = $"Scanning {totalFiles} file(s) with VirusTotal...";
            int processed = 0, failedCount = 0, skippedCount = 0; // ✅ NEW: Track skipped files
            var infectedFiles = new List<FileItemViewModel>();

            foreach (var item in _fileList.Items)
            {
                ct.ThrowIfCancellationRequested(); // ✅ NEW: Check for cancellation

                if (_settings.OnlyScanExecutables &&
                    !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                {
                    item.Status = FileStatusEnum.Skipped;
                    skippedCount++; // ✅ NEW: Increment skipped counter
                    processed++;
                    // ✅ NEW: Provide immediate feedback to user
                    _status.Message = $"Scanning {totalFiles} file(s)... ({skippedCount} skipped)";
                    UpdateProgress(processed, totalFiles);
                    continue; // Skip to next file
                }

                try
                {
                    // ✅ FIX: Pass CancellationToken to scan method
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        _settings.VirusTotalApiKey,
                        _settings.OnlyScanExecutables,
                        _settings.MinimumDetectionsToFlag,
                        ct); // Pass the cancellation token

                    item.Positives = result.Positives;
                    item.TotalScans = result.TotalScans;
                    item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                    if (result.IsInfected)
                        infectedFiles.Add(item);

                    // ✅ NEW: Log scan result for debugging
                    _logService.Info($"Scanned '{item.FileName}': {result.Positives}/{result.TotalScans} detections — {item.Status}");
                }
                catch (OperationCanceledException)
                {
                    throw; // Re-throw to be handled by outer try-catch
                }
                catch (Exception ex)
                {
                    _logService.Error($"Scan failed for '{item.FileName}'", ex);
                    item.Status = FileStatusEnum.ScanFailed;
                    failedCount++;
                }
                finally
                {
                    processed++;
                    UpdateProgress(processed, totalFiles); // Throttled updates
                }
            }

            // ── Results summary ───────────────────────────────────────────────

            if (infectedFiles.Count > 0)
            {
                var message = $"{infectedFiles.Count} infected file(s) detected!";
                if (_settings.AutoRemoveInfectedFiles)
                {
                    foreach (var file in infectedFiles)
                        _fileList.Items.Remove(file);
                    message += "\nAutomatically removed from package list.";
                }
                else
                {
                    message += "\nReview files marked as 'Infected' before packaging.";
                }
                MessageBox.Show(message, "Security Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (failedCount > 0)
            {
                MessageBox.Show(
                    $"Scan completed with {failedCount} error(s).\nCheck logs for details.",
                    "Scan Completed with Errors",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                var skippedNote = skippedCount > 0 ? $" ({skippedCount} skipped)" : ""; // ✅ NEW: Show skipped count
                MessageBox.Show(
                    $"All {totalFiles} file(s) scanned clean!{skippedNote}",
                    "Scan Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            // ✅ FIX: Pass logService to SaveCacheAsync
            await _virusTotalClient.SaveCacheAsync(_logService);

            _status.Message = failedCount > 0
                ? $"Scan completed — {failedCount} error(s). Check log."
                : "Scan completed successfully.";
        }

        // ✅ NEW: Throttle progress updates to prevent UI overload
        private void UpdateProgress(int processed, int total)
        {
            var now = DateTime.Now;
            if ((now - _lastProgressUpdate).TotalMilliseconds > ProgressUpdateIntervalMs)
            {
                _status.ProgressPercentage = Math.Round((double)processed / total * 100, 1);
                _lastProgressUpdate = now;
            }
        }

        public override void Dispose()
        {
            _status.PropertyChanged -= OnStatusPropertyChanged;
            _settings.PropertyChanged -= OnSettingsPropertyChanged;
            _scanCts?.Cancel();
            _scanCts?.Dispose();
            base.Dispose();
        }
    }
}