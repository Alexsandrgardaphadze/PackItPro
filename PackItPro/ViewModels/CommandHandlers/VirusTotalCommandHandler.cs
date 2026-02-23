// ViewModels/CommandHandlers/VirusTotalCommandHandler.cs - v2.1 SMALL ISSUES FIX
// Changes vs v2.0:
//   - catch (Exception ex) where ex was unused → now logs the exception via _logService.
//     The compiler warning (CS0168) pointed at real behaviour: scan failures were
//     silently swallowed with no trace in the log, making diagnosis impossible.
//     Now every per-file scan failure is logged with file name and exception details.
//   - No other logic changes.
using PackItPro.Models;
using PackItPro.Services;
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

        private CancellationTokenSource? _scanCancellationTokenSource;
        private DateTime _lastProgressUpdate = DateTime.MinValue;
        private const int ProgressUpdateIntervalMs = 100;

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

            ScanFilesCommand = new RelayCommand(async _ => await ExecuteScanFilesCommandAsync(null), CanExecuteScan);
            CancelScanCommand = new RelayCommand(_ => CancelScan(), CanCancelScan);

            _status.PropertyChanged += OnStatusPropertyChanged;
        }

        private void OnStatusPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(StatusViewModel.IsBusy))
                RaiseCanExecuteChanged();
        }

        private bool CanExecuteScan(object? parameter) =>
            _fileList.HasFiles && !_status.IsBusy && !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey);

        private bool CanCancelScan(object? parameter) =>
            _status.IsBusy && _scanCancellationTokenSource != null;

        private void CancelScan()
        {
            _scanCancellationTokenSource?.Cancel();
            _logService.Info("Scan cancellation requested by user.");
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
                _logService.Info("Virus scan cancelled by user.");
            }
            catch (Exception ex)
            {
                _logService.Error("Scan operation failed unexpectedly", ex);
                _status.Message = $"Scan failed: {ex.Message}";
                _error.ShowError(
                    $"Virus scan failed: {ex.Message}",
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
            if (string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
            {
                _error.ShowError(
                    "VirusTotal API key is required for scanning.\n" +
                    "Set it via Settings → VirusTotal API Key.");
                return;
            }

            var totalFiles = _fileList.Items.Count(f =>
                !_settings.OnlyScanExecutables ||
                _executableExtensions.Contains(Path.GetExtension(f.FilePath)));

            if (totalFiles == 0)
            {
                MessageBox.Show(
                    "No scannable files found.\n" +
                    "Enable 'Scan all files' in settings to include non-executables.",
                    "No Files to Scan",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource = new CancellationTokenSource();
            var ct = _scanCancellationTokenSource.Token;

            _status.Message = $"Scanning {totalFiles} file(s) with VirusTotal...";
            int processed = 0;
            int failedCount = 0;
            int skippedCount = 0;
            var infectedFiles = new List<FileItemViewModel>();

            foreach (var item in _fileList.Items)
            {
                ct.ThrowIfCancellationRequested();

                if (_settings.OnlyScanExecutables &&
                    !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                {
                    item.Status = FileStatusEnum.Skipped;
                    skippedCount++;
                    processed++;
                    UpdateProgress(processed, totalFiles);
                    continue;
                }

                try
                {
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        _settings.VirusTotalApiKey,
                        _settings.OnlyScanExecutables,
                        _settings.MinimumDetectionsToFlag,
                        ct);

                    item.Positives = result.Positives;
                    item.TotalScans = result.TotalScans;
                    item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                    if (result.IsInfected)
                        infectedFiles.Add(item);

                    _logService.Info(
                        $"Scanned '{item.FileName}': {result.Positives}/{result.TotalScans} " +
                        $"detections — {item.Status}");
                }
                catch (OperationCanceledException)
                {
                    throw; // propagate to outer handler
                }
                catch (Exception ex)
                {
                    // FIX: was catch (Exception ex) with ex unused → warning CS0168
                    // and silent failure. Now logged so failures are diagnosable.
                    _logService.Error($"Scan failed for '{item.FileName}'", ex);
                    item.Status = FileStatusEnum.ScanFailed;
                    failedCount++;
                }
                finally
                {
                    processed++;
                    UpdateProgress(processed, totalFiles);
                }
            }

            // ── Report results ─────────────────────────────────────────

            if (infectedFiles.Count > 0)
            {
                var msg = $"{infectedFiles.Count} infected file(s) detected!";
                if (_settings.AutoRemoveInfectedFiles)
                {
                    foreach (var f in infectedFiles)
                        _fileList.Items.Remove(f);
                    msg += "\n\nAutomatically removed from the package list.";
                }
                else
                {
                    msg += "\n\nReview files marked 'Infected' before packaging.";
                }
                MessageBox.Show(msg, "Security Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (failedCount > 0)
            {
                MessageBox.Show(
                    $"Scan completed with {failedCount} error(s).\n\nCheck the log for details.",
                    "Scan Completed with Errors",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                var skippedNote = skippedCount > 0 ? $" ({skippedCount} skipped)" : "";
                MessageBox.Show(
                    $"All {totalFiles} file(s) scanned clean!{skippedNote}",
                    "Scan Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            await _virusTotalClient.SaveCacheAsync(_logService);

            _status.Message = failedCount > 0
                ? $"Scan completed — {failedCount} error(s). Check log."
                : "Scan completed successfully.";
        }

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
            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource?.Dispose();
            base.Dispose();
        }
    }
}