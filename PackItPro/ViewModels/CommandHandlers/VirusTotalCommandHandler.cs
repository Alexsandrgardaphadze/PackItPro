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
        private readonly TrustStore _trustStore;

        private CancellationTokenSource? _scanCancellationTokenSource;
        private DateTime _lastProgressUpdate = DateTime.MinValue;
        private const int ProgressUpdateIntervalMs = 100;

        public ICommand ScanFilesCommand { get; }
        public ICommand CancelScanCommand { get; }

        /// <summary>
        /// Right-click → "Mark as Trusted / False Positive".
        /// CommandParameter: the FileItemViewModel being right-clicked.
        /// Disabled for files flagged by a trusted engine — those cannot be overridden.
        /// </summary>
        public ICommand MarkAsTrustedCommand { get; }

        /// <summary>Right-click → "Remove Trust" to un-mark a previously trusted file.</summary>
        public ICommand RemoveTrustCommand { get; }

        public VirusTotalCommandHandler(
            FileListViewModel fileList,
            SettingsViewModel settings,
            StatusViewModel status,
            ErrorViewModel error,
            VirusTotalClient virusTotalClient,
            ILogService logService,
            HashSet<string> executableExtensions,
            TrustStore trustStore)
        {
            _fileList = fileList ?? throw new ArgumentNullException(nameof(fileList));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _error = error ?? throw new ArgumentNullException(nameof(error));
            _virusTotalClient = virusTotalClient ?? throw new ArgumentNullException(nameof(virusTotalClient));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _executableExtensions = executableExtensions ?? throw new ArgumentNullException(nameof(executableExtensions));
            _trustStore = trustStore ?? throw new ArgumentNullException(nameof(trustStore));

            ScanFilesCommand = new RelayCommand(async _ => await ExecuteScanFilesCommandAsync(null), CanExecuteScan);
            CancelScanCommand = new RelayCommand(_ => CancelScan(), CanCancelScan);
            MarkAsTrustedCommand = new RelayCommand(async p => await ExecuteMarkAsTrustedAsync(p), CanMarkAsTrusted);
            RemoveTrustCommand = new RelayCommand(async p => await ExecuteRemoveTrustAsync(p), CanRemoveTrust);

            _status.PropertyChanged += OnStatusPropertyChanged;
        }

        // ── CanExecute ────────────────────────────────────────────────────────

        private void OnStatusPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(StatusViewModel.IsBusy))
                RaiseCanExecuteChanged();
        }

        private bool CanExecuteScan(object? _) =>
            _fileList.HasFiles && !_status.IsBusy && !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey);

        private bool CanCancelScan(object? _) =>
            _status.IsBusy && _scanCancellationTokenSource != null;

        private bool CanMarkAsTrusted(object? parameter) =>
            parameter is FileItemViewModel item &&
            item.Status == FileStatusEnum.Infected &&
            !item.FlaggedByTrustedEngine &&
            !item.IsTrustedFalsePositive;

        private bool CanRemoveTrust(object? parameter) =>
            parameter is FileItemViewModel item && item.IsTrustedFalsePositive;

        // ── Scan ──────────────────────────────────────────────────────────────

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

            // Count only files that will actually be submitted — skipped files do not
            // consume progress slots. This prevents the bar from stalling at e.g. 50%
            // when half the list is non-executables.
            var scannableItems = _fileList.Items
                .Where(f => !_settings.OnlyScanExecutables ||
                            _executableExtensions.Contains(Path.GetExtension(f.FilePath)))
                .ToList();

            if (scannableItems.Count == 0)
            {
                MessageBox.Show(
                    "No scannable files found.\n" +
                    "Enable 'Scan all files' in settings to include non-executables.",
                    "No Files to Scan",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            // Mark non-scannable files as Skipped up front
            foreach (var item in _fileList.Items.Except(scannableItems))
                item.Status = FileStatusEnum.Skipped;

            _scanCancellationTokenSource?.Cancel();
            _scanCancellationTokenSource = new CancellationTokenSource();
            var ct = _scanCancellationTokenSource.Token;

            _status.Message = $"Scanning {scannableItems.Count} file(s) with VirusTotal...";
            int processed = 0, failedCount = 0, trustedFpCount = 0;
            var infectedFiles = new List<FileItemViewModel>();
            var trustedEngineFiles = new List<FileItemViewModel>();

            var trustedEngines = _settings.SettingsModel.TrustedEngines;

            foreach (var item in scannableItems)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        _settings.VirusTotalApiKey,
                        _settings.OnlyScanExecutables,
                        _settings.MinimumDetectionsToFlag,
                        ct,
                        trustedEngines: trustedEngines,
                        trustStore: _trustStore);

                    item.Positives = result.Positives;
                    item.TotalScans = result.TotalScans;
                    item.FlaggedByTrustedEngine = result.FlaggedByTrustedEngine;
                    item.TrustedEngineName = result.TrustedEngineName;

                    if (result.IsTrustedFalsePositive)
                    {
                        item.Status = FileStatusEnum.Clean;
                        item.IsTrustedFalsePositive = true;
                        trustedFpCount++;
                        _logService.Info($"Scanned '{item.FileName}': trusted false positive — skipped VT.");
                    }
                    else
                    {
                        item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                        if (result.IsInfected)
                        {
                            infectedFiles.Add(item);
                            if (result.FlaggedByTrustedEngine)
                                trustedEngineFiles.Add(item);
                        }

                        _logService.Info(
                            $"Scanned '{item.FileName}': {result.Positives}/{result.TotalScans} detections" +
                            (result.FlaggedByTrustedEngine ? $" [TRUSTED ENGINE: {result.TrustedEngineName}]" : "") +
                            $" — {item.Status}");
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
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
                    UpdateProgress(processed, scannableItems.Count);
                }
            }

            // ── Results summary ───────────────────────────────────────────────

            if (trustedEngineFiles.Count > 0)
            {
                var names = string.Join("\n", trustedEngineFiles.Select(f =>
                    $"  • {f.FileName} — flagged by {f.TrustedEngineName}"));
                var msg = $"⚠ REAL MALWARE DETECTED\n\n" +
                          $"The following file(s) were flagged by a trusted security engine:\n\n{names}\n\n" +
                          $"These cannot be marked as false positives. Remove them before packaging.";

                if (_settings.AutoRemoveInfectedFiles)
                {
                    foreach (var f in trustedEngineFiles)
                        _fileList.Items.Remove(f);
                    msg += "\n\nAutomatically removed from the package list.";
                }

                MessageBox.Show(msg, "Real Malware Detected", MessageBoxButton.OK, MessageBoxImage.Stop);
            }
            else if (infectedFiles.Count > 0)
            {
                var names = string.Join("\n", infectedFiles.Select(f =>
                    $"  • {f.FileName} ({f.Positives}/{f.TotalScans} engines)"));
                var msg = $"{infectedFiles.Count} file(s) flagged:\n\n{names}\n\n" +
                          $"If these are false positives, right-click → 'Mark as Trusted'.";

                if (_settings.AutoRemoveInfectedFiles)
                {
                    foreach (var f in infectedFiles)
                        _fileList.Items.Remove(f);
                    msg += "\n\nAutomatically removed from the package list.";
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
                var notes = new List<string>();
                if (trustedFpCount > 0) notes.Add($"{trustedFpCount} trusted FP");
                var suffix = notes.Count > 0 ? $" ({string.Join(", ", notes)})" : "";

                MessageBox.Show(
                    $"All {scannableItems.Count} file(s) scanned clean!{suffix}",
                    "Scan Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            await _virusTotalClient.SaveCacheAsync(_logService);

            _status.Message = failedCount > 0
                ? $"Scan completed — {failedCount} error(s). Check log."
                : "Scan completed successfully.";
        }

        // ── Trust actions ─────────────────────────────────────────────────────

        private async Task ExecuteMarkAsTrustedAsync(object? parameter)
        {
            if (parameter is not FileItemViewModel item) return;
            if (item.FlaggedByTrustedEngine)
            {
                MessageBox.Show(
                    $"'{item.FileName}' was flagged by {item.TrustedEngineName}, " +
                    "a trusted security engine.\n\nThis detection cannot be overridden.",
                    "Cannot Trust",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var confirm = MessageBox.Show(
                $"Mark '{item.FileName}' as a trusted false positive?\n\n" +
                $"It was flagged by {item.Positives}/{item.TotalScans} engine(s).\n\n" +
                "It will be included in the package and this choice will be remembered.",
                "Mark as Trusted",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                string hash = FileHasher.ComputeFileHashString(item.FilePath);
                await _trustStore.TrustAsync(hash, item.FileName);

                item.IsTrustedFalsePositive = true;
                item.Status = FileStatusEnum.Clean;

                _logService.Info($"[Trust] '{item.FileName}' ({hash[..8]}...) marked as trusted FP by user.");
            }
            catch (Exception ex)
            {
                _logService.Error($"Failed to trust '{item.FileName}'", ex);
                _error.ShowError($"Could not save trust entry: {ex.Message}");
            }

            RaiseCanExecuteChanged();
        }

        private async Task ExecuteRemoveTrustAsync(object? parameter)
        {
            if (parameter is not FileItemViewModel item) return;

            try
            {
                string hash = FileHasher.ComputeFileHashString(item.FilePath);
                await _trustStore.UntrustAsync(hash);

                item.IsTrustedFalsePositive = false;
                item.Status = FileStatusEnum.Infected;

                _logService.Info($"[Trust] '{item.FileName}' trust removed.");
            }
            catch (Exception ex)
            {
                _logService.Error($"Failed to remove trust for '{item.FileName}'", ex);
            }

            RaiseCanExecuteChanged();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

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