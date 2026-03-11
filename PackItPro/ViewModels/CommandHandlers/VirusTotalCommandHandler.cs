// PackItPro/ViewModels/CommandHandlers/VirusTotalCommandHandler.cs - v2.4 (TRUST STORE FIX)
// Changes vs v2.3:
//   [1] TrustStore injected via constructor — trusted files are now SKIPPED during scanning.
//       Previously the handler had no reference to TrustStore, so every scan would re-flag
//       files the user had already marked as false positives. Files whose SHA-256 hash is in
//       TrustStore are now marked FileStatusEnum.Trusted and counted as "skipped (trusted)".
//   [2] Hash computation is done inline using SHA256 on the file path, consistent with how
//       MarkTrustCommandHandler computes hashes before calling TrustStore.TrustAsync.
//   [3] Trusted-file skip is logged so users can verify the behaviour in packitpro.log.
using PackItPro.Models;
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
        private readonly TrustStore _trustStore;                 // NEW — injected
        private readonly ILogService _logService;
        private readonly HashSet<string> _executableExtensions;

        // Cancellation support
        private CancellationTokenSource? _scanCts;
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
            TrustStore trustStore,                               // NEW parameter
            ILogService logService,
            HashSet<string> executableExtensions)
        {
            _fileList = fileList ?? throw new ArgumentNullException(nameof(fileList));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _error = error ?? throw new ArgumentNullException(nameof(error));
            _virusTotalClient = virusTotalClient ?? throw new ArgumentNullException(nameof(virusTotalClient));
            _trustStore = trustStore ?? throw new ArgumentNullException(nameof(trustStore));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _executableExtensions = executableExtensions ?? throw new ArgumentNullException(nameof(executableExtensions));

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
            _settings.ScanWithVirusTotal &&
            _fileList.HasFiles &&
            !_status.IsBusy &&
            !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey);

        private bool CanCancelScan(object? parameter) =>
            _status.IsBusy && _scanCts != null;

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
                    retryAction: () => _ = ExecuteScanFilesCommandAsync(parameter));
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
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "No Files to Scan",
                    "No scannable files found.\n\nEnable 'Scan all files' in settings to include non-executables.",
                    kind: AlertDialog.Kind.Info);
                return;
            }

            _scanCts?.Cancel();
            _scanCts = new CancellationTokenSource();
            var ct = _scanCts.Token;

            ToastService.NotifyScanStarted(totalFiles);
            _status.Message = $"Scanning {totalFiles} file(s) with VirusTotal...";

            int processed = 0, failedCount = 0, skippedCount = 0, trustedCount = 0;
            var infectedFiles = new List<FileItemViewModel>();

            foreach (var item in _fileList.Items)
            {
                ct.ThrowIfCancellationRequested();

                // ── Extension filter ─────────────────────────────────────────
                if (_settings.OnlyScanExecutables &&
                    !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                {
                    item.Status = FileStatusEnum.Skipped;
                    skippedCount++;
                    processed++;
                    _status.Message = $"Scanning {totalFiles} file(s)... ({skippedCount} skipped)";
                    UpdateProgress(processed, totalFiles);
                    continue;
                }

                // ── Trust Store check ────────────────────────────────────────
                // Compute the file's SHA-256 and check the store before making
                // any API call. This is the same hash MarkTrustCommandHandler
                // stores, so the comparison is always apples-to-apples.
                try
                {
                    string hash = await ComputeSha256Async(item.FilePath, ct);

                    if (_trustStore.IsTrusted(hash))
                    {
                        item.Status = FileStatusEnum.Trusted;
                        trustedCount++;
                        processed++;
                        _logService.Info($"[TrustStore] Skipping trusted file '{item.FileName}' (hash: {hash[..16]}...)");
                        UpdateProgress(processed, totalFiles);
                        continue;
                    }

                    // ── VirusTotal API call ──────────────────────────────────
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

                    _logService.Info($"Scanned '{item.FileName}': {result.Positives}/{result.TotalScans} detections — {item.Status}");
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
                    UpdateProgress(processed, totalFiles);
                }
            }

            // ── Results summary ───────────────────────────────────────────────
            var owner = Application.Current?.MainWindow;

            if (infectedFiles.Count > 0)
            {
                if (_settings.AutoRemoveInfectedFiles)
                    foreach (var file in infectedFiles)
                        _fileList.Items.Remove(file);

                ToastService.NotifyScanThreatsFound(infectedFiles.Count, totalFiles);
                ScanResultsWindow.ShowInfected(owner, infectedFiles.Count, totalFiles, _settings.AutoRemoveInfectedFiles);
            }
            else if (failedCount > 0)
            {
                ScanResultsWindow.ShowErrors(owner, failedCount, totalFiles);
            }
            else
            {
                // Exclude both extension-skipped and trust-skipped from the "clean" count
                ToastService.NotifyScanClean(totalFiles - skippedCount - trustedCount);
                ScanResultsWindow.ShowClean(owner, totalFiles, skippedCount + trustedCount);
            }

            await _virusTotalClient.SaveCacheAsync(_logService);

            // Build a meaningful completion message
            var parts = new List<string>();
            if (failedCount > 0) parts.Add($"{failedCount} error(s)");
            if (trustedCount > 0) parts.Add($"{trustedCount} trusted (skipped)");
            if (skippedCount > 0) parts.Add($"{skippedCount} non-exe skipped");

            _status.Message = parts.Count > 0
                ? $"Scan completed — {string.Join(", ", parts)}. Check log."
                : "Scan completed successfully.";
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /// <summary>
        /// Computes the SHA-256 hash of a file asynchronously on the thread pool.
        /// Returns a lowercase hex string, consistent with MarkTrustCommandHandler.
        /// </summary>
        private static Task<string> ComputeSha256Async(string filePath, CancellationToken ct) =>
            Task.Run(() =>
            {
                using var sha = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hashBytes = sha.ComputeHash(stream);
                return Convert.ToHexString(hashBytes).ToLowerInvariant();
            }, ct);

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