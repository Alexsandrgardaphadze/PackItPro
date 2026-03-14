// PackItPro/ViewModels/CommandHandlers/PackagingCommandHandler.cs
using Microsoft.Win32;
using PackItPro.Models;
using PackItPro.Services;
using PackItPro.Views;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class PackagingCommandHandler : CommandHandlerBase
    {
        private readonly FileListViewModel _fileList;
        private readonly SettingsViewModel _settings;
        private readonly StatusViewModel _status;
        private readonly ErrorViewModel _error;
        private readonly ILogService _log;

        private CancellationTokenSource? _packCts;
        private string? _lastPackedFile; // used by TestPackageCommand

        public ICommand PackCommand { get; }
        public ICommand TestPackageCommand { get; }

        public PackagingCommandHandler(
            FileListViewModel fileList,
            SettingsViewModel settings,
            StatusViewModel status,
            ErrorViewModel error,
            ILogService log)
        {
            _fileList = fileList ?? throw new ArgumentNullException(nameof(fileList));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _status = status ?? throw new ArgumentNullException(nameof(status));
            _error = error ?? throw new ArgumentNullException(nameof(error));
            _log = log ?? throw new ArgumentNullException(nameof(log));

            PackCommand = new AsyncRelayCommand(ExecutePackAsync, CanExecutePack);
            TestPackageCommand = new RelayCommand(ExecuteTestPackage, CanTestPackage);

            _fileList.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_fileList.HasFiles)) RaiseCanExecuteChanged();
            };
            _status.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_status.IsBusy)) RaiseCanExecuteChanged();
            };
            _settings.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_settings.OutputLocation)) RaiseCanExecuteChanged();
            };
        }

        // ── Can Execute ───────────────────────────────────────────────────────

        private bool CanExecutePack(object? _) =>
            _fileList.HasFiles && !_status.IsBusy;

        private bool CanTestPackage(object? _) =>
            !string.IsNullOrEmpty(_lastPackedFile) && File.Exists(_lastPackedFile);

        // ── Pack ──────────────────────────────────────────────────────────────

        private async Task ExecutePackAsync(object? _)
        {
            if (!CanExecutePack(null)) return;

            bool succeeded = false;

            try
            {
                if (!_settings.ValidateSettings(out var settingsError))
                {
                    _error.ShowError($"Cannot create package: {settingsError}");
                    return;
                }

                // Show disclaimer on first pack. Once accepted with "do not show again"
                // ticked, it is saved to settings.json and suppressed on future packs.
                if (!_settings.SettingsModel.DisclaimerAccepted)
                {
                    int pendingCount = _fileList.Items.Count(f => f.Status == FileStatusEnum.Pending);
                    int scannedCount = _fileList.CleanCount + _fileList.InfectedCount + _fileList.FailedCount;
                    int trustedCount = _fileList.Items.Count(f => f.Status == FileStatusEnum.Trusted);

                    bool accepted = DisclaimerWindow.Show(
                        Application.Current?.MainWindow,
                        out bool suppress,
                        fileCount: _fileList.Count,
                        scannedCount: scannedCount,
                        infectedCount: _fileList.InfectedCount,
                        trustedCount: trustedCount,
                        requiresAdmin: _settings.SettingsModel.RequiresAdmin,
                        hasInfectedFiles: _fileList.HasInfectedFiles,
                        hasUnscannedFiles: pendingCount > 0);

                    if (!accepted) return;

                    if (suppress)
                    {
                        _settings.SettingsModel.DisclaimerAccepted = true;
                        _ = _settings.SaveSettingsAsync();
                    }
                }

                var saveDialog = new SaveFileDialog
                {
                    Filter = "PackItPro Executable (*.exe)|*.exe",
                    InitialDirectory = _settings.OutputLocation,
                    FileName = $"{_settings.OutputFileName ?? "Package"}_{DateTime.Now:yyyyMMdd_HHmmss}.exe",
                    DefaultExt = "exe",
                    AddExtension = true
                };

                if (saveDialog.ShowDialog() != true) return;

                _status.SetStatusPacking();
                _packCts = new CancellationTokenSource();

                var progress = new Progress<(int percentage, string message)>(report =>
                {
                    _status.ProgressPercentage = report.percentage;
                    _status.Message = report.message;
                    _log.Debug($"Pack {report.percentage}%: {report.message}");
                });

                string outputPath = await Packager.CreatePackageAsync(
                    filePaths: _fileList.Items.Select(f => f.FilePath).ToList(),
                    outputDirectory: Path.GetDirectoryName(saveDialog.FileName) ?? _settings.OutputLocation,
                    packageName: Path.GetFileNameWithoutExtension(saveDialog.FileName),
                    requiresAdmin: _settings.RequiresAdmin,
                    compressionLevel: _settings.CompressionLevel,
                    includeWingetUpdateScript: _settings.IncludeWingetUpdateScript,
                    progress: progress,
                    log: _log,
                    ct: _packCts.Token);

                _lastPackedFile = outputPath;
                succeeded = true;
                _settings.OutputFileName = string.Empty; // Reset for next package
                _status.SetStatusSuccess($"Package created — {Path.GetFileName(outputPath)}");
                RaiseCanExecuteChanged(); // enable TestPackageCommand

                // Windows toast — fires immediately; dialog appears after
                ToastService.NotifyPackageCreated(Path.GetFileName(outputPath), outputPath);

                bool openFolder = ConfirmDialog.Show(
                    Application.Current?.MainWindow,
                    "Package Created",
                    $"Package saved successfully.\n\n{outputPath}",
                    confirmLabel: "Open Folder",
                    cancelLabel: "Close",
                    kind: ConfirmDialog.Kind.Info);

                if (openFolder)
                    OpenFolderAndSelect(outputPath);
            }
            catch (OperationCanceledException)
            {
                _log.Info("Package creation cancelled.");
                _status.Message = "Packaging cancelled.";
            }
            catch (FileNotFoundException ex) when (
                ex.Message.Contains("StubInstaller") ||
                ex.FileName?.Contains("StubInstaller") == true)
            {
                HandleStubMissingError(ex);
            }
            catch (IOException ex) when (IsFileLocked(ex))
            {
                _log.Error("Packaging failed — file locked", ex);
                _error.ShowErrorAsync(
                    "Cannot create package: a file is locked by another program.\n\n" +
                    "Close any programs using your installer files and try again.",
                    retryActionAsync: () => ExecutePackAsync(null));
            }
            catch (IOException ex) when (IsDiskFull(ex))
            {
                _log.Error("Packaging failed — disk full", ex);
                _error.ShowError("Cannot create package: disk is full.\n\nFree up space and try again.");
            }
            catch (UnauthorizedAccessException ex)
            {
                _log.Error("Packaging failed — access denied", ex);
                _error.ShowErrorAsync(
                    "Cannot create package: access denied.\n\n" +
                    "Check write permissions on the output folder, or run PackItPro as Administrator.",
                    retryActionAsync: () => ExecutePackAsync(null));
            }
            catch (Exception ex)
            {
                _log.Error("Packaging failed", ex);
                _status.Message = "Packaging failed — see error panel.";
                _error.ShowErrorAsync(
                    $"Failed to create package.\n\nError: {ex.Message}\n\nCheck logs for details.",
                    retryActionAsync: () => ExecutePackAsync(null));
            }
            finally
            {
                _packCts?.Dispose();
                _packCts = null;
                if (!succeeded) _status.SetStatusReady();
            }
        }

        // ── Test Package ──────────────────────────────────────────────────────
        // Opens the folder containing the last packed file and selects it in Explorer.
        // This is the most useful "test" action short of running the installer —
        // it lets users immediately drag it to a VM, share it, or run it manually.

        private void ExecuteTestPackage(object? parameter)
        {
            // If we have a recently packed file, reveal it in Explorer
            if (!string.IsNullOrEmpty(_lastPackedFile) && File.Exists(_lastPackedFile))
            {
                OpenFolderAndSelect(_lastPackedFile);
                return;
            }

            // Otherwise let them browse to a .exe to open its folder
            var dialog = new OpenFileDialog
            {
                Title = "Select a PackItPro package to locate",
                Filter = "Executable Files (*.exe)|*.exe",
                InitialDirectory = _settings.OutputLocation,
            };

            if (dialog.ShowDialog() != true) return;

            if (File.Exists(dialog.FileName))
                OpenFolderAndSelect(dialog.FileName);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static void OpenFolderAndSelect(string filePath)
        {
            try
            {
                // /select highlights the specific file in Explorer
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{filePath}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Cannot Open Explorer",
                    "Could not open File Explorer.",
                    detail: filePath + "\n\n" + ex.Message,
                    kind: AlertDialog.Kind.Error);
            }
        }

        private void HandleStubMissingError(Exception ex)
        {
            _log.Error("StubInstaller.exe not found", ex);
            _error.ShowError(
                "StubInstaller.exe was not found.\n\n" +
                "Fix:\n" +
                "1. Run:  .\\build.ps1 -SkipPackItPro\n" +
                "   This publishes StubInstaller and copies it to Resources\\\n\n" +
                "2. Rebuild PackItPro.");
        }

        private static bool IsFileLocked(IOException ex)
        {
            int hr = ex.HResult & 0xFFFF;
            return hr is 0x20 or 0x21
                || ex.Message.Contains("being used by another process", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDiskFull(IOException ex)
        {
            int hr = ex.HResult & 0xFFFF;
            return hr is 0x70 or 0x27
                || ex.Message.Contains("disk full", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("not enough space", StringComparison.OrdinalIgnoreCase);
        }

        public override void Dispose()
        {
            _packCts?.Cancel();
            _packCts?.Dispose();
            base.Dispose();
        }
    }
}