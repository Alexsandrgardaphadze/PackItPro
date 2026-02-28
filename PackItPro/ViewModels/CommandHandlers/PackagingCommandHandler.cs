using Microsoft.Win32;
using PackItPro.Services;
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
            TestPackageCommand = new RelayCommand(ExecuteTestPackage);

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

        private bool CanExecutePack(object? parameter) =>
            _fileList.HasFiles && !_status.IsBusy;

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

                var saveDialog = new SaveFileDialog
                {
                    Filter = "PackItPro Executable (*.exe)|*.exe",
                    InitialDirectory = _settings.OutputLocation,
                    FileName = $"{_settings.OutputFileName ?? "Package"}_{DateTime.Now:yyyyMMdd_HHmmss}.exe",
                    DefaultExt = "exe",
                    AddExtension = true
                };

                if (saveDialog.ShowDialog() != true) return;

                // Generate manifest and validate before packing starts
                string packageName = Path.GetFileNameWithoutExtension(saveDialog.FileName);
                var filePaths = _fileList.Items.Select(f => f.FilePath).ToList();

                try
                {
                    var manifestJson = ManifestGenerator.Generate(
                        filePaths,
                        packageName,
                        _settings.RequiresAdmin,
                        _settings.IncludeWingetUpdateScript);

                    var manifestObj = System.Text.Json.JsonSerializer.Deserialize<PackageManifest>(manifestJson)
                        ?? throw new InvalidOperationException("Failed to deserialize manifest.");

                    // Validate manifest before showing summary
                    ManifestValidator.Validate(manifestObj);

                    // Show summary to user
                    ShowPackagingSummary(packageName, filePaths);
                }
                catch (InvalidOperationException ex)
                {
                    _log.Error("Manifest validation failed", ex);
                    _error.ShowError($"Package configuration invalid:\n\n{ex.Message}");
                    return;
                }

                _status.SetStatusPacking();
                _packCts = new CancellationTokenSource();

                var progress = new Progress<(int percentage, string message)>(report =>
                {
                    _status.ProgressPercentage = report.percentage;
                    _status.Message = report.message;
                    _log.Debug($"Pack {report.percentage}%: {report.message}");
                });

                string outputPath = await Packager.CreatePackageAsync(
                    filePaths: filePaths,
                    outputDirectory: Path.GetDirectoryName(saveDialog.FileName) ?? _settings.OutputLocation,
                    packageName: packageName,
                    requiresAdmin: _settings.RequiresAdmin,
                    compressionLevel: _settings.CompressionLevel,
                    includeWingetUpdateScript: _settings.IncludeWingetUpdateScript,
                    progress: progress,
                    log: _log,
                    ct: _packCts.Token);

                succeeded = true;
                _status.SetStatusSuccess($"Package created — {Path.GetFileName(outputPath)}");

                MessageBox.Show(
                    $"Package created successfully!\n\nSaved to:\n{outputPath}",
                    "PackItPro — Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (OperationCanceledException)
            {
                _log.Info("Package creation cancelled by user.");
                _status.Message = "Packaging cancelled.";
            }
            catch (FileNotFoundException ex) when (
                ex.Message.Contains("StubInstaller.exe") ||
                ex.FileName?.Contains("StubInstaller") == true)
            {
                HandleStubMissingError(ex);
            }
            catch (IOException ex) when (IsFileLockedException(ex))
            {
                _log.Error("Packaging failed — file locked", ex);
                _error.ShowErrorAsync(
                    "Cannot create package: a file is locked by another program.\n\n" +
                    "Close any programs that might be using your installer files and try again.",
                    retryActionAsync: () => ExecutePackAsync(null));
            }
            catch (IOException ex) when (IsDiskFullException(ex))
            {
                _log.Error("Packaging failed — disk full", ex);
                _error.ShowError(
                    "Cannot create package: your disk is full or nearly full.\n\n" +
                    "Free up disk space and try again.");
            }
            catch (UnauthorizedAccessException ex)
            {
                _log.Error("Packaging failed — access denied", ex);
                _error.ShowErrorAsync(
                    "Cannot create package: access denied.\n\n" +
                    "Check that you have write permission in the output folder, " +
                    "or try running PackItPro as Administrator.",
                    retryActionAsync: () => ExecutePackAsync(null));
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("self-contained"))
            {
                _log.Error("Packaging failed — stub is framework-dependent", ex);
                _error.ShowError(
                    "StubInstaller.exe is a framework-dependent build and cannot be used.\n\n" +
                    "Fix:\n" +
                    "  cd StubInstaller\n" +
                    "  dotnet publish -c Release -r win-x64 --self-contained\n" +
                    "  copy publish\\StubInstaller.exe PackItPro\\Resources\\StubInstaller.exe\n\n" +
                    "Then rebuild PackItPro.");
            }
            catch (Exception ex)
            {
                _log.Error("Packaging failed", ex);
                _status.Message = "Packaging failed — see error panel.";
                _error.ShowErrorAsync(
                    $"Failed to create package.\n\nError: {ex.Message}\n\nCheck logs for full details.",
                    retryActionAsync: () => ExecutePackAsync(null));
            }
            finally
            {
                _packCts?.Dispose();
                _packCts = null;

                if (!succeeded)
                    _status.SetStatusReady();
            }
        }

        private void ShowPackagingSummary(string packageName, System.Collections.Generic.List<string> filePaths)
        {
            var summary = new PackagingSummaryViewModel();
            summary.UpdateFromSettings(
                packageName: packageName,
                fileCount: filePaths.Count,
                compressionMethod: _settings.SettingsModel.CompressionMethod,
                requiresAdmin: _settings.RequiresAdmin,
                includeWingetUpdater: _settings.IncludeWingetUpdateScript,
                verifyIntegrity: _settings.VerifyIntegrity,
                filePaths: filePaths);

            var msg = $"Package Summary\n" +
                      $"═══════════════════════════════════════\n" +
                      $"Name:                  {summary.PackageName}\n" +
                      $"Files:                 {summary.FileCount}\n" +
                      $"Estimated Size:        {summary.EstimatedSize}\n" +
                      $"Compression:           {summary.CompressionMethod}\n" +
                      $"Requires Admin:        {(summary.RequiresAdmin ? "Yes" : "No")}\n" +
                      $"Integrity Verification: {(summary.VerifyIntegrity ? "Yes" : "No")}\n" +
                      $"Winget Updater:        {(summary.IncludeWingetUpdater ? "Yes" : "No")}\n" +
                      $"═══════════════════════════════════════";

            _log.Info(msg);
        }

        private void ExecuteTestPackage(object? parameter)
        {
            MessageBox.Show(
                "Test package feature coming in Phase 2.",
                "PackItPro — Test Package",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void HandleStubMissingError(Exception ex)
        {
            _log.Error("StubInstaller.exe not found", ex);
            _error.ShowError(
                "StubInstaller.exe was not found.\n\n" +
                "To fix this:\n" +
                "1. Open a terminal in the solution root.\n" +
                "2. Run:\n" +
                "   cd StubInstaller\n" +
                "   dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true\n" +
                "3. Copy the output:\n" +
                "   copy publish\\StubInstaller.exe ..\\PackItPro\\Resources\\StubInstaller.exe\n" +
                "4. Rebuild PackItPro.");
        }

        private static bool IsFileLockedException(IOException ex)
        {
            int hResult = ex.HResult & 0xFFFF;
            return hResult is 0x20 or 0x21
                || ex.Message.Contains("being used by another process", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("locked", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDiskFullException(IOException ex)
        {
            int hResult = ex.HResult & 0xFFFF;
            return hResult is 0x70 or 0x27
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