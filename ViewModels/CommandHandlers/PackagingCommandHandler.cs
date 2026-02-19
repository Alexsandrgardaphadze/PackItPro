// ViewModels/CommandHandlers/PackagingCommandHandler.cs - v2.3 FIXED
using Microsoft.Win32;
using PackItPro.Services;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    /// <summary>
    /// Handles all packaging-related operations (Pack, Test Package)
    /// </summary>
    public class PackagingCommandHandler : CommandHandlerBase
    {
        private readonly FileListViewModel _fileList;
        private readonly SettingsViewModel _settings;
        private readonly StatusViewModel _status;
        private readonly ErrorViewModel _error;
        private readonly ILogService _log;

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

            PackCommand = new RelayCommand(async _ => await ExecutePackAsync(), CanExecutePack);
            TestPackageCommand = new RelayCommand(ExecuteTestPackage);

            // Subscribe to changes that affect CanExecute
            _fileList.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_fileList.HasFiles))
                    RaiseCanExecuteChanged();
            };

            _status.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_status.IsBusy))
                    RaiseCanExecuteChanged();
            };

            // FIX: Subscribe to Settings changes too — Pack button was broken
            // because it checked OutputLocation but never listened for changes!
            _settings.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_settings.OutputLocation))
                    RaiseCanExecuteChanged();
            };
        }

        // FIX: Made OutputLocation check optional — we validate it properly when Pack is clicked anyway
        private bool CanExecutePack(object? parameter) =>
            _fileList.HasFiles && !_status.IsBusy;

        private async Task ExecutePackAsync()
        {
            if (!CanExecutePack(null)) return;

            try
            {
                // Validate settings first (with clear error message)
                if (!_settings.ValidateSettings(out var errorMessage))
                {
                    _error.ShowError($"Invalid settings: {errorMessage}");
                    return;
                }

                // Show save dialog
                var saveDialog = new SaveFileDialog
                {
                    Filter = "PackItPro Executable (*.exe)|*.exe",
                    InitialDirectory = _settings.OutputLocation,
                    FileName = $"{_settings.OutputFileName ?? "Package"}_{DateTime.Now:yyyyMMdd_HHmmss}.exe",
                    DefaultExt = "exe",
                    AddExtension = true
                };

                if (saveDialog.ShowDialog() != true) return;

                // Set up status and progress reporting
                _status.SetStatusPacking();
                _status.Message = "Preparing to create package...";
                _status.ProgressPercentage = 0;

                var progress = new Progress<(int percentage, string message)>(report =>
                {
                    _status.ProgressPercentage = report.percentage;
                    _status.Message = report.message;
                    _log.Info($"Pack Progress: {report.percentage}% - {report.message}");
                });

                // Create package
                var outputPath = await Packager.CreatePackageAsync(
                    _fileList.Items.Select(f => f.FilePath).ToList(),
                    Path.GetDirectoryName(saveDialog.FileName) ?? _settings.OutputLocation,
                    Path.GetFileNameWithoutExtension(saveDialog.FileName),
                    _settings.RequiresAdmin,
                    _settings.UseLZMACompression,
                    progress,
                    _log
                );

                _status.SetStatusReady();
                _status.Message = "Package created successfully!";
                _status.ProgressPercentage = 100;

                MessageBox.Show(
                    $"Package created successfully!\n\nLocation: {outputPath}",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (FileNotFoundException fileEx) when (fileEx.Message.Contains("StubInstaller.exe"))
            {
                HandleStubMissingError();
            }
            catch (IOException ex) when (ex.Message.Contains("in use") || ex.Message.Contains("locked"))
            {
                _error.ShowErrorAsync(
                    "Cannot package: A file is locked or in use.\n\nSolution: Close programs using these files and try again.",
                    retryActionAsync: ExecutePackAsync
                );
                _log.Error("Packaging failed - file locked", ex);
            }
            catch (Exception ex)
            {
                _log.Error("Packaging failed", ex);
                _status.Message = $"Packaging failed: {ex.Message}";
                _error.ShowErrorAsync(
                    $"Failed to create package: {ex.Message}\n\nCheck logs for details.",
                    retryActionAsync: ExecutePackAsync
                );
            }
            finally
            {
                _status.SetStatusReady();
            }
        }

        private void ExecuteTestPackage(object? parameter)
        {
            MessageBox.Show(
                "Test package feature not yet implemented.",
                "Test Package",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void HandleStubMissingError()
        {
            var message = "StubInstaller.exe not found!\n\n" +
                         "To fix this:\n" +
                         "1. Ensure StubInstaller.exe exists in your project directory\n" +
                         "2. In Visual Studio:\n" +
                         "   - Right-click StubInstaller.exe in Solution Explorer\n" +
                         "   - Properties → 'Copy to Output Directory' = 'Copy always'\n" +
                         "3. Rebuild the solution";

            _error.ShowError(message);
            _log.Error("StubInstaller.exe missing", new FileNotFoundException("StubInstaller.exe not found"));
        }
    }
}