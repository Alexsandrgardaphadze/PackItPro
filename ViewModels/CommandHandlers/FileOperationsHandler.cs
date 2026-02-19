// ViewModels/CommandHandlers/FileOperationsHandler.cs
using Microsoft.Win32;
using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    /// <summary>
    /// Handles all file list operations (Browse, Clear, Export List)
    /// </summary>
    public class FileOperationsHandler : CommandHandlerBase
    {
        private readonly FileListViewModel _fileList;
        private readonly SettingsViewModel _settings;
        private readonly ICommand _scanFilesCommand;

        public ICommand BrowseFilesCommand { get; }
        public ICommand ClearAllFilesCommand { get; }
        public ICommand ExportListCommand { get; }

        public FileOperationsHandler(
            FileListViewModel fileList,
            SettingsViewModel settings,
            ICommand scanFilesCommand)
        {
            _fileList = fileList ?? throw new ArgumentNullException(nameof(fileList));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _scanFilesCommand = scanFilesCommand ?? throw new ArgumentNullException(nameof(scanFilesCommand));

            BrowseFilesCommand = new RelayCommand(ExecuteBrowseFiles);
            ClearAllFilesCommand = new RelayCommand(ExecuteClearAllFiles, CanExecuteClearAll);
            ExportListCommand = new RelayCommand(ExecuteExportList);

            _fileList.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_fileList.HasFiles))
                    RaiseCanExecuteChanged();
            };
        }

        private void ExecuteBrowseFiles(object? parameter)
        {
            var dialog = new OpenFileDialog
            {
                Multiselect = true,
                Title = "Select Files to Pack",
                Filter = "All Files (*.*)|*.*",
                CheckFileExists = true,
                CheckPathExists = true
            };

            if (dialog.ShowDialog() != true) return;

            _fileList.AddFilesWithValidation(dialog.FileNames, out var result);

            if (result.SkippedCount > 0)
            {
                var message = $"Added {result.SuccessCount} file(s).\n\n" +
                             $"Skipped {result.SkippedCount}:\n" +
                             string.Join("\n", result.SkipReasons.Take(3));

                if (result.SkipReasons.Count > 3)
                    message += $"\n...and {result.SkipReasons.Count - 3} more";

                MessageBox.Show(message, "Files Added", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            // Auto-scan if enabled
            if (_settings.ScanWithVirusTotal && !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
            {
                _scanFilesCommand.Execute(null);
            }
        }

        private void ExecuteClearAllFiles(object? parameter)
        {
            if (_fileList.Items.Count == 0) return;

            var result = MessageBox.Show(
                $"Remove all {_fileList.Items.Count} files from the list?",
                "Confirm Clear",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
                _fileList.ClearAllFilesCommand.Execute(null);
        }

        private bool CanExecuteClearAll(object? parameter) => _fileList.HasFiles;

        private void ExecuteExportList(object? parameter)
        {
            if (_fileList.Items.Count == 0)
            {
                MessageBox.Show(
                    "No files to export.",
                    "Export List",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                FileName = $"PackItPro_FileList_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                var content = string.Join("\n", _fileList.Items.Select(f => $"{f.FileName} - {f.Size}"));
                File.WriteAllText(dialog.FileName, content);

                MessageBox.Show(
                    $"File list exported to:\n{dialog.FileName}",
                    "Export Successful",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to export list: {ex.Message}",
                    "Export Failed",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}