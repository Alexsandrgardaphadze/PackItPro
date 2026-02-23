// ViewModels/CommandHandlers/FileOperationsHandler.cs - v2.7 ULTIMATE
using Microsoft.Win32;
using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public class FileOperationsHandler : CommandHandlerBase
    {
        private readonly FileListViewModel _fileList;
        private readonly SettingsViewModel _settings;
        private readonly ICommand _scanFilesCommand;

        // ✅ Store ALL commands as fields for proper CanExecute refresh
        private readonly RelayCommand _browseFilesCommand;
        private readonly RelayCommand _clearAllFilesCommand;
        private readonly RelayCommand _exportListCommand;

        public ICommand BrowseFilesCommand => _browseFilesCommand;
        public ICommand ClearAllFilesCommand => _clearAllFilesCommand;
        public ICommand ExportListCommand => _exportListCommand;

        public FileOperationsHandler(
            FileListViewModel fileList,
            SettingsViewModel settings,
            ICommand scanFilesCommand)
        {
            _fileList = fileList ?? throw new ArgumentNullException(nameof(fileList));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _scanFilesCommand = scanFilesCommand ?? throw new ArgumentNullException(nameof(scanFilesCommand));

            _browseFilesCommand = new RelayCommand(ExecuteBrowseFiles);
            _clearAllFilesCommand = new RelayCommand(ExecuteClearAllFiles, CanExecuteClearAll);
            _exportListCommand = new RelayCommand(ExecuteExportList, CanExecuteExportList);

            // ✅ Subscribe to FileList changes and refresh COMMAND state
            _fileList.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_fileList.HasFiles))
                {
                    _clearAllFilesCommand.RaiseCanExecuteChanged();
                    _exportListCommand.RaiseCanExecuteChanged();
                }
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
                var message = $"Added {result.SuccessCount} file(s).\n\nSkipped {result.SkippedCount}:\n" +
                             string.Join("\n", result.SkipReasons.Take(3));
                if (result.SkipReasons.Count > 3)
                    message += $"\n...and {result.SkipReasons.Count - 3} more";
                MessageBox.Show(message, "Files Added", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            if (_settings.ScanWithVirusTotal && !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
                _scanFilesCommand.Execute(null);
        }

        private bool CanExecuteClearAll(object? parameter) => _fileList.HasFiles;

        private void ExecuteClearAllFiles(object? parameter)
        {
            if (!_fileList.HasFiles) return;

            var result = MessageBox.Show(
                $"Remove all {_fileList.Count} files?",
                "Confirm Clear",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
                _fileList.ClearAll();
        }

        private bool CanExecuteExportList(object? parameter) => _fileList.HasFiles;

        private void ExecuteExportList(object? parameter)
        {
            if (!_fileList.HasFiles)
            {
                MessageBox.Show("No files to export.", "Export List",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv",
                FileName = $"PackItPro_FileList_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                var content = string.Join("\n", _fileList.Items.Select(f => $"{f.FileName} - {f.Size}"));
                File.WriteAllText(dialog.FileName, content);
                MessageBox.Show($"List exported to:\n{dialog.FileName}", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}