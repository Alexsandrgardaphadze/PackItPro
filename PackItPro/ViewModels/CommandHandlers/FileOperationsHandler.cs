// PackItPro/ViewModels/CommandHandlers/FileOperationsHandler.cs
using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
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
            _scanFilesCommand = scanFilesCommand;

            BrowseFilesCommand = new RelayCommand(ExecuteBrowseFiles);
            ClearAllFilesCommand = new RelayCommand(ExecuteClearAllFiles, _ => _fileList.HasFiles);
            ExportListCommand = new RelayCommand(ExecuteExportList, _ => _fileList.HasFiles);

            _fileList.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(FileListViewModel.HasFiles))
                    RaiseCanExecuteChanged();
            };
        }

        // ── Browse Files ──────────────────────────────────────────────────────

        private void ExecuteBrowseFiles(object? parameter)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Add Files to Package",
                Multiselect = true,
                Filter = "All Files (*.*)|*.*" +
                              "|Executables (*.exe;*.msi)|*.exe;*.msi" +
                              "|Scripts (*.bat;*.cmd;*.ps1)|*.bat;*.cmd;*.ps1" +
                              "|Archives (*.zip;*.7z)|*.zip;*.7z"
            };

            if (dialog.ShowDialog() != true) return;

            _fileList.AddFilesWithValidation(dialog.FileNames, out var result);

            if (result.SkippedCount > 0)
            {
                var reasons = string.Join("\n  • ", result.SkipReasons);
                MessageBox.Show(
                    $"{result.SuccessCount} file(s) added.\n" +
                    $"{result.SkippedCount} file(s) skipped:\n\n  • {reasons}",
                    "Some Files Skipped",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }

        // ── Clear All Files ───────────────────────────────────────────────────

        private void ExecuteClearAllFiles(object? parameter)
        {
            if (_fileList.Count == 0) return;

            var result = MessageBox.Show(
                $"Remove all {_fileList.Count} file(s) from the list?",
                "Clear File List",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
                _fileList.ClearAll();
        }

        // ── Export List ───────────────────────────────────────────────────────
        // Saves the current file list as a CSV (usable in Excel) or plain text.

        private void ExecuteExportList(object? parameter)
        {
            if (!_fileList.HasFiles)
            {
                MessageBox.Show(
                    "No files in the list to export.",
                    "Nothing to Export",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export File List",
                Filter = "CSV File (*.csv)|*.csv|Text File (*.txt)|*.txt",
                FileName = $"PackItPro_FileList_{DateTime.Now:yyyyMMdd_HHmmss}",
                DefaultExt = "csv",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() != true) return;

            try
            {
                bool isCsv = Path.GetExtension(dialog.FileName)
                    .Equals(".csv", StringComparison.OrdinalIgnoreCase);

                string content = isCsv
                    ? BuildCsvExport()
                    : BuildTextExport();

                File.WriteAllText(dialog.FileName, content, Encoding.UTF8);

                MessageBox.Show(
                    $"File list exported to:\n{dialog.FileName}\n\n{_fileList.Count} file(s) listed.",
                    "Export Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to export file list:\n{ex.Message}",
                    "Export Failed",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private string BuildCsvExport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("File Name,File Path,Size,Status,Detections,Total Scans");

            foreach (var item in _fileList.Items)
            {
                sb.AppendLine(
                    $"\"{EscapeCsv(item.FileName)}\"," +
                    $"\"{EscapeCsv(item.FilePath)}\"," +
                    $"\"{EscapeCsv(item.Size)}\"," +
                    $"\"{item.Status}\"," +
                    $"{item.Positives}," +
                    $"{item.TotalScans}");
            }

            return sb.ToString();
        }

        private string BuildTextExport()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"PackItPro — File List Export");
            sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Files: {_fileList.Count}");
            sb.AppendLine(new string('-', 60));
            sb.AppendLine();

            int i = 1;
            foreach (var item in _fileList.Items)
            {
                sb.AppendLine($"{i++,3}. {item.FileName}");
                sb.AppendLine($"      Path:   {item.FilePath}");
                sb.AppendLine($"      Size:   {item.Size}");
                sb.AppendLine($"      Status: {item.Status}" +
                    (item.TotalScans > 0 ? $"  ({item.Positives}/{item.TotalScans} detections)" : ""));
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static string EscapeCsv(string value)
            => value?.Replace("\"", "\"\"") ?? "";
    }
}