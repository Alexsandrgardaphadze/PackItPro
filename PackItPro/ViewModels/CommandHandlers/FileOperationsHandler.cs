// PackItPro/ViewModels/CommandHandlers/FileOperationsHandler.cs
// v2.3 — Memory leak fix: PropertyChanged subscription is now a named method
//         so it can be properly unsubscribed in Dispose().
//         The anonymous lambda in v2.1/v2.2 was never removed, keeping
//         FileOperationsHandler alive as long as FileListViewModel lived.
using PackItPro.Views;
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

            // FIX: Named method — can be unsubscribed in Dispose.
            // The old anonymous lambda was never removed, so FileListViewModel
            // held a reference to this handler for the entire process lifetime.
            _fileList.PropertyChanged += OnFileListPropertyChanged;
        }

        private void OnFileListPropertyChanged(
            object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(FileListViewModel.HasFiles))
                RaiseCanExecuteChanged();
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

            if (result.SuccessCount > 0 || result.SkippedCount > 0)
                FileAddResultWindow.Show(
                    Application.Current?.MainWindow,
                    result.SuccessCount,
                    result.SkippedCount,
                    result.SkipReasons);

            TriggerScanOnAddIfEnabled(result.SuccessCount);
        }

        // ── Clear All Files ───────────────────────────────────────────────────

        private void ExecuteClearAllFiles(object? parameter)
        {
            if (_fileList.Count == 0) return;

            bool confirmed = ConfirmDialog.Show(
                Application.Current?.MainWindow,
                "Clear File List",
                $"Remove all {_fileList.Count} file(s) from the list?",
                confirmLabel: "Clear All",
                cancelLabel: "Cancel",
                kind: ConfirmDialog.Kind.Danger);

            if (confirmed)
                _fileList.ClearAll();
        }

        // ── Export List ───────────────────────────────────────────────────────

        private void ExecuteExportList(object? parameter)
        {
            if (!_fileList.HasFiles)
            {
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Nothing to Export",
                    "No files in the list to export.",
                    kind: AlertDialog.Kind.Info);
                return;
            }

            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export File List",
                Filter = "CSV File (*.csv)|*.csv|Text File (*.txt)|*.txt",
                FileName = $"PackItPro_FileList_{DateTime.Now:yyyyMMdd_HHmmss}",
                DefaultExt = "csv",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (saveDialog.ShowDialog() != true) return;

            try
            {
                bool isCsv = Path.GetExtension(saveDialog.FileName)
                    .Equals(".csv", StringComparison.OrdinalIgnoreCase);

                string content = isCsv ? BuildCsvExport() : BuildTextExport();
                File.WriteAllText(saveDialog.FileName, content, Encoding.UTF8);

                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Export Complete",
                    $"File list exported — {_fileList.Count} file(s) listed.",
                    detail: saveDialog.FileName,
                    kind: AlertDialog.Kind.Success);
            }
            catch (Exception ex)
            {
                AlertDialog.Show(
                    Application.Current?.MainWindow,
                    "Export Failed",
                    $"Failed to export file list:\n{ex.Message}",
                    kind: AlertDialog.Kind.Error);
            }
        }

        // ── Scan-on-add ───────────────────────────────────────────────────────

        private void TriggerScanOnAddIfEnabled(int addedCount)
        {
            if (!_settings.ScanOnAdd) return;
            if (addedCount <= 0) return;
            if (!_scanFilesCommand.CanExecute(null)) return;

            _scanFilesCommand.Execute(null);
        }

        // ── Export builders ───────────────────────────────────────────────────

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
            sb.AppendLine("PackItPro — File List Export");
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

        private static string EscapeCsv(string value) =>
            value?.Replace("\"", "\"\"") ?? "";

        // ── Dispose ───────────────────────────────────────────────────────────

        public override void Dispose()
        {
            // FIX: Unsubscribe so FileListViewModel no longer holds a reference to us.
            _fileList.PropertyChanged -= OnFileListPropertyChanged;
            base.Dispose();
        }
    }
}