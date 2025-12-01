// ViewModels/FileListViewModel.cs
using PackItPro.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input; // For RelayCommand

namespace PackItPro.ViewModels
{
    public class FileListViewModel : INotifyPropertyChanged
    {
        private readonly ObservableCollection<FileItemViewModel> _items = new();
        private readonly AppSettings _settings; // NEW: Hold the AppSettings model, not the ViewModel
        private readonly HashSet<string> _executableExtensions; // NEW: Reference to allowed extensions

        // Expose the collection for binding
        public ObservableCollection<FileItemViewModel> Items => _items;

        // Properties derived from the list
        public int Count => _items.Count;
        public long TotalSize => _items.Sum(f => new FileInfo(f.FilePath).Length); // NEW: Handle exceptions in UI code-behind if needed
        public int CleanCount => _items.Count(f => f.Status == FileStatusEnum.Clean);
        public int InfectedCount => _items.Count(f => f.Status == FileStatusEnum.Infected);
        public int FailedCount => _items.Count(f => f.Status == FileStatusEnum.ScanFailed);
        public int SkippedCount => _items.Count(f => f.Status == FileStatusEnum.Skipped);
        public bool HasFiles => _items.Any();
        public bool HasInfectedFiles => _items.Any(f => f.Status == FileStatusEnum.Infected);

        // NEW: Accept AppSettings model and executable extensions
        public FileListViewModel(AppSettings settings, HashSet<string> executableExtensions)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _executableExtensions = executableExtensions ?? throw new ArgumentNullException(nameof(executableExtensions));

            AddFilesCommand = new RelayCommand(ExecuteAddFiles);
            ClearAllFilesCommand = new RelayCommand(ExecuteClearAllFiles);
            // RemoveFileCommand is more complex, often handled by the individual FileItemViewModel's RemoveCommand
            // Or, define it here if it takes the FileItemViewModel as a parameter
            // RemoveFileCommand = new RelayCommand(ExecuteRemoveFile);
        }

        // NEW: Command properties (example)
        public ICommand AddFilesCommand { get; }
        public ICommand ClearAllFilesCommand { get; }
        // public ICommand RemoveFileCommand { get; } // If defined per item, no need here.

        // NEW: Method to add files with validation (logic moved from MainWindow.xaml.cs)
        public void AddFilesWithValidation(string[] paths)
        {
            var validFiles = paths
                .Where(p => File.Exists(p))
                .Select(p => new FileInfo(p))
                .Where(fi =>
                {
                    if (fi.Length == 0)
                    {
                        MessageBox.Show($"Skipped zero-byte file: {fi.Name}",
                            "Invalid File", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    // NEW: Check file extension against allowed list using settings from the model
                    if (_settings.OnlyScanExecutables && !_executableExtensions.Contains(fi.Extension))
                    {
                        MessageBox.Show($"Skipped non-executable file (or unsupported type): {fi.Name}",
                            "File Type Not Allowed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return false;
                    }

                    return true;
                })
                .Select(fi => fi.FullName)
                .Take(20 - _items.Count)
                .ToList();

            foreach (var file in validFiles)
            {
                var fileInfo = new FileInfo(file);
                var fileItem = new FileItemViewModel
                {
                    FileName = Path.GetFileName(file),
                    FilePath = file,
                    Size = FormatBytes(fileInfo.Length),
                    Status = FileStatusEnum.Pending, // NEW: Use enum
                    // StatusColor will be handled by the converter in XAML
                    // RemoveCommand will be set after initialization
                    Positives = 0, // Initialize scan results
                    TotalScans = 0
                };
                // NEW: Set the command to remove this specific item from the list
                fileItem.RemoveCommand = new RelayCommand((param) => ExecuteRemoveFile(fileItem));
                _items.Add(fileItem);
            }

            if (paths.Length > validFiles.Count)
            {
                MessageBox.Show($"Added {validFiles.Count} files (limit reached or invalid files skipped)",
                    "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            // Notify properties that depend on the list count/contents
            OnPropertyChanged(nameof(Count));
            OnPropertyChanged(nameof(TotalSize));
            OnPropertyChanged(nameof(HasFiles));
            OnPropertyChanged(nameof(HasInfectedFiles));
            OnPropertyChanged(nameof(CleanCount));
            OnPropertyChanged(nameof(InfectedCount));
            OnPropertyChanged(nameof(FailedCount));
            OnPropertyChanged(nameof(SkippedCount));
        }

        private void ExecuteAddFiles(object? parameter)
        {
            // This should trigger the file dialog in the MainViewModel or be handled by a service
            // For now, just a placeholder command
            if (parameter is string[] filePaths)
            {
                AddFilesWithValidation(filePaths);
            }
        }

        private void ExecuteClearAllFiles(object? parameter)
        {
            _items.Clear();
        }

        private void ExecuteRemoveFile(FileItemViewModel item)
        {
            _items.Remove(item);
        }

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int suffixIndex = 0;
            double size = bytes;

            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }

            return $"{size:0.##} {suffixes[suffixIndex]}";
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}