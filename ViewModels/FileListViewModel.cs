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
        public long TotalSize
        {
            get
            {
                try
                {
                    return _items.Sum(f => File.Exists(f.FilePath) ? new FileInfo(f.FilePath).Length : 0);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[FileListViewModel] Error calculating TotalSize: {ex.Message}");
                    return 0; // Fallback if any file access error occurs
                }
            }
        } // NEW: Handle exceptions in UI code-behind if needed
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

        // NEW: Result model for validation
        public class AddFilesResult
        {
            public int SuccessCount { get; set; }
            public int SkippedCount { get; set; }
            public List<string> SkipReasons { get; } = new();
        }

        // NEW: Method to add files with validation results
        public void AddFilesWithValidation(string[] paths, out AddFilesResult result)
        {
            result = new AddFilesResult();
            var skipReasons = new List<string>();

            if (_items.Count >= _settings.MaxFilesInList)
            {
                result.SkippedCount = paths.Length;
                result.SkipReasons.Add($"File limit reached ({_settings.MaxFilesInList} files maximum)");
                return;
            }

            var validFiles = paths
                .Where(p => 
                {
                    if (!File.Exists(p))
                    {
                        skipReasons.Add($"File not found: {Path.GetFileName(p)}");
                        return false;
                    }
                    return true;
                })
                .Select(p =>
                {
                    try
                    {
                        return new FileInfo(p);
                    }
                    catch (Exception ex)
                    {
                        skipReasons.Add($"Cannot access file: {Path.GetFileName(p)} ({ex.Message})");
                        return null;
                    }
                })
                .Where(fi => fi != null)
                .Where(fi =>
                {
                    if (fi!.Length == 0)
                    {
                        skipReasons.Add($"Zero-byte file: {fi.Name}");
                        return false;
                    }

                    // Only filter by extension if OnlyScanExecutables is TRUE
                    if (_settings.OnlyScanExecutables && !_executableExtensions.Contains(fi.Extension))
                    {
                        skipReasons.Add($"Non-executable file: {fi.Name} ({fi.Extension})");
                        return false;
                    }

                    return true;
                })
                .Select(fi => fi!.FullName)
                .Take(_settings.MaxFilesInList - _items.Count)
                .ToList();

            foreach (var file in validFiles)
            {
                var fileInfo = new FileInfo(file);
                var fileItem = new FileItemViewModel
                {
                    FileName = Path.GetFileName(file),
                    FilePath = file,
                    Size = FormatBytes(fileInfo.Length),
                    Status = FileStatusEnum.Pending,
                    Positives = 0,
                    TotalScans = 0
                };
                fileItem.RemoveCommand = new RelayCommand((param) => ExecuteRemoveFile(fileItem));
                _items.Add(fileItem);
            }

            result.SuccessCount = validFiles.Count;
            result.SkippedCount = skipReasons.Count;
            result.SkipReasons.AddRange(skipReasons);

            // Notify properties that depend on the list count/contents
            NotifyListChanged();
        }

        // Backward compatibility overload
        public void AddFilesWithValidation(string[] paths)
        {
            AddFilesWithValidation(paths, out _);
        }

        private void ExecuteAddFiles(object? parameter)
        {
            // Handle both cases: direct string[] (from drag-drop) and null (from button)
            if (parameter is string[] filePaths)
            {
                AddFilesWithValidation(filePaths);
            }
            // If no parameter, the button should trigger a file browser in MainViewModel instead
        }

        private void ExecuteClearAllFiles(object? parameter)
        {
            _items.Clear();
            NotifyListChanged();
        }

        private void ExecuteRemoveFile(FileItemViewModel item)
        {
            _items.Remove(item);
            NotifyListChanged();
        }

        /// <summary>
        /// Notifies UI of all list-dependent property changes.
        /// Call after any operation that modifies the file list.
        /// </summary>
        private void NotifyListChanged()
        {
            OnPropertyChanged(nameof(Count));
            OnPropertyChanged(nameof(TotalSize));
            OnPropertyChanged(nameof(HasFiles));
            OnPropertyChanged(nameof(HasInfectedFiles));
            OnPropertyChanged(nameof(CleanCount));
            OnPropertyChanged(nameof(InfectedCount));
            OnPropertyChanged(nameof(FailedCount));
            OnPropertyChanged(nameof(SkippedCount));
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