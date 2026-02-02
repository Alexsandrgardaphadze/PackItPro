// ViewModels/FileListViewModel.cs - OPTIMIZED VERSION
using PackItPro.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    public class FileListViewModel : INotifyPropertyChanged, IDisposable
    {
        private readonly ObservableCollection<FileItemViewModel> _items = new();
        private readonly AppSettings _settings;
        private readonly HashSet<string> _executableExtensions;

        // ✅ CACHED PROPERTIES (Performance optimization)
        private long _totalSize;
        private bool _disposed;

        // Expose the collection for binding
        public ObservableCollection<FileItemViewModel> Items => _items;

        // Properties derived from the list
        public int Count => _items.Count;

        // ✅ CACHED - No longer recalculates on every access
        public long TotalSize
        {
            get => _totalSize;
            private set
            {
                if (_totalSize != value)
                {
                    _totalSize = value;
                    OnPropertyChanged();
                }
            }
        }

        public int CleanCount => _items.Count(f => f.Status == FileStatusEnum.Clean);
        public int InfectedCount => _items.Count(f => f.Status == FileStatusEnum.Infected);
        public int FailedCount => _items.Count(f => f.Status == FileStatusEnum.ScanFailed);
        public int SkippedCount => _items.Count(f => f.Status == FileStatusEnum.Skipped);
        public bool HasFiles => _items.Any();
        public bool HasInfectedFiles => _items.Any(f => f.Status == FileStatusEnum.Infected);

        // Commands
        public ICommand AddFilesCommand { get; }
        public ICommand ClearAllFilesCommand { get; }
        public ICommand RemoveFileCommand { get; }

        public FileListViewModel(AppSettings settings, HashSet<string> executableExtensions)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _executableExtensions = executableExtensions ?? throw new ArgumentNullException(nameof(executableExtensions));

            AddFilesCommand = new RelayCommand(ExecuteAddFiles);
            ClearAllFilesCommand = new RelayCommand(ExecuteClearAllFiles);
            RemoveFileCommand = new RelayCommand(ExecuteRemoveFile);

            // ✅ FIX: Subscribe to collection changes to update cached properties
            _items.CollectionChanged += OnItemsCollectionChanged;
        }

        // ✅ FIX: Proper collection change handling
        private void OnItemsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            // Recalculate cached properties when collection changes
            RecalculateTotalSize();
            NotifyListChanged();
        }

        // ✅ OPTIMIZATION: Calculate total size once instead of on every access
        private void RecalculateTotalSize()
        {
            try
            {
                TotalSize = _items.Sum(f =>
                {
                    try
                    {
                        return File.Exists(f.FilePath) ? new FileInfo(f.FilePath).Length : 0;
                    }
                    catch
                    {
                        return 0; // Ignore individual file errors
                    }
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[FileListViewModel] Error calculating TotalSize: {ex.Message}");
                TotalSize = 0;
            }
        }

        /// <summary>
        /// Result model for validation
        /// </summary>
        public class AddFilesResult
        {
            public int SuccessCount { get; set; }
            public int SkippedCount { get; set; }
            public List<string> SkipReasons { get; } = new();
        }

        /// <summary>
        /// Adds files with validation and returns result
        /// </summary>
        public void AddFilesWithValidation(string[] paths, out AddFilesResult result)
        {
            result = new AddFilesResult();

            // ✅ FIX: Early return now adds message to result
            if (_items.Count >= _settings.MaxFilesInList)
            {
                result.SkippedCount = paths.Length;
                var message = $"File limit reached ({_settings.MaxFilesInList} files maximum)";
                result.SkipReasons.Add(message); // ✅ Fixed: Add directly to result
                return;
            }

            var skipReasons = new List<string>();

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

            // Collection change will trigger NotifyListChanged via event handler
        }

        /// <summary>
        /// Backward compatibility overload
        /// </summary>
        public void AddFilesWithValidation(string[] paths)
        {
            AddFilesWithValidation(paths, out _);
        }

        private void ExecuteAddFiles(object? parameter)
        {
            if (parameter is string[] filePaths)
            {
                AddFilesWithValidation(filePaths);
            }
        }

        private void ExecuteClearAllFiles(object? parameter)
        {
            _items.Clear();
            // Collection change will trigger NotifyListChanged via event handler
        }

        private void ExecuteRemoveFile(object? parameter)
        {
            if (parameter is FileItemViewModel item)
            {
                _items.Remove(item);
                // Collection change will trigger NotifyListChanged via event handler
            }
        }

        /// <summary>
        /// Notifies UI of all list-dependent property changes
        /// ✅ OPTIMIZED: Now uses batch notification
        /// </summary>
        private void NotifyListChanged()
        {
            // Batch notification - tells UI all properties changed
            OnPropertyChanged(nameof(Count));
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

        // ✅ FIX: Proper disposal to prevent memory leaks
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Unsubscribe from events
                _items.CollectionChanged -= OnItemsCollectionChanged;

                // Clear items
                _items.Clear();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
