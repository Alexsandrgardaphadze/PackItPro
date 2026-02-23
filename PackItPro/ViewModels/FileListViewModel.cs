// ViewModels/FileListViewModel.cs - v2.6 SMALL ISSUES FIX
// Changes vs v2.5:
//   - Removed duplicate OnPropertyChanged declaration. The class had two:
//       protected virtual void OnPropertyChanged([CallerMemberName] string? ...)  ← correct
//       protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] ...)
//     The second (with the full namespace qualifier) shadowed the first and compiled
//     without error only because they had the same signature after resolution.
//     Kept the cleaner form with the using directive at the top.
//   - No logic changes.
using PackItPro.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    public class FileListViewModel : INotifyPropertyChanged, IDisposable
    {
        private readonly ObservableCollection<FileItemViewModel> _items = new();
        private readonly AppSettings _settings;
        private readonly HashSet<string> _executableExtensions;
        private long _cachedTotalSize = -1;
        private bool _disposed;

        public ObservableCollection<FileItemViewModel> Items => _items;
        public int Count => _items.Count;

        public long TotalSize
        {
            get
            {
                if (_cachedTotalSize == -1)
                {
                    _cachedTotalSize = 0;
                    foreach (var item in _items)
                    {
                        try
                        {
                            if (File.Exists(item.FilePath))
                                _cachedTotalSize += new FileInfo(item.FilePath).Length;
                        }
                        catch { /* File deleted between add and render — skip */ }
                    }
                }
                return _cachedTotalSize;
            }
        }

        public int CleanCount => _items.Count(f => f.Status == FileStatusEnum.Clean);
        public int InfectedCount => _items.Count(f => f.Status == FileStatusEnum.Infected);
        public int FailedCount => _items.Count(f => f.Status == FileStatusEnum.ScanFailed);
        public int SkippedCount => _items.Count(f => f.Status == FileStatusEnum.Skipped);
        public bool HasFiles => _items.Any();
        public bool HasInfectedFiles => _items.Any(f => f.Status == FileStatusEnum.Infected);

        public ICommand AddFilesCommand { get; }
        public ICommand ClearAllFilesCommand { get; }
        public ICommand RemoveFileCommand { get; }

        public FileListViewModel(AppSettings settings, HashSet<string> executableExtensions)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _executableExtensions = executableExtensions ?? throw new ArgumentNullException(nameof(executableExtensions));

            AddFilesCommand = new RelayCommand(ExecuteAddFiles);
            ClearAllFilesCommand = new RelayCommand(_ => ClearAll());
            RemoveFileCommand = new RelayCommand(ExecuteRemoveFile);

            _items.CollectionChanged += OnItemsCollectionChanged;
        }

        private void OnItemsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            _cachedTotalSize = -1;
            NotifyListChanged();
        }

        public void ClearAll() => _items.Clear();

        // ── AddFilesWithValidation ─────────────────────────────────────

        public class AddFilesResult
        {
            public int SuccessCount { get; set; }
            public int SkippedCount { get; set; }
            public List<string> SkipReasons { get; } = new();
        }

        public void AddFilesWithValidation(string[] paths, out AddFilesResult result)
        {
            result = new AddFilesResult();

            if (_items.Count >= _settings.MaxFilesInList)
            {
                result.SkippedCount = paths.Length;
                result.SkipReasons.Add($"File limit reached ({_settings.MaxFilesInList} files maximum)");
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
                    try { return new FileInfo(p); }
                    catch (Exception ex)
                    {
                        skipReasons.Add($"Cannot access: {Path.GetFileName(p)} ({ex.Message})");
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

                    if (_settings.OnlyScanExecutables &&
                        !_executableExtensions.Contains(fi.Extension))
                    {
                        skipReasons.Add($"Non-executable: {fi.Name} ({fi.Extension})");
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
                fileItem.RemoveCommand = new RelayCommand(_ => ExecuteRemoveFile(fileItem));
                _items.Add(fileItem);
            }

            result.SuccessCount = validFiles.Count;
            result.SkippedCount = skipReasons.Count;
            result.SkipReasons.AddRange(skipReasons);
        }

        public void AddFilesWithValidation(string[] paths)
            => AddFilesWithValidation(paths, out _);

        // ── Private command handlers ───────────────────────────────────

        private void ExecuteAddFiles(object? parameter)
        {
            if (parameter is string[] filePaths)
                AddFilesWithValidation(filePaths);
        }

        private void ExecuteRemoveFile(object? parameter)
        {
            if (parameter is FileItemViewModel item)
                _items.Remove(item);
        }

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

        private static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int i = 0;
            double size = bytes;
            while (size >= 1024 && i < suffixes.Length - 1) { size /= 1024; i++; }
            return $"{size:0.##} {suffixes[i]}";
        }

        // ── IDisposable ────────────────────────────────────────────────

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {
                _items.CollectionChanged -= OnItemsCollectionChanged;
                _items.Clear();
            }
            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // ── INotifyPropertyChanged ─────────────────────────────────────
        // FIX: single declaration — was duplicated with full namespace qualifier.

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}