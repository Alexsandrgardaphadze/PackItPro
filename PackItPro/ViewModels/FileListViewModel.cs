// PackItPro/ViewModels/FileListViewModel.cs
// v2.1 — Duplicate file detection (#4)
//   AddFilesWithValidation now checks for existing paths (OrdinalIgnoreCase)
//   before any other guard. Duplicates are reported as "already in list" in
//   SkipReasons so FileAddResultWindow surfaces them to the user.
//   No other logic changed.
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
        public int TrustedCount => _items.Count(f => f.Status == FileStatusEnum.Trusted);
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
                    // ── Duplicate check ──────────────────────────────────────
                    // Must be the FIRST guard: a file already in the list that
                    // has since been deleted from disk should report "already in
                    // list", not "file not found".
                    // OrdinalIgnoreCase because Windows paths are case-insensitive.
                    if (_items.Any(existing =>
                            string.Equals(existing.FilePath, p, StringComparison.OrdinalIgnoreCase)))
                    {
                        skipReasons.Add($"Already in list: {Path.GetFileName(p)}");
                        return false;
                    }

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
                    return true;
                })
                // Validate file type — only accepted installer/script types allowed in a package.
                // NOTE: OnlyScanExecutables affects SCANNING, not adding. All valid installer
                // types can always be added to the list.
                .Where(fi =>
                {
                    string ext = Path.GetExtension(fi!.Name).ToLowerInvariant();
                    if (_executableExtensions.Contains(ext))
                        return true;

                    skipReasons.Add($"Unsupported file type: {fi.Name} ({ext})\n  PackItPro packages installer files (.exe, .msi, .bat, .zip, etc.)");
                    return false;
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
                    TotalScans = 0,
                    InstallOrder = 0
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

        private void ExecuteAddFiles(object? parameter)
        {
            if (parameter is string[] filePaths)
                AddFilesWithValidation(filePaths);
        }

        private void ExecuteRemoveFile(object? parameter)
        {
            try
            {
                if (parameter is FileItemViewModel item && item != null && _items.Contains(item))
                    _items.Remove(item);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[FileListViewModel] Remove file failed: {ex.Message}");
            }
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
            OnPropertyChanged(nameof(TrustedCount));
        }

        private static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int i = 0;
            double size = bytes;
            while (size >= 1024 && i < suffixes.Length - 1) { size /= 1024; i++; }
            return $"{size:0.##} {suffixes[i]}";
        }

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

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}