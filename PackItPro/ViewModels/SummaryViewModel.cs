// ViewModels/SummaryViewModel.cs - v2.2
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace PackItPro.ViewModels
{
    public class SummaryViewModel : INotifyPropertyChanged, IDisposable
    {
        private readonly FileListViewModel _fileListViewModel;
        private readonly SettingsViewModel _settingsViewModel;
        private bool _disposed;

        public SummaryViewModel(FileListViewModel fileListViewModel, SettingsViewModel settingsViewModel)
        {
            _fileListViewModel = fileListViewModel ?? throw new ArgumentNullException(nameof(fileListViewModel));
            _settingsViewModel = settingsViewModel ?? throw new ArgumentNullException(nameof(settingsViewModel));

            _fileListViewModel.PropertyChanged += OnFileListPropertyChanged;
            _settingsViewModel.PropertyChanged += OnSettingsPropertyChanged;
        }

        private void OnFileListPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(_fileListViewModel.Items) ||
                e.PropertyName == nameof(_fileListViewModel.Count) ||
                e.PropertyName == nameof(_fileListViewModel.CleanCount) ||
                e.PropertyName == nameof(_fileListViewModel.InfectedCount) ||
                e.PropertyName == nameof(_fileListViewModel.FailedCount) ||
                e.PropertyName == nameof(_fileListViewModel.SkippedCount) ||
                e.PropertyName == nameof(_fileListViewModel.TotalSize))
            {
                OnPropertyChanged(nameof(Files));
                OnPropertyChanged(nameof(CleanFiles));
                OnPropertyChanged(nameof(InfectedFiles));
                OnPropertyChanged(nameof(FailedScans));
                OnPropertyChanged(nameof(SkippedFiles));
                OnPropertyChanged(nameof(TotalSize));
                OnPropertyChanged(nameof(Status));
                OnPropertyChanged(nameof(EstimatedPackageSize));
                OnPropertyChanged(nameof(EstimatedTime));
            }
        }

        private void OnSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(_settingsViewModel.RequiresAdmin))
            {
                OnPropertyChanged(nameof(RequiresAdminText));
            }
        }

        public int Files => _fileListViewModel.Count;
        public long TotalSize => _fileListViewModel.TotalSize;
        public int CleanFiles => _fileListViewModel.CleanCount;
        public int InfectedFiles => _fileListViewModel.InfectedCount;
        public int FailedScans => _fileListViewModel.FailedCount;
        public int SkippedFiles => _fileListViewModel.SkippedCount;

        public string Status
        {
            get
            {
                if (_fileListViewModel.HasInfectedFiles) return "⚠️ Infected Files";
                if (_fileListViewModel.FailedCount > 0) return "⚠️ Scan Errors";
                if (_fileListViewModel.Count == 0) return "No Files";
                return "Ready";
            }
        }

        public string EstimatedPackageSize
        {
            get
            {
                if (TotalSize == 0) return "~0 B";
                long estimatedSize = (long)(TotalSize * 0.8);
                return $"~{FormatBytes(estimatedSize)}";
            }
        }

        public string EstimatedTime
        {
            get
            {
                if (TotalSize == 0) return "~0 sec";

                long megabytes = TotalSize / (1024 * 1024);
                long estimatedSeconds = megabytes + 5;

                if (estimatedSeconds < 60)
                    return $"~{Math.Max(1, estimatedSeconds)} sec";

                long minutes = estimatedSeconds / 60;
                long seconds = estimatedSeconds % 60;
                return seconds > 0 ? $"~{minutes}m {seconds}s" : $"~{minutes} min";
            }
        }

        public string RequiresAdminText => _settingsViewModel.RequiresAdmin ? "Yes" : "No";

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int suffixIndex = 0;
            double size = bytes;
            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }
            return $"{size:0.##} {suffixes[suffixIndex]}";
        }

        // FIX: Proper disposal to prevent memory leaks
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                if (_fileListViewModel != null)
                    _fileListViewModel.PropertyChanged -= OnFileListPropertyChanged;

                if (_settingsViewModel != null)
                    _settingsViewModel.PropertyChanged -= OnSettingsPropertyChanged;
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