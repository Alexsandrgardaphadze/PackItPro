// ViewModels/SummaryViewModel.cs
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace PackItPro.ViewModels
{
    public class SummaryViewModel : INotifyPropertyChanged
    {
        private readonly FileListViewModel _fileListViewModel;
        private readonly SettingsViewModel _settingsViewModel;

        public SummaryViewModel(FileListViewModel fileListViewModel, SettingsViewModel settingsViewModel)
        {
            _fileListViewModel = fileListViewModel ?? throw new ArgumentNullException(nameof(fileListViewModel));
            _settingsViewModel = settingsViewModel ?? throw new ArgumentNullException(nameof(settingsViewModel));

            // Subscribe to changes in the file list to update summary properties
            _fileListViewModel.PropertyChanged += OnFileListPropertyChanged;
            
            // Subscribe to settings changes for RequiresAdmin
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
                // Notify all dependent properties
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

        // ✅ Properties bound in XAML - all delegating to FileListViewModel
        public int Files => _fileListViewModel.Count;
        public long TotalSize => _fileListViewModel.TotalSize;
        public int CleanFiles => _fileListViewModel.CleanCount;
        public int InfectedFiles => _fileListViewModel.InfectedCount;
        public int FailedScans => _fileListViewModel.FailedCount;
        public int SkippedFiles => _fileListViewModel.SkippedCount;

        // ✅ NEW: Computed property for overall status
        public string Status
        {
            get
            {
                if (_fileListViewModel.HasInfectedFiles)
                    return "⚠️ Infected Files";
                
                if (_fileListViewModel.FailedCount > 0)
                    return "⚠️ Scan Errors";
                
                if (_fileListViewModel.Count == 0)
                    return "No Files";
                
                return "Ready";
            }
        }

        // ✅ NEW: Estimated package size (rough estimate: 80% of total due to compression)
        public string EstimatedPackageSize
        {
            get
            {
                if (TotalSize == 0)
                    return "~0 B";

                long estimatedSize = (long)(TotalSize * 0.8); // Assume 20% compression
                return $"~{FormatBytes(estimatedSize)}";
            }
        }

        // ✅ NEW: Estimated time (very rough: 1 second per MB + overhead)
        public string EstimatedTime
        {
            get
            {
                if (TotalSize == 0)
                    return "~0 sec";

                // Calculate: 1 second per MB + 5 seconds base overhead
                long megabytes = TotalSize / (1024 * 1024);
                long estimatedSeconds = megabytes + 5;

                if (estimatedSeconds < 60)
                    return $"~{Math.Max(1, estimatedSeconds)} sec";
                
                long minutes = estimatedSeconds / 60;
                long seconds = estimatedSeconds % 60;
                
                if (seconds > 0)
                    return $"~{minutes}m {seconds}s";
                
                return $"~{minutes} min";
            }
        }

        // ✅ NEW: Requires admin text (delegating to SettingsViewModel)
        public string RequiresAdminText => _settingsViewModel.RequiresAdmin ? "Yes" : "No";

        // ✅ Helper method for formatting bytes
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

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}