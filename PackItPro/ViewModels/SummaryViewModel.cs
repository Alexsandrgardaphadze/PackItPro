// PackItPro/ViewModels/SummaryViewModel.cs
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;

namespace PackItPro.ViewModels
{
    public class SummaryViewModel : INotifyPropertyChanged, IDisposable
    {
        private readonly FileListViewModel _fileListViewModel;
        private readonly SettingsViewModel _settingsViewModel;
        private bool _disposed;

        // Cached stub size so we're not hitting disk on every property change.
        // Lazily loaded on first access; null means not yet measured.
        private long? _cachedStubBytes;

        public SummaryViewModel(FileListViewModel fileListViewModel, SettingsViewModel settingsViewModel)
        {
            _fileListViewModel = fileListViewModel ?? throw new ArgumentNullException(nameof(fileListViewModel));
            _settingsViewModel = settingsViewModel ?? throw new ArgumentNullException(nameof(settingsViewModel));

            _fileListViewModel.PropertyChanged += OnFileListPropertyChanged;
            _settingsViewModel.PropertyChanged += OnSettingsPropertyChanged;
        }

        private void OnFileListPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName is nameof(FileListViewModel.Count)
                               or nameof(FileListViewModel.TotalSize)
                               or nameof(FileListViewModel.CleanCount)
                               or nameof(FileListViewModel.InfectedCount)
                               or nameof(FileListViewModel.FailedCount)
                               or nameof(FileListViewModel.SkippedCount))
            {
                NotifySummaryChanged();
            }
        }

        private void OnSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName is nameof(SettingsViewModel.RequiresAdmin)
                               or nameof(SettingsViewModel.CompressionLevel))
            {
                NotifySummaryChanged();
            }
        }

        private void NotifySummaryChanged()
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
            OnPropertyChanged(nameof(RequiresAdminText));
        }

        // ── File list summary ─────────────────────────────────────────────────

        public int Files => _fileListViewModel.Count;
        public long TotalSize => _fileListViewModel.TotalSize;
        public int CleanFiles => _fileListViewModel.CleanCount;
        public int InfectedFiles => _fileListViewModel.InfectedCount;
        public int FailedScans => _fileListViewModel.FailedCount;
        public int SkippedFiles => _fileListViewModel.SkippedCount;
        public string RequiresAdminText => _settingsViewModel.RequiresAdmin ? "Yes" : "No";

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

        // ── Size estimation ───────────────────────────────────────────────────

        /// <summary>
        /// Shows an honest output size estimate: real payload bytes + real stub bytes.
        /// Does NOT apply fake compression ratio multipliers — compression gain on
        /// .exe/.msi files (the primary use case) is near zero, so false estimates
        /// actively mislead users.
        /// </summary>
        public string EstimatedPackageSize
        {
            get
            {
                if (TotalSize == 0) return "Add files to see estimate";

                long stubBytes = GetStubSize();
                long payloadBytes = TotalSize;
                long totalBytes = payloadBytes + stubBytes;

                string compressionNote = _settingsViewModel.CompressionLevel switch
                {
                    0 => " (no compression)",
                    1 => " (may compress text/source files)",
                    2 => " (may compress text/source files further)",
                    3 => " (maximum — may compress text/source files further)",
                    _ => ""
                };

                if (stubBytes > 0)
                {
                    return $"~{FormatBytes(totalBytes)} total" +
                           $"\n{FormatBytes(payloadBytes)} payload  +  {FormatBytes(stubBytes)} stub" +
                           compressionNote;
                }

                // Stub not found — show payload-only estimate
                return $"~{FormatBytes(payloadBytes)} payload{compressionNote}";
            }
        }

        // ── Time estimation ───────────────────────────────────────────────────

        public string EstimatedTime
        {
            get
            {
                if (TotalSize == 0) return "—";

                // Rough estimate: compression at ~120 MB/s for Fast, ~50 MB/s for Max
                // plus ~3s for manifest/hash/inject overhead
                double mbPerSecond = _settingsViewModel.CompressionLevel switch
                {
                    0 => 500.0,  // Store-only: just IO
                    1 => 120.0,  // Deflate 6
                    2 => 70.0,   // Deflate 7
                    3 => 50.0,   // Deflate 9
                    _ => 120.0
                };

                double mb = TotalSize / (1024.0 * 1024.0);
                long estimatedSeconds = Math.Max(2, (long)(mb / mbPerSecond) + 3);

                if (estimatedSeconds < 60)
                    return $"~{estimatedSeconds} sec";

                long minutes = estimatedSeconds / 60;
                long seconds = estimatedSeconds % 60;
                return seconds > 0 ? $"~{minutes}m {seconds}s" : $"~{minutes} min";
            }
        }

        // ── Stub size helper ──────────────────────────────────────────────────

        private long GetStubSize()
        {
            if (_cachedStubBytes.HasValue) return _cachedStubBytes.Value;

            try
            {
                // Ask the same locator the Packager uses — consistent path resolution.
                // If it throws (stub not built yet), we return 0 and don't cache,
                // so it retries on the next property access.
                var stubPath = Services.StubLocator.FindStubInstaller(null);
                _cachedStubBytes = new FileInfo(stubPath).Length;
                return _cachedStubBytes.Value;
            }
            catch
            {
                return 0; // Stub not found yet — show payload-only estimate
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int i = 0;
            double size = bytes;
            while (size >= 1024 && i < suffixes.Length - 1) { size /= 1024; i++; }
            return $"{size:0.##} {suffixes[i]}";
        }

        // ── Disposal ──────────────────────────────────────────────────────────

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {
                _fileListViewModel.PropertyChanged -= OnFileListPropertyChanged;
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
