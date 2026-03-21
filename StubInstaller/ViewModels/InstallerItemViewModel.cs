// StubInstaller/ViewModels/InstallerItemViewModel.cs
// One row in the app selection list.
// Constructed from a ManifestFile + the size of the extracted file on disk.
using System.IO;

namespace StubInstaller.ViewModels
{
    public enum InstallItemStatus
    {
        Waiting,     // not yet started
        Installing,  // currently running
        Done,        // completed successfully
        Failed,      // non-zero exit code or exception
        Skipped,     // user unchecked, or skipped due to missing file
    }

    public class InstallerItemViewModel : ViewModelBase
    {
        // ── Identity ─────────────────────────────────────────────────────────

        /// <summary>Raw filename — used as the install path key.</summary>
        public string FileName { get; }

        /// <summary>
        /// Display name shown in the UI.
        /// Uses ManifestFile.ResolvedDisplayName (ProductName → FileDescription → filename).
        /// </summary>
        public string DisplayName { get; }

        /// <summary>Optional per-file note from PackItPro. Shown as italic subtitle.</summary>
        public string? Notes { get; }

        /// <summary>Installer type string ("msi", "inno", "nsis", etc.).</summary>
        public string InstallType { get; }

        /// <summary>
        /// How the installer type was determined.
        /// "header" or "manifest" = reliable; "extension" = lower confidence.
        /// </summary>
        public string DetectionSource { get; }

        /// <summary>File size in bytes. -1 if the file wasn't found on disk.</summary>
        public long FileSizeBytes { get; }

        // ── Computed display helpers ──────────────────────────────────────────

        /// <summary>Formatted file size string, e.g. "47.3 MB".</summary>
        public string FileSizeDisplay => FileSizeBytes >= 0
            ? FormatBytes(FileSizeBytes)
            : "unknown";

        /// <summary>
        /// Short badge label for the installer type, e.g. "MSI", "NSIS", "Inno".
        /// Shown in the row next to the checkbox.
        /// </summary>
        public string TypeBadge => InstallType.ToUpperInvariant() switch
        {
            "MSI" => "MSI",
            "MSP" => "MSP",
            "INNO" => "Inno",
            "NSIS" => "NSIS",
            "SQUIRREL" => "Squirrel",
            "BURN" => "WiX",
            "APPX" => "APPX",
            "MSIX" => "MSIX",
            "FILE" => "File",
            _ => "EXE",
        };

        /// <summary>
        /// True when the detection source is reliable (header scan or user-set).
        /// False = extension-only guess. Used to tint the type badge amber vs green.
        /// </summary>
        public bool IsDetectionReliable =>
            DetectionSource is "header" or "manifest";

        /// <summary>Human-readable detection source for the tooltip.</summary>
        public string DetectionSourceDisplay => DetectionSource switch
        {
            "header" => "Header scan ✅",
            "manifest" => "User-specified ✅",
            _ => "Extension only ⚠️",
        };

        /// <summary>
        /// VirusTotal scan result from the manifest ("Clean", "Infected", "Unscanned").
        /// Shown as a badge on each row and in the tooltip.
        /// </summary>
        public string VtStatus { get; }

        /// <summary>Human-readable VT status for the tooltip.</summary>
        public string VtStatusDisplay => VtStatus switch
        {
            "Clean" => "Clean (no detections)",
            "Infected" => "⚠️ Detections found!",
            _ => "Not scanned",
        };

        // ── Mutable UI state ─────────────────────────────────────────────────

        private bool _isSelected = true;
        /// <summary>
        /// Whether this app is selected for installation.
        /// Defaults to true — user must actively opt out.
        /// Raises PropertyChanged so the parent VM can recalculate totals.
        /// </summary>
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (SetField(ref _isSelected, value))
                    OnPropertyChanged(nameof(IsSelectedAndWaiting));
            }
        }

        private InstallItemStatus _status = InstallItemStatus.Waiting;
        public InstallItemStatus Status
        {
            get => _status;
            set
            {
                if (SetField(ref _status, value))
                {
                    OnPropertyChanged(nameof(StatusText));
                    OnPropertyChanged(nameof(IsRunning));
                    OnPropertyChanged(nameof(IsDone));
                    OnPropertyChanged(nameof(IsFailed));
                    OnPropertyChanged(nameof(IsSelectedAndWaiting));
                }
            }
        }

        private string _statusDetail = string.Empty;
        /// <summary>Extra detail shown under the status badge, e.g. "Exit code: 1603".</summary>
        public string StatusDetail
        {
            get => _statusDetail;
            set => SetField(ref _statusDetail, value);
        }

        // ── Computed status helpers ───────────────────────────────────────────

        public string StatusText => Status switch
        {
            InstallItemStatus.Waiting => "Waiting",
            InstallItemStatus.Installing => "Installing...",
            InstallItemStatus.Done => "Done",
            InstallItemStatus.Failed => "Failed",
            InstallItemStatus.Skipped => "Skipped",
            _ => string.Empty,
        };

        public bool IsRunning => Status == InstallItemStatus.Installing;
        public bool IsDone => Status == InstallItemStatus.Done;
        public bool IsFailed => Status == InstallItemStatus.Failed;

        /// <summary>
        /// True when the item is checked AND hasn't run yet.
        /// Used to compute the "X of Y selected" summary line.
        /// </summary>
        public bool IsSelectedAndWaiting => IsSelected && Status == InstallItemStatus.Waiting;

        // ── Constructor ───────────────────────────────────────────────────────

        public InstallerItemViewModel(ManifestFile file, string tempDir)
        {
            FileName = file.Name;
            DisplayName = file.ResolvedDisplayName;
            Notes = string.IsNullOrWhiteSpace(file.Notes) ? null : file.Notes;
            InstallType = file.InstallType;
            DetectionSource = file.DetectionSource;

            string fullPath = Path.Combine(tempDir, file.Name);
            FileSizeBytes = File.Exists(fullPath)
                ? new FileInfo(fullPath).Length
                : -1;

            VtStatus = file.ScanResult switch
            {
                "clean" => "Clean",
                "infected" => "Infected",
                _ => "Unscanned",
            };
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return $"{v:0.#} {units[i]}";
        }
    }
}
