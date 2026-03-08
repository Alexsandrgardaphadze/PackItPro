using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Media;
using PackItPro.Models;

namespace PackItPro.ViewModels
{
    public class FileItemViewModel : INotifyPropertyChanged
    {
        private static readonly SolidColorBrush FallbackBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)));

        private sealed record FileTypeInfo(string Icon, SolidColorBrush Badge);
        private static SolidColorBrush Frozen(SolidColorBrush b) { b.Freeze(); return b; }

        // Static lookup: one entry per extension. Brushes frozen at class init — zero allocations during rendering.
        private static readonly Dictionary<string, FileTypeInfo> ExtensionMap =
            new(System.StringComparer.OrdinalIgnoreCase)
            {
                [".exe"] = new("⚙️", Frozen(new SolidColorBrush(Color.FromRgb(0x63, 0x66, 0xF1)))),
                [".msi"] = new("📦", Frozen(new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)))),
                [".msp"] = new("🩹", Frozen(new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)))),
                [".dll"] = new("🔧", Frozen(new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)))),
                [".bat"] = new("📜", Frozen(new SolidColorBrush(Color.FromRgb(0x8B, 0x5C, 0xF6)))),
                [".cmd"] = new("📜", Frozen(new SolidColorBrush(Color.FromRgb(0x8B, 0x5C, 0xF6)))),
                [".ps1"] = new("💻", Frozen(new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)))),
                [".vbs"] = new("📝", Frozen(new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)))),
                [".jar"] = new("☕", Frozen(new SolidColorBrush(Color.FromRgb(0xFB, 0x92, 0x3C)))),
                [".zip"] = new("🗜️", Frozen(new SolidColorBrush(Color.FromRgb(0xEC, 0x48, 0x99)))),
                [".7z"] = new("🗜️", Frozen(new SolidColorBrush(Color.FromRgb(0xEC, 0x48, 0x99)))),
                [".rar"] = new("🗜️", Frozen(new SolidColorBrush(Color.FromRgb(0xEC, 0x48, 0x99)))),
                [".msix"] = new("📦", Frozen(new SolidColorBrush(Color.FromRgb(0x06, 0xB6, 0xD4)))),
                [".appx"] = new("📦", Frozen(new SolidColorBrush(Color.FromRgb(0x06, 0xB6, 0xD4)))),
            };

        // ── Backing fields ────────────────────────────────────────────────────

        private string _fileName = "";
        private string _filePath = "";
        private string _size = "";
        private FileStatusEnum _status = FileStatusEnum.Pending;
        private int _positives;
        private int _totalScans;
        private int _installOrder;
        private bool _isTrustedFalsePositive;
        private bool _flaggedByTrustedEngine;
        private string? _trustedEngineName;

        // ── Core properties ───────────────────────────────────────────────────

        public string FileName
        {
            get => _fileName;
            set { _fileName = value; OnPropertyChanged(); }
        }

        public string FilePath
        {
            get => _filePath;
            set
            {
                _filePath = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FileIcon));
                OnPropertyChanged(nameof(FileTypeIcon));
                OnPropertyChanged(nameof(FileTypeBadgeColor));
            }
        }

        public string Size
        {
            get => _size;
            set { _size = value; OnPropertyChanged(); }
        }

        public FileStatusEnum Status
        {
            get => _status;
            set
            {
                _status = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusDisplay));
            }
        }

        public int Positives
        {
            get => _positives;
            set { _positives = value; OnPropertyChanged(); }
        }

        public int TotalScans
        {
            get => _totalScans;
            set { _totalScans = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Install order for drag-to-reorder. Kept in sync with list position by
        /// FileListPanel.xaml.cs after every drop.
        /// </summary>
        public int InstallOrder
        {
            get => _installOrder;
            set { _installOrder = value; OnPropertyChanged(); }
        }

        // ── Trust / false-positive properties ────────────────────────────────

        /// <summary>
        /// True when the user has manually marked this file as a trusted false positive.
        /// Status is set to Clean when this flag is true; this property lets the UI
        /// distinguish "scanned clean" from "user-trusted FP".
        /// Persisted via TrustStore by file hash.
        /// </summary>
        public bool IsTrustedFalsePositive
        {
            get => _isTrustedFalsePositive;
            set
            {
                _isTrustedFalsePositive = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusDisplay));
                OnPropertyChanged(nameof(TrustTooltip));
            }
        }

        /// <summary>
        /// True when at least one trusted engine (Microsoft, Google, Kaspersky, etc.)
        /// flagged this file. MinimumDetectionsToFlag is bypassed — always treated as
        /// real malware and cannot be overridden by the user.
        /// </summary>
        public bool FlaggedByTrustedEngine
        {
            get => _flaggedByTrustedEngine;
            set { _flaggedByTrustedEngine = value; OnPropertyChanged(); }
        }

        /// <summary>Name of the trusted engine that flagged this file, for display in UI.</summary>
        public string? TrustedEngineName
        {
            get => _trustedEngineName;
            set { _trustedEngineName = value; OnPropertyChanged(); OnPropertyChanged(nameof(TrustTooltip)); }
        }

        // ── Computed display properties ───────────────────────────────────────

        /// <summary>
        /// Status label shown in the Status column. Reflects trust overrides:
        /// - Trusted engine detection → "⚠ MALWARE (EngineName)"
        /// - User-trusted FP → "✓ Trusted (FP)"
        /// - Otherwise → Status.ToString()
        /// </summary>
        public string StatusDisplay
        {
            get
            {
                if (FlaggedByTrustedEngine)
                    return $"⚠ MALWARE ({TrustedEngineName})";
                if (IsTrustedFalsePositive)
                    return "✓ Trusted (FP)";
                return Status.ToString();
            }
        }

        /// <summary>Tooltip shown on the trust badge in the file list.</summary>
        public string TrustTooltip
        {
            get
            {
                if (FlaggedByTrustedEngine)
                    return $"Flagged by {TrustedEngineName} — considered real malware. Cannot be overridden.";
                if (IsTrustedFalsePositive)
                    return "Marked as trusted false positive. Will be included in package.";
                return "";
            }
        }

        // Alias so existing XAML bindings using {Binding FileIcon} continue to work.
        public string FileIcon => FileTypeIcon;

        public string FileTypeIcon
        {
            get
            {
                if (string.IsNullOrEmpty(FilePath)) return "📄";
                var ext = Path.GetExtension(FilePath);
                return ExtensionMap.TryGetValue(ext, out var info) ? info.Icon : "📄";
            }
        }

        public Brush FileTypeBadgeColor
        {
            get
            {
                if (string.IsNullOrEmpty(FilePath)) return FallbackBrush;
                var ext = Path.GetExtension(FilePath);
                return ExtensionMap.TryGetValue(ext, out var info) ? info.Badge : FallbackBrush;
            }
        }

        public ICommand? RemoveCommand { get; set; }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
