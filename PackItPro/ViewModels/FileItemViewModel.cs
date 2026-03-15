// PackItPro/ViewModels/FileItemViewModel.cs
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
        private string _notes = "";          // NEW

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

        public int InstallOrder
        {
            get => _installOrder;
            set { _installOrder = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Optional free-text label for this file — install order hints, version notes, etc.
        /// Written into packitmeta.json so the stub can display it during installation.
        /// Editable inline in the file list Notes column.
        /// </summary>
        public string Notes
        {
            get => _notes;
            set { _notes = value ?? ""; OnPropertyChanged(); }
        }

        // ── Trust / false-positive properties ────────────────────────────────

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

        public bool FlaggedByTrustedEngine
        {
            get => _flaggedByTrustedEngine;
            set { _flaggedByTrustedEngine = value; OnPropertyChanged(); }
        }

        public string? TrustedEngineName
        {
            get => _trustedEngineName;
            set { _trustedEngineName = value; OnPropertyChanged(); OnPropertyChanged(nameof(TrustTooltip)); }
        }

        // ── Computed display properties ───────────────────────────────────────

        public string StatusDisplay
        {
            get
            {
                if (FlaggedByTrustedEngine) return $"⚠ MALWARE ({TrustedEngineName})";
                if (IsTrustedFalsePositive) return "✓ Trusted (FP)";
                return Status.ToString();
            }
        }

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