// PackItPro/ViewModels/FileItemViewModel.cs
// CHANGE: Notes -> CustomArgs
// The "Notes" field was informational only. CustomArgs lets the user override
// the auto-detected silent arguments per file. The stub uses these in preference
// to the auto-detected ones when present.
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

        /// <summary>
        /// Optional custom silent install arguments entered by the user.
        /// When non-empty, these are passed to the stub instead of the
        /// auto-detected defaults (e.g. "/S /D=C:\MyApp" for NSIS).
        /// Stored in the manifest's <c>customArgs</c> field.
        /// </summary>
        private string _customArgs = "";

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
        /// User-supplied custom silent arguments for this installer.
        /// Overrides auto-detected args when non-empty.
        /// Example: "/S /D=%ProgramFiles%\MyApp" for NSIS.
        /// Editable inline in the file list Args column.
        /// </summary>
        public string CustomArgs
        {
            get => _customArgs;
            set
            {
                _customArgs = value ?? "";
                OnPropertyChanged();
                OnPropertyChanged(nameof(HasCustomArgs));
            }
        }

        /// <summary>True when the user has provided custom args for this file.</summary>
        public bool HasCustomArgs => !string.IsNullOrWhiteSpace(_customArgs);

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

        // ── Computed display ──────────────────────────────────────────────────

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
