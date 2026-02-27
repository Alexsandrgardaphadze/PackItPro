// ViewModels/FileItemViewModel.cs - v3.1 SMALL ISSUES FIX
// Changes vs v3.0:
//   - FileTypeBadgeColor: was allocating a new SolidColorBrush on every property get.
//     WPF calls this on every render pass for every visible list row. Under scrolling
//     this produced continuous allocations and GC pressure.
//     Fix: static frozen brush dictionary — allocated once at startup, zero allocations
//     during scrolling.
//   - FileTypeIcon + FileTypeBadgeColor: both had duplicate extension switch statements.
//     Unified into a single static lookup table (FileTypeInfo) so extension metadata
//     lives in one place.
//   - Brushes are Frozen() for thread-safety and WPF rendering performance.
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
        // ── Static lookup table ────────────────────────────────────────
        // One entry per extension group. Brush frozen once at class init.
        // Adding a new file type: add one entry here, nothing else changes.

        private static readonly SolidColorBrush FallbackBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B))); // slate-500

        private sealed record FileTypeInfo(string Icon, SolidColorBrush Badge);

        private static SolidColorBrush Frozen(SolidColorBrush b) { b.Freeze(); return b; }

        private static readonly Dictionary<string, FileTypeInfo> ExtensionMap =
            new(System.StringComparer.OrdinalIgnoreCase)
            {
                [".exe"] = new("⚙️", Frozen(new SolidColorBrush(Color.FromRgb(0x63, 0x66, 0xF1)))), // indigo
                [".msi"] = new("📦", Frozen(new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)))), // emerald
                [".msp"] = new("🩹", Frozen(new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)))), // emerald
                [".dll"] = new("🔧", Frozen(new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)))), // amber
                [".bat"] = new("📜", Frozen(new SolidColorBrush(Color.FromRgb(0x8B, 0x5C, 0xF6)))), // violet
                [".cmd"] = new("📜", Frozen(new SolidColorBrush(Color.FromRgb(0x8B, 0x5C, 0xF6)))), // violet
                [".ps1"] = new("💻", Frozen(new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)))), // blue
                [".vbs"] = new("📝", Frozen(new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)))), // blue
                [".jar"] = new("☕", Frozen(new SolidColorBrush(Color.FromRgb(0xFB, 0x92, 0x3C)))), // orange
                [".zip"] = new("🗜️", Frozen(new SolidColorBrush(Color.FromRgb(0xEC, 0x48, 0x99)))), // pink
                [".7z"] = new("🗜️", Frozen(new SolidColorBrush(Color.FromRgb(0xEC, 0x48, 0x99)))), // pink
                [".rar"] = new("🗜️", Frozen(new SolidColorBrush(Color.FromRgb(0xEC, 0x48, 0x99)))), // pink
                [".msix"] = new("📦", Frozen(new SolidColorBrush(Color.FromRgb(0x06, 0xB6, 0xD4)))), // cyan
                [".appx"] = new("📦", Frozen(new SolidColorBrush(Color.FromRgb(0x06, 0xB6, 0xD4)))), // cyan
            };

        // ── Backing fields ─────────────────────────────────────────────

        private string _fileName = "";
        private string _filePath = "";
        private string _size = "";
        private FileStatusEnum _status = FileStatusEnum.Pending;
        private int _positives;
        private int _totalScans;

        // ── Properties ─────────────────────────────────────────────────

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
                // Both computed properties depend on FilePath
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
            set { _status = value; OnPropertyChanged(); }
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

        public ICommand? RemoveCommand { get; set; }

        // ── Computed — zero allocations on every call ─────────────────

        /// <summary>Emoji icon for the file type. Resolved from static table.</summary>
        public string FileTypeIcon
        {
            get
            {
                if (string.IsNullOrEmpty(FilePath)) return "📄";
                var ext = Path.GetExtension(FilePath);
                return ExtensionMap.TryGetValue(ext, out var info) ? info.Icon : "📄";
            }
        }

        /// <summary>
        /// Frozen brush for the file-type badge. Static — zero allocations per call.
        /// </summary>
        public Brush FileTypeBadgeColor
        {
            get
            {
                if (string.IsNullOrEmpty(FilePath)) return FallbackBrush;
                var ext = Path.GetExtension(FilePath);
                return ExtensionMap.TryGetValue(ext, out var info) ? info.Badge : FallbackBrush;
            }
        }

        // ── INotifyPropertyChanged ─────────────────────────────────────

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}