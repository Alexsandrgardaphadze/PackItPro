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
        // Static lookup table: one entry per extension group.
        // Brushes are frozen once at class init — zero allocations during rendering.
        // Adding a new file type: add one entry here, nothing else changes.

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

        private string _fileName = "";
        private string _filePath = "";
        private string _size = "";
        private FileStatusEnum _status = FileStatusEnum.Pending;
        private int _positives;
        private int _totalScans;

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
        /// Frozen brush for the file-type badge. Static lookup — zero allocations per call.
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

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}