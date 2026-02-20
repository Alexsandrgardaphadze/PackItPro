// ViewModels/FileItemViewModel.cs - v3.0 POLISHED (Add these properties)
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
        private string _fileName = "";
        private string _filePath = "";
        private string _size = "";
        private FileStatusEnum _status = FileStatusEnum.Pending;
        private int _positives;
        private int _totalScans;

        public string FileName
        {
            get => _fileName;
            set
            {
                _fileName = value;
                OnPropertyChanged();
            }
        }

        public string FilePath
        {
            get => _filePath;
            set
            {
                _filePath = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FileTypeIcon));
                OnPropertyChanged(nameof(FileTypeBadgeColor));
            }
        }

        public string Size
        {
            get => _size;
            set
            {
                _size = value;
                OnPropertyChanged();
            }
        }

        public FileStatusEnum Status
        {
            get => _status;
            set
            {
                _status = value;
                OnPropertyChanged();
            }
        }

        public int Positives
        {
            get => _positives;
            set
            {
                _positives = value;
                OnPropertyChanged();
            }
        }

        public int TotalScans
        {
            get => _totalScans;
            set
            {
                _totalScans = value;
                OnPropertyChanged();
            }
        }

        public ICommand? RemoveCommand { get; set; }

        // ✨ NEW: File type icon based on extension
        public string FileTypeIcon
        {
            get
            {
                if (string.IsNullOrEmpty(FilePath))
                    return "📄";

                return Path.GetExtension(FilePath).ToLower() switch
                {
                    ".exe" => "⚙️",
                    ".msi" => "📦",
                    ".dll" => "🔧",
                    ".bat" => "📜",
                    ".cmd" => "📜",
                    ".ps1" => "💻",
                    ".vbs" => "📝",
                    ".jar" => "☕",
                    ".zip" => "🗜️",
                    ".7z" => "🗜️",
                    ".rar" => "🗜️",
                    _ => "📄"
                };
            }
        }

        // ✨ NEW: Badge color based on file type
        public Brush FileTypeBadgeColor
        {
            get
            {
                if (string.IsNullOrEmpty(FilePath))
                    return new SolidColorBrush(Color.FromRgb(100, 116, 139)); // Gray

                var ext = Path.GetExtension(FilePath).ToLower();
                return ext switch
                {
                    ".exe" => new SolidColorBrush(Color.FromRgb(99, 102, 241)),   // Blue #6366f1
                    ".msi" => new SolidColorBrush(Color.FromRgb(16, 185, 129)),   // Green #10b981
                    ".dll" => new SolidColorBrush(Color.FromRgb(245, 158, 11)),   // Orange #f59e0b
                    ".bat" => new SolidColorBrush(Color.FromRgb(139, 92, 246)),   // Purple #8b5cf6
                    ".cmd" => new SolidColorBrush(Color.FromRgb(139, 92, 246)),   // Purple #8b5cf6
                    ".ps1" => new SolidColorBrush(Color.FromRgb(59, 130, 246)),   // Light Blue #3b82f6
                    ".jar" => new SolidColorBrush(Color.FromRgb(251, 146, 60)),   // Coffee #fb923c
                    ".zip" or ".7z" or ".rar" => new SolidColorBrush(Color.FromRgb(236, 72, 153)), // Pink #ec4899
                    _ => new SolidColorBrush(Color.FromRgb(100, 116, 139))        // Gray #64748b
                };
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
