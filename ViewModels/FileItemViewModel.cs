// PackItPro/ViewModels/FileItemViewModel.cs
using System;
using System.ComponentModel;
using System.IO;
using System.Windows.Input;
using PackItPro.Models;

namespace PackItPro.ViewModels
{
    public class FileItemViewModel : INotifyPropertyChanged
    {
        private string _fileName = string.Empty;
        private string _filePath = string.Empty;
        private string _size = "0 KB";
        private FileStatusEnum _status = FileStatusEnum.Pending;

        public int Positives { get; set; }
        public int TotalScans { get; set; }
        public ICommand RemoveCommand { get; set; } = null!;

        public string FileName
        {
            get => _fileName;
            set { _fileName = value; OnPropertyChanged(); }
        }

        public string FilePath
        {
            get => _filePath;
            set { _filePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(FileIcon)); }
        }

        public string Size
        {
            get => _size;
            set { _size = value; OnPropertyChanged(); }
        }

        public FileStatusEnum Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); OnPropertyChanged(nameof(StatusText)); OnPropertyChanged(nameof(IsInfected)); }
        }

        public string StatusText => _status switch
        {
            FileStatusEnum.Pending => "Pending Scan",
            FileStatusEnum.Clean => "Clean",
            FileStatusEnum.Infected => $"Infected ({Positives}/{TotalScans})",
            FileStatusEnum.ScanFailed => "Scan Failed",
            FileStatusEnum.Skipped => "Skipped Scan",
            _ => "Unknown"
        };

        public bool IsInfected => Status == FileStatusEnum.Infected;

        public string FileIcon => Path.GetExtension(FilePath).ToLowerInvariant() switch
        {
            ".exe" => "⚙️",
            ".msi" => "📦",
            ".zip" => "🗜️",
            ".appx" or ".msix" => "📱",
            _ => "📄"
        };

        public string StatusIcon => StatusText switch
        {
            var s when s.Contains("Infected") => "⚠️",
            "Clean" => "✅",
            "Pending Scan" => "⏳",
            "Scan Failed" => "❌",
            "Skipped Scan" => "⊝",
            _ => "❓"
        };

        public System.Windows.Media.SolidColorBrush StatusColor
        {
            get
            {
                return Status switch
                {
                    FileStatusEnum.Clean => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x10, 0xB9, 0x81)),
                    FileStatusEnum.Infected => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xEF, 0x44, 0x44)),
                    FileStatusEnum.ScanFailed => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xF5, 0x9E, 0x0B)),
                    FileStatusEnum.Skipped => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3B, 0x82, 0xF6)),
                    FileStatusEnum.Pending => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x3B, 0x82, 0xF6)),
                    _ => new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8))
                };
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}