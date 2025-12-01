// ViewModels/FileItemViewModel.cs
using System;
using System.ComponentModel;
using System.IO; // For Path
using System.Windows.Input; // For ICommand
using System.Windows.Media; // For SolidColorBrush

namespace PackItPro.ViewModels
{
    public class FileItemViewModel : INotifyPropertyChanged
    {
        private string _fileName = string.Empty;
        private string _filePath = string.Empty;
        private string _size = "0 KB";
        private FileStatusEnum _status = FileStatusEnum.Pending;
        // NEW: Remove direct StatusColor property, use converter in XAML
        // private SolidColorBrush _statusColor = Brushes.Gray;

        // NEW: Properties for scan results (to be updated by MainViewModel after scan)
        public int Positives { get; set; }
        public int TotalScans { get; set; }

        // ICommand for remove button (assigned by MainViewModel)
        public ICommand RemoveCommand { get; set; } = null!;

        public string FileName
        {
            get => _fileName;
            set { _fileName = value; OnPropertyChanged(); }
        }

        public string FilePath
        {
            get => _filePath;
            set { _filePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(FileIcon)); } // NEW: Notify FileIcon changed
        }

        public string Size
        {
            get => _size;
            set { _size = value; OnPropertyChanged(); }
        }

        public FileStatusEnum Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); OnPropertyChanged(nameof(StatusText)); OnPropertyChanged(nameof(IsInfected)); } // NEW: Notify StatusText and IsInfected changed
        }

        // NEW: StatusText is the display text for the UI, derived from Status enum
        public string StatusText => _status switch
        {
            FileStatusEnum.Pending => "Pending Scan",
            FileStatusEnum.Clean => "Clean",
            FileStatusEnum.Infected => $"Infected ({Positives}/{TotalScans})",
            FileStatusEnum.ScanFailed => "Scan Failed",
            FileStatusEnum.Skipped => "Skipped Scan",
            _ => "Unknown"
        };

        // NEW: IsInfected is now calculated based on Status
        public bool IsInfected => Status == FileStatusEnum.Infected;

        // NEW: Add FileIcon property (calculated based on FilePath)
        public string FileIcon => Path.GetExtension(FilePath).ToLower() switch
        {
            ".exe" => "⚙️",
            ".msi" => "📦",
            ".zip" => "🗜️",
            ".appx" => "📱",
            ".msix" => "📱",
            _ => "📄"
        };

        // NEW: Add StatusIcon property (calculated based on StatusText)
        public string StatusIcon => StatusText switch
        {
            var s when s.Contains("Infected") => "⚠️",
            "Clean" => "✅",
            "Pending Scan" => "⏳",
            "Scan Failed" => "❌",
            "Skipped Scan" => "⊝",
            _ => "❓"
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    // NEW: Enum for file status (defined here or shared)
    public enum FileStatusEnum
    {
        Pending,
        Clean,
        Infected,
        ScanFailed,
        Skipped
    }
}