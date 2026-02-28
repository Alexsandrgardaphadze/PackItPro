using PackItPro.Models;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// Displays a summary of packaging configuration before the pack begins.
    /// Lets users verify their choices before committing to the packaging operation.
    /// </summary>
    public class PackagingSummaryViewModel : INotifyPropertyChanged
    {
        private string _packageName = "";
        private int _fileCount = 0;
        private string _compressionMethod = "";
        private bool _requiresAdmin = false;
        private bool _includeWingetUpdater = false;
        private bool _verifyIntegrity = false;
        private string _estimatedSize = "";

        public string PackageName
        {
            get => _packageName;
            set { _packageName = value; OnPropertyChanged(); }
        }

        public int FileCount
        {
            get => _fileCount;
            set { _fileCount = value; OnPropertyChanged(); }
        }

        public string CompressionMethod
        {
            get => _compressionMethod;
            set { _compressionMethod = value; OnPropertyChanged(); }
        }

        public bool RequiresAdmin
        {
            get => _requiresAdmin;
            set { _requiresAdmin = value; OnPropertyChanged(); }
        }

        public bool IncludeWingetUpdater
        {
            get => _includeWingetUpdater;
            set { _includeWingetUpdater = value; OnPropertyChanged(); }
        }

        public bool VerifyIntegrity
        {
            get => _verifyIntegrity;
            set { _verifyIntegrity = value; OnPropertyChanged(); }
        }

        public string EstimatedSize
        {
            get => _estimatedSize;
            set { _estimatedSize = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// Builds a summary from the current package settings and file list.
        /// </summary>
        public void UpdateFromSettings(
            string packageName,
            int fileCount,
            CompressionMethodEnum compressionMethod,
            bool requiresAdmin,
            bool includeWingetUpdater,
            bool verifyIntegrity,
            List<string> filePaths)
        {
            PackageName = packageName;
            FileCount = fileCount;
            CompressionMethod = DescribeCompression(compressionMethod);
            RequiresAdmin = requiresAdmin;
            IncludeWingetUpdater = includeWingetUpdater;
            VerifyIntegrity = verifyIntegrity;
            EstimatedSize = EstimatePackageSize(filePaths);
        }

        private static string DescribeCompression(CompressionMethodEnum method) => method switch
        {
            CompressionMethodEnum.None => "None (fastest)",
            CompressionMethodEnum.Fast => "Fast (DEFLATE 6)",
            CompressionMethodEnum.Normal => "Normal (DEFLATE 6)",
            CompressionMethodEnum.Maximum => "Maximum (DEFLATE 9, slowest)",
            _ => "Unknown"
        };

        private static string EstimatePackageSize(List<string> filePaths)
        {
            if (filePaths == null || filePaths.Count == 0)
                return "0 B";

            try
            {
                long totalBytes = filePaths
                    .Sum(path => new System.IO.FileInfo(path).Length);

                return FormatBytes(totalBytes);
            }
            catch
            {
                return "Unable to estimate";
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
