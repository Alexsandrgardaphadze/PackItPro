// Views/CacheViewWindow.xaml.cs
using System;
using System.Diagnostics;
using System.Windows;

namespace PackItPro.Views
{
    public partial class CacheViewWindow : Window
    {
        private readonly string _cacheFilePath;

        public CacheViewWindow(int entryCount, long fileSizeBytes, DateTime lastModified, string cacheFilePath)
        {
            InitializeComponent();
            _cacheFilePath = cacheFilePath;

            EntryCountText.Text = entryCount.ToString();
            CacheSizeText.Text = AppConstants.FormatBytes(fileSizeBytes);
            LastModText.Text = lastModified.ToString("MMM d\nyyyy HH:mm");
            CachePathText.Text = cacheFilePath;
        }

        private void OpenNotepad_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    Arguments = $"\"{_cacheFilePath}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(this, "Cannot Open File",
                    "Could not launch Notepad.",
                    detail: ex.Message, kind: AlertDialog.Kind.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    }
}
