// Views/UpdateAvailableWindow.xaml.cs
using System;
using System.Windows;

namespace PackItPro.Views
{
    public partial class UpdateAvailableWindow : Window
    {
        private readonly string? _releaseUrl;

        /// <summary>True if the user clicked Download.</summary>
        public bool ShouldDownload { get; private set; }

        public UpdateAvailableWindow(
            string? currentVersion,
            string? latestVersion,
            DateTime? publishedAt,
            string? releaseNotes,
            string? releaseUrl)
        {
            InitializeComponent();
            _releaseUrl = releaseUrl;

            CurrentVersionText.Text = currentVersion ?? "unknown";
            LatestVersionText.Text = latestVersion ?? "unknown";

            if (publishedAt.HasValue)
            {
                PublishedText.Text = $"Published {publishedAt.Value.ToLocalTime():MMM d, yyyy}";
                PublishedText.Visibility = Visibility.Visible;
            }

            if (!string.IsNullOrWhiteSpace(releaseNotes))
            {
                NotesText.Text = Truncate(releaseNotes, 300);
                NotesBox.Visibility = Visibility.Visible;
            }
        }

        private void DownloadButton_Click(object sender, RoutedEventArgs e)
        {
            ShouldDownload = true;
            DialogResult = true;
            Close();
        }

        private void LaterButton_Click(object sender, RoutedEventArgs e)
        {
            ShouldDownload = false;
            DialogResult = false;
            Close();
        }

        private static string Truncate(string text, int max)
        {
            if (text.Length <= max) return text;
            return text[..max].TrimEnd() + "\n…(see release page for full notes)";
        }
    }
}
