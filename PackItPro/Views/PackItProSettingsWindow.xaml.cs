// Views/PackItProSettingsWindow.xaml.cs
// v2.0 — added TrustStore viewer with per-entry remove buttons
using PackItPro.Models;
using PackItPro.Services;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;

namespace PackItPro.Views
{
    public partial class PackItProSettingsWindow : Window
    {
        private readonly AppSettings _settings;
        private readonly string _settingsFilePath;
        private readonly TrustStore? _trustStore;

        private readonly ObservableCollection<TrustEntryRow> _trustRows = new();

        public string OutputFileName { get; private set; } = "";
        public int MinDetections { get; private set; }
        public bool VerifyIntegrity { get; private set; }
        public int MaxFiles { get; private set; }
        public bool ScanOnAdd { get; private set; }

        public PackItProSettingsWindow(AppSettings current, string settingsFilePath,
                                       TrustStore? trustStore = null)
        {
            InitializeComponent();
            _settings = current;
            _settingsFilePath = settingsFilePath;
            _trustStore = trustStore;

            OutputLocationBox.Text = current.OutputLocation ?? "";
            SettingsPathText.Text = settingsFilePath;
            OutputFileNameBox.Text = current.OutputFileName ?? "Package";
            MinDetectionsBox.Text = current.MinimumDetectionsToFlag.ToString();
            MaxFilesBox.Text = current.MaxFilesInList.ToString();
            VerifyIntegrityBox.IsChecked = current.VerifyIntegrity;
            ScanOnAddBox.IsChecked = current.ScanOnAdd;

            LoadTrustEntries();
            TrustedHashList.ItemsSource = _trustRows;
        }

        private void LoadTrustEntries()
        {
            _trustRows.Clear();
            if (_trustStore == null) return;
            foreach (var entry in _trustStore.GetAll())
                _trustRows.Add(new TrustEntryRow(entry));
            RefreshTrustVisibility();
        }

        private void RefreshTrustVisibility()
        {
            bool hasEntries = _trustRows.Count > 0;
            TrustedHashList.Visibility = hasEntries ? Visibility.Visible : Visibility.Collapsed;
            NoTrustedText.Visibility = hasEntries ? Visibility.Collapsed : Visibility.Visible;
        }

        private async void RemoveTrust_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn) return;
            if (btn.Tag is not string hash) return;
            if (_trustStore == null) return;

            TrustEntryRow? row = null;
            foreach (var r in _trustRows)
                if (r.Hash == hash) { row = r; break; }
            if (row == null) return;

            bool confirmed = ConfirmDialog.Show(
                this,
                "Remove Trusted Hash",
                $"Remove \"{row.FileName}\" from the trusted list?\n\n" +
                "The next scan will evaluate this file normally again.",
                confirmLabel: "Remove",
                cancelLabel: "Keep",
                kind: ConfirmDialog.Kind.Warning);

            if (!confirmed) return;

            _trustRows.Remove(row);
            RefreshTrustVisibility();
            await _trustStore.UntrustAsync(hash);
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(MinDetectionsBox.Text.Trim(), out int minDet) || minDet < 1 || minDet > 72)
            {
                AlertDialog.Show(this, "Invalid Value",
                    "Min detections to flag must be a number between 1 and 72.",
                    kind: AlertDialog.Kind.Warning);
                MinDetectionsBox.Focus();
                return;
            }

            if (!int.TryParse(MaxFilesBox.Text.Trim(), out int maxFiles) || maxFiles < 1 || maxFiles > 50)
            {
                AlertDialog.Show(this, "Invalid Value",
                    "Max files in list must be a number between 1 and 50.",
                    kind: AlertDialog.Kind.Warning);
                MaxFilesBox.Focus();
                return;
            }

            string outputName = OutputFileNameBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(outputName)) outputName = "Package";

            OutputFileName = outputName;
            MinDetections = minDet;
            VerifyIntegrity = VerifyIntegrityBox.IsChecked == true;
            MaxFiles = maxFiles;
            ScanOnAdd = ScanOnAddBox.IsChecked == true;

            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void OpenInNotepad_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    Arguments = $"\"{_settingsFilePath}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(this, "Cannot Open File",
                    $"Could not open Notepad.\n\nFile is at:\n{_settingsFilePath}",
                    detail: ex.Message, kind: AlertDialog.Kind.Error);
            }
        }
    }

    internal sealed class TrustEntryRow
    {
        public string Hash { get; }
        public string FileName { get; }
        public string ShortHash { get; }
        public string TrustedAtFormatted { get; }

        public TrustEntryRow(TrustEntry entry)
        {
            Hash = entry.Hash;
            FileName = entry.FileName;
            ShortHash = entry.Hash.Length >= 8 ? entry.Hash[..8] + "…" : entry.Hash;
            TrustedAtFormatted = entry.TrustedAt.ToLocalTime().ToString("dd MM yyyy HH:mm");
        }
    }
}