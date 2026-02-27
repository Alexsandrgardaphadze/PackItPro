// ViewModels/VirusTotalViewModel.cs
using PackItPro.Models;
using PackItPro.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace PackItPro.ViewModels
{
    public class VirusTotalViewModel
    {
        private readonly string _cacheFilePath;
        private readonly FileListViewModel _fileList;
        private readonly StatusViewModel _status;
        private readonly ErrorViewModel _error;
        private readonly SettingsViewModel _settings;
        private readonly HashSet<string> _executableExtensions;

        private VirusTotalClient? _virusTotalClient;

        public VirusTotalViewModel(
            string cacheFilePath,
            FileListViewModel fileList,
            StatusViewModel status,
            SettingsViewModel settings,
            ErrorViewModel error,
            HashSet<string> executableExtensions)
        {
            _cacheFilePath = cacheFilePath;
            _fileList = fileList;
            _status = status;
            _settings = settings;
            _error = error;
            _executableExtensions = executableExtensions;
        }

        public async Task InitializeAsync()
        {
            if (string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
                return;

            _virusTotalClient = new VirusTotalClient(_cacheFilePath, _settings.VirusTotalApiKey);
            await _virusTotalClient.LoadCacheAsync();
        }

        public void SetApiKey(string apiKey)
        {
            _virusTotalClient?.SetApiKey(apiKey);
        }

        public void ClearCache()
        {
            try
            {
                _virusTotalClient?.ClearCache();
                if (File.Exists(_cacheFilePath))
                    File.Delete(_cacheFilePath);

                MessageBox.Show(
                    "Scan cache cleared successfully.",
                    "Cache Cleared",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                _error.ShowError($"Failed to clear cache: {ex.Message}");
            }
        }

        public async Task ScanFilesAsync()
        {
            if (_virusTotalClient == null || string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey))
            {
                _error.ShowError("VirusTotal API key is required for scanning.\nSet it in Settings > VirusTotal API Key.");
                return;
            }

            var totalFiles = _fileList.Items.Count(f =>
                !_settings.OnlyScanExecutables || _executableExtensions.Contains(Path.GetExtension(f.FilePath)));

            if (totalFiles == 0)
            {
                MessageBox.Show(
                    "No scannable files found.\nEnable 'Scan all files' in settings to scan non-executables.",
                    "No Files to Scan",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            _status.SetStatusScanning();
            _status.Message = $"Scanning {totalFiles} file(s) with VirusTotal...";
            int processed = 0;
            int failedCount = 0;
            var infectedFiles = new List<FileItemViewModel>();

            foreach (var item in _fileList.Items)
            {
                if (_settings.OnlyScanExecutables &&
                    !_executableExtensions.Contains(Path.GetExtension(item.FilePath)))
                {
                    item.Status = FileStatusEnum.Skipped;
                    continue;
                }

                try
                {
                    var result = await _virusTotalClient.ScanFileAsync(
                        item.FilePath,
                        _settings.VirusTotalApiKey,
                        _settings.OnlyScanExecutables,
                        _settings.MinimumDetectionsToFlag
                    );

                    item.Positives = result.Positives;
                    item.TotalScans = result.TotalScans;
                    item.Status = result.IsInfected ? FileStatusEnum.Infected : FileStatusEnum.Clean;

                    if (result.IsInfected)
                        infectedFiles.Add(item);
                }
                catch (Exception ex)
                {
                    item.Status = FileStatusEnum.ScanFailed;
                    failedCount++;
                }
                finally
                {
                    processed++;
                    _status.ProgressPercentage = (double)processed / totalFiles * 100;
                }
            }

            if (infectedFiles.Count > 0)
            {
                var message = $"{infectedFiles.Count} infected file(s) detected!";
                if (_settings.SettingsModel.AutoRemoveInfectedFiles)
                {
                    foreach (var file in infectedFiles)
                        _fileList.Items.Remove(file);

                    message += $"\n\nAutomatically removed from package list.";
                }
                else
                {
                    message += $"\n\nReview files marked as 'Infected' before packaging.";
                }

                MessageBox.Show(message, "Security Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (failedCount > 0)
            {
                MessageBox.Show(
                    $"Scan completed with errors:\n{failedCount} file(s) failed to scan.\n\nCheck logs for details.",
                    "Scan Completed with Errors",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                MessageBox.Show(
                    $"All {totalFiles} file(s) scanned clean!",
                    "Scan Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            await _virusTotalClient.SaveCacheAsync();
            _status.Message = failedCount > 0 ? "Scan completed with errors" : "Scan completed successfully";
        }
    }
}
