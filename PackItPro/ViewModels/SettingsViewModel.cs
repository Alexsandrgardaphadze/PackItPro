// PackItPro/ViewModels/SettingsViewModel.cs - v2.2
using PackItPro.Models;
using System;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.ViewModels
{
    public class SettingsViewModel : INotifyPropertyChanged, IDisposable
    {
        public AppSettings SettingsModel { get; }

        private readonly string _settingsFilePath;
        private CancellationTokenSource? _saveCts;
        private bool _disposed;

        public string OutputLocation
        {
            get => SettingsModel.OutputLocation;
            set { SettingsModel.OutputLocation = value; OnPropertyChanged(); }
        }

        public string OutputFileName
        {
            get => SettingsModel.OutputFileName;
            set { SettingsModel.OutputFileName = value; OnPropertyChanged(); }
        }

        public string VirusTotalApiKey
        {
            get => SettingsModel.VirusTotalApiKey;
            set { SettingsModel.VirusTotalApiKey = value; OnPropertyChanged(); }
        }

        public bool OnlyScanExecutables
        {
            get => SettingsModel.OnlyScanExecutables;
            set { SettingsModel.OnlyScanExecutables = value; OnPropertyChanged(); }
        }

        public bool AutoRemoveInfectedFiles
        {
            get => SettingsModel.AutoRemoveInfectedFiles;
            set { SettingsModel.AutoRemoveInfectedFiles = value; OnPropertyChanged(); }
        }

        public int MinimumDetectionsToFlag
        {
            get => SettingsModel.MinimumDetectionsToFlag;
            set { SettingsModel.MinimumDetectionsToFlag = value; OnPropertyChanged(); }
        }

        public bool IncludeWingetUpdateScript
        {
            get => SettingsModel.IncludeWingetUpdateScript;
            set { SettingsModel.IncludeWingetUpdateScript = value; OnPropertyChanged(); }
        }

        public bool UseLZMACompression
        {
            get => SettingsModel.UseLZMACompression;
            set { SettingsModel.UseLZMACompression = value; OnPropertyChanged(); }
        }

        public bool RequiresAdmin
        {
            get => SettingsModel.RequiresAdmin;
            set { SettingsModel.RequiresAdmin = value; OnPropertyChanged(); }
        }

        public bool VerifyIntegrity
        {
            get => SettingsModel.VerifyIntegrity;
            set { SettingsModel.VerifyIntegrity = value; OnPropertyChanged(); }
        }

        public bool ScanWithVirusTotal
        {
            get => SettingsModel.ScanWithVirusTotal;
            set { SettingsModel.ScanWithVirusTotal = value; OnPropertyChanged(); }
        }

        public int CompressionLevel
        {
            get => SettingsModel.CompressionLevel;
            set { SettingsModel.CompressionLevel = value; OnPropertyChanged(); }
        }

        public SettingsViewModel(string settingsFilePath)
        {
            SettingsModel = new AppSettings();
            _settingsFilePath = settingsFilePath ?? throw new ArgumentNullException(nameof(settingsFilePath));
        }

        // FIX: Add CancellationToken support for async operations
        public async Task LoadSettingsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (!string.IsNullOrEmpty(_settingsFilePath) && File.Exists(_settingsFilePath))
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath, cancellationToken);
                    var loadedSettings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (loadedSettings != null)
                    {
                        SettingsModel.OutputLocation = loadedSettings.OutputLocation;
                        SettingsModel.OutputFileName = loadedSettings.OutputFileName;
                        SettingsModel.VirusTotalApiKey = loadedSettings.VirusTotalApiKey;
                        SettingsModel.OnlyScanExecutables = loadedSettings.OnlyScanExecutables;
                        SettingsModel.AutoRemoveInfectedFiles = loadedSettings.AutoRemoveInfectedFiles;
                        SettingsModel.MinimumDetectionsToFlag = loadedSettings.MinimumDetectionsToFlag;
                        SettingsModel.IncludeWingetUpdateScript = loadedSettings.IncludeWingetUpdateScript;
                        SettingsModel.UseLZMACompression = loadedSettings.UseLZMACompression;
                        SettingsModel.RequiresAdmin = loadedSettings.RequiresAdmin;
                        SettingsModel.VerifyIntegrity = loadedSettings.VerifyIntegrity;
                        SettingsModel.ScanWithVirusTotal = loadedSettings.ScanWithVirusTotal;
                        SettingsModel.CompressionLevel = loadedSettings.CompressionLevel;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Silent cancellation — caller handles it
                throw;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SettingsViewModel] Load failed: {ex.Message}");
            }
        }

        // FIX: Add CancellationToken support and cancel previous save if in progress
        public async Task SaveSettingsAsync(CancellationToken cancellationToken = default)
        {
            // Cancel any previous save operation
            _saveCts?.Cancel();
            _saveCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            try
            {
                if (string.IsNullOrEmpty(_settingsFilePath)) return;

                var dirPath = Path.GetDirectoryName(_settingsFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                    Directory.CreateDirectory(dirPath);

                var json = JsonSerializer.Serialize(SettingsModel, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_settingsFilePath, json, _saveCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Silent — save was cancelled (normal during rapid property changes)
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SettingsViewModel] Save failed: {ex.Message}");
            }
            finally
            {
                _saveCts?.Dispose();
                _saveCts = null;
            }
        }

        public bool ValidateSettings(out string errorMessage)
        {
            errorMessage = "";

            if (string.IsNullOrWhiteSpace(OutputLocation))
            {
                errorMessage = "Output location not set.";
                return false;
            }

            if (!Directory.Exists(OutputLocation))
            {
                errorMessage = $"Output location does not exist: {OutputLocation}";
                return false;
            }

            try
            {
                var testFile = Path.Combine(OutputLocation, $".test_{Guid.NewGuid()}");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
            }
            catch (Exception ex)
            {
                errorMessage = $"No write permission in output location: {ex.Message}";
                return false;
            }

            return true;
        }

        // FIX: Proper disposal
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _saveCts?.Cancel();
                _saveCts?.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}