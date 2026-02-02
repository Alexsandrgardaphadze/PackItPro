// PackItPro/ViewModels/SettingsViewModel.cs
using PackItPro.Models;
using System;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace PackItPro.ViewModels
{
    public class SettingsViewModel : INotifyPropertyChanged
    {
        public AppSettings SettingsModel { get; }

        private readonly string _settingsFilePath;

        // ✅ EXPOSE ALL REQUIRED PROPERTIES (delegating to SettingsModel)
        public string OutputLocation
        {
            get => SettingsModel.OutputLocation;
            set { SettingsModel.OutputLocation = value; OnPropertyChanged(); }
        }

        public string OutputFileName  // ✅ NEW
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

        public bool ScanWithVirusTotal  // ✅ NEW
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

        public async Task LoadSettingsAsync()
        {
            try
            {
                if (!string.IsNullOrEmpty(_settingsFilePath) && File.Exists(_settingsFilePath))
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath);
                    var loadedSettings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (loadedSettings != null)
                    {
                        // ✅ Copy ALL properties (including new ones)
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
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SettingsViewModel] Load failed: {ex.Message}");
            }
        }

        public async Task SaveSettingsAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(_settingsFilePath)) return;

                var dirPath = Path.GetDirectoryName(_settingsFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                    Directory.CreateDirectory(dirPath);

                var json = JsonSerializer.Serialize(SettingsModel, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_settingsFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SettingsViewModel] Save failed: {ex.Message}");
            }
        }

        public bool ValidateSettings(out string errorMessage)
        {
            errorMessage = "";

            // Check output location
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

            // Try creating a temp file to verify write access
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

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}