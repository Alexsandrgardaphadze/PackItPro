// ViewModels/SettingsViewModel.cs
using PackItPro.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Text.Json;

namespace PackItPro.ViewModels
{
    public class SettingsViewModel : INotifyPropertyChanged
    {
        // NEW: Expose the underlying model
        public AppSettings SettingsModel { get; }

        private readonly string _settingsFilePath;

        // Properties exposed for binding (delegating to SettingsModel)
        public string OutputLocation
        {
            get => SettingsModel.OutputLocation;
            set { SettingsModel.OutputLocation = value; OnPropertyChanged(); }
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

        public SettingsViewModel(string settingsFilePath)
        {
            SettingsModel = new AppSettings(); // Initialize the model
            _settingsFilePath = settingsFilePath;
        }

        // NEW: Load settings from file
        public async Task LoadSettingsAsync()
        {
            try
            {
                if (File.Exists(_settingsFilePath))
                {
                    var json = await File.ReadAllTextAsync(_settingsFilePath);
                    var loadedSettings = JsonSerializer.Deserialize<AppSettings>(json);
                    if (loadedSettings != null)
                    {
                        // Copy loaded settings to the model instance held by this ViewModel
                        SettingsModel.OutputLocation = loadedSettings.OutputLocation;
                        SettingsModel.VirusTotalApiKey = loadedSettings.VirusTotalApiKey;
                        SettingsModel.OnlyScanExecutables = loadedSettings.OnlyScanExecutables;
                        SettingsModel.AutoRemoveInfectedFiles = loadedSettings.AutoRemoveInfectedFiles;
                        SettingsModel.MinimumDetectionsToFlag = loadedSettings.MinimumDetectionsToFlag;
                        SettingsModel.IncludeWingetUpdateScript = loadedSettings.IncludeWingetUpdateScript;
                        SettingsModel.UseLZMACompression = loadedSettings.UseLZMACompression;
                        SettingsModel.RequiresAdmin = loadedSettings.RequiresAdmin;
                        SettingsModel.VerifyIntegrity = loadedSettings.VerifyIntegrity;
                    }
                }
            }
            catch (Exception ex)
            {
                // Log error or handle default settings
                Console.WriteLine($"[SettingsViewModel] LoadSettingsAsync failed: {ex.Message}");
                // Optionally reset SettingsModel to defaults if loading fails
                // SettingsModel = new AppSettings(); // This would require changing SettingsModel to a property setter
            }
        }

        // NEW: Save settings to file
        public async Task SaveSettingsAsync()
        {
            try
            {
                var dirPath = Path.GetDirectoryName(_settingsFilePath);
                if (!string.IsNullOrEmpty(dirPath) && !Directory.Exists(dirPath))
                {
                    Directory.CreateDirectory(dirPath);
                }

                var json = JsonSerializer.Serialize(SettingsModel, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_settingsFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SettingsViewModel] SaveSettingsAsync failed: {ex.Message}");
                // Optionally throw or handle error
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}