// PackItPro/ViewModels/SettingsViewModel.cs - v2.1
// Added: ScanOnAdd property (wraps AppSettings.ScanOnAdd)
//        LoadSettingsAsync now restores ScanOnAdd from JSON.
using PackItPro.Models;
using PackItPro.Services;
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
        private string? _virusTotalApiKey;
        private bool _disposed;

        // API key is stored via DPAPI (CredentialStore), never in settings.json as plaintext.
        public string VirusTotalApiKey
        {
            get => _virusTotalApiKey ?? "";
            set
            {
                _virusTotalApiKey = value;
                CredentialStore.SaveVirusTotalKey(value);
                OnPropertyChanged();
            }
        }

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

        /// <summary>
        /// When true, a VirusTotal scan is triggered automatically after files are added.
        /// Requires ScanWithVirusTotal = true and a valid API key — checked at call-time.
        /// </summary>
        public bool ScanOnAdd
        {
            get => SettingsModel.ScanOnAdd;
            set { SettingsModel.ScanOnAdd = value; OnPropertyChanged(); }
        }

        public SettingsViewModel(string settingsFilePath)
        {
            SettingsModel = new AppSettings();
            _settingsFilePath = settingsFilePath ?? throw new ArgumentNullException(nameof(settingsFilePath));
            _virusTotalApiKey = CredentialStore.LoadVirusTotalKey();
        }

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
                        // OutputFileName is per-package — do NOT restore it.
                        SettingsModel.OnlyScanExecutables = loadedSettings.OnlyScanExecutables;
                        SettingsModel.AutoRemoveInfectedFiles = loadedSettings.AutoRemoveInfectedFiles;
                        SettingsModel.MinimumDetectionsToFlag = loadedSettings.MinimumDetectionsToFlag;
                        SettingsModel.IncludeWingetUpdateScript = loadedSettings.IncludeWingetUpdateScript;
                        SettingsModel.UseLZMACompression = loadedSettings.UseLZMACompression;
                        SettingsModel.RequiresAdmin = loadedSettings.RequiresAdmin;
                        SettingsModel.VerifyIntegrity = loadedSettings.VerifyIntegrity;
                        SettingsModel.ScanWithVirusTotal = loadedSettings.ScanWithVirusTotal;
                        SettingsModel.CompressionLevel = loadedSettings.CompressionLevel;
                        SettingsModel.CompressionMethod = loadedSettings.CompressionMethod;
                        SettingsModel.MaxFilesInList = loadedSettings.MaxFilesInList;
                        SettingsModel.DisclaimerAccepted = loadedSettings.DisclaimerAccepted;
                        SettingsModel.ScanOnAdd = loadedSettings.ScanOnAdd;

                        if (loadedSettings.TrustedEngines?.Count > 0)
                            SettingsModel.TrustedEngines = loadedSettings.TrustedEngines;

                        await MigrateLegacyApiKeyIfNeededAsync(json, cancellationToken);
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SettingsViewModel] Load failed: {ex.Message}");
            }
        }

        private async Task MigrateLegacyApiKeyIfNeededAsync(string jsonContent, CancellationToken ct)
        {
            try
            {
                if (CredentialStore.HasStoredKey()) return;

                using var doc = JsonDocument.Parse(jsonContent);
                if (!doc.RootElement.TryGetProperty("virusTotalApiKey", out var keyElement)) return;

                string? legacyKey = keyElement.GetString();
                if (string.IsNullOrWhiteSpace(legacyKey)) return;

                CredentialStore.SaveVirusTotalKey(legacyKey);
                _virusTotalApiKey = legacyKey;

                var migratedJson = JsonSerializer.Serialize(
                    SettingsModel,
                    new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_settingsFilePath, migratedJson, ct);

                System.Diagnostics.Debug.WriteLine(
                    "[SettingsViewModel] Migrated legacy plaintext API key to DPAPI storage.");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[SettingsViewModel] Legacy API key migration failed (non-fatal): {ex.Message}");
            }
        }

        public async Task SaveSettingsAsync(CancellationToken cancellationToken = default)
        {
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
            catch (OperationCanceledException) { /* superseded by a newer save call */ }
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

            return true;
        }

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

        protected virtual void OnPropertyChanged(
            [System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}