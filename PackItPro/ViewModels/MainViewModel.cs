// PackItPro/ViewModels/MainViewModel.cs
using PackItPro.Services;
using PackItPro.ViewModels.CommandHandlers;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Reflection;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// Main ViewModel — orchestrates all CommandHandlers and sub-ViewModels.
    /// </summary>
    public class MainViewModel : INotifyPropertyChanged, IDisposable
    {
        public string AppVersion
        {
            get
            {
                var version = Assembly.GetExecutingAssembly().GetName().Version;
                return $"v{version!.Major}.{version.Minor}.{version.Build}";
            }
        }

        #region Fields

        private readonly string _appDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PackItPro");
        private readonly string _cacheFilePath;
        private readonly string _trustStorePath;
        private readonly HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
            ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
            ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf"
        };

        private VirusTotalClient? _virusTotalClient;
        private TrustStore? _trustStore;
        private readonly ILogService _logService;
        private readonly HttpClient _httpClient;       // long-lived — one instance per application
        private readonly UpdateService _updateService;
        private bool _isInitialized;
        private bool _disposed;

        #endregion

        #region Sub-ViewModels

        public ErrorViewModel Error { get; }
        public FileListViewModel FileList { get; }
        public SettingsViewModel Settings { get; }
        public SummaryViewModel Summary { get; }
        public StatusViewModel Status { get; }

        #endregion

        #region Command Handlers

        private PackagingCommandHandler? _packagingHandler;
        private FileOperationsHandler? _fileOperationsHandler;
        private SettingsHandler? _settingsHandler;
        private VirusTotalCommandHandler? _virusTotalHandler;
        private HelpHandler? _helpHandler;
        private ApplicationHandler? _applicationHandler;
        private MarkTrustCommandHandler? _markTrustHandler;

        #endregion

        #region Commands

        private static readonly ICommand NullCommand = new RelayCommand(_ => { });

        // Packaging
        public ICommand PackCommand => _packagingHandler?.PackCommand ?? NullCommand;
        public ICommand TestPackageCommand => _packagingHandler?.TestPackageCommand ?? NullCommand;

        // File operations
        public ICommand BrowseFilesCommand => _fileOperationsHandler?.BrowseFilesCommand ?? NullCommand;
        public ICommand ClearAllFilesCommand => _fileOperationsHandler?.ClearAllFilesCommand ?? NullCommand;
        public ICommand ExportListCommand => _fileOperationsHandler?.ExportListCommand ?? NullCommand;

        // Settings
        public ICommand SetOutputLocationCommand => _settingsHandler?.SetOutputLocationCommand ?? NullCommand;
        public ICommand SetVirusApiKeyCommand => _settingsHandler?.SetVirusApiKeyCommand ?? NullCommand;
        public ICommand ClearCacheCommand => _settingsHandler?.ClearCacheCommand ?? NullCommand;
        public ICommand ExportLogsCommand => _settingsHandler?.ExportLogsCommand ?? NullCommand;
        public ICommand PackItProSettingsCommand => _settingsHandler?.PackItProSettingsCommand ?? NullCommand;
        public ICommand ViewCacheCommand => _settingsHandler?.ViewCacheCommand ?? NullCommand;

        // VirusTotal
        public ICommand ScanFilesCommand => _virusTotalHandler?.ScanFilesCommand ?? NullCommand;
        public ICommand CancelScanCommand => _virusTotalHandler?.CancelScanCommand ?? NullCommand;
        public ICommand DeleteVirusApiKeyCommand => _settingsHandler?.DeleteVirusApiKeyCommand ?? NullCommand;

        // Trust — exposed here so FileListPanel ContextMenu can reach them via Tag binding
        public ICommand MarkAsTrustedCommand => _markTrustHandler?.MarkAsTrustedCommand ?? NullCommand;
        public ICommand RemoveTrustCommand => _markTrustHandler?.RemoveTrustCommand ?? NullCommand;

        // Help
        public ICommand DocumentationCommand => _helpHandler?.DocumentationCommand ?? NullCommand;
        public ICommand GitHubCommand => _helpHandler?.GitHubCommand ?? NullCommand;
        public ICommand ReportIssueCommand => _helpHandler?.ReportIssueCommand ?? NullCommand;
        public ICommand CheckUpdatesCommand => _helpHandler?.CheckUpdatesCommand ?? NullCommand;
        public ICommand AboutCommand => _helpHandler?.AboutCommand ?? NullCommand;

        // Application
        public ICommand ExitCommand => _applicationHandler?.ExitCommand ?? NullCommand;

        #endregion

        public MainViewModel()
        {
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");
            _trustStorePath = Path.Combine(_appDataDir, "trusted_hashes.json");
            EnsureAppDataDirectoryExists();

            var logPath = Path.Combine(_appDataDir, "packitpro.log");
            _logService = new FileLogService(logPath);

            _httpClient = new HttpClient();
            _updateService = new UpdateService(_httpClient);

            Settings = new SettingsViewModel(Path.Combine(_appDataDir, "settings.json"));
            FileList = new FileListViewModel(Settings.SettingsModel, _executableExtensions);
            Summary = new SummaryViewModel(FileList, Settings);
            Status = new StatusViewModel();
            Error = new ErrorViewModel();

            _logService.Info("MainViewModel constructed");
        }

        private void EnsureAppDataDirectoryExists()
        {
            Directory.CreateDirectory(_appDataDir);
            Directory.CreateDirectory(Path.Combine(_appDataDir, "Logs"));
            Directory.CreateDirectory(Path.Combine(_appDataDir, "Cache"));
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            try
            {
                _logService.Info($"PackItPro {AppVersion} started");
                _logService.Info("========== INITIALIZATION START ==========");

                await Settings.LoadSettingsAsync();
                _logService.Info("Settings loaded");

                _virusTotalClient = new VirusTotalClient(_cacheFilePath, Settings.VirusTotalApiKey);
                await _virusTotalClient.LoadCacheAsync(_logService);
                _logService.Info("VirusTotal initialized");

                _trustStore = new TrustStore(_trustStorePath);
                await _trustStore.LoadAsync(_logService);
                _logService.Info("TrustStore initialized");

                InitializeHandlers();
                NotifyAllCommandsAvailable();

                _isInitialized = true;
                Status.SetStatusReady();
                _logService.Info("========== INITIALIZATION SUCCESS ==========");
            }
            catch (Exception ex)
            {
                _logService.Error("Initialization failed", ex);
                Status.Message = "Failed to initialize";
                Error.ShowErrorAsync("App failed to initialize. See logs.", retryActionAsync: InitializeAsync);
            }
        }

        private void InitializeHandlers()
        {
            _packagingHandler = new PackagingCommandHandler(FileList, Settings, Status, Error, _logService);
            _virusTotalHandler = new VirusTotalCommandHandler(
                FileList, Settings, Status, Error, _virusTotalClient!, _logService, _executableExtensions);
            _fileOperationsHandler = new FileOperationsHandler(FileList, Settings, ScanFilesCommand);
            _settingsHandler = new SettingsHandler(Settings, Status, Error, _virusTotalClient, _cacheFilePath, _appDataDir, _logService);
            _helpHandler = new HelpHandler(_updateService, Status, _logService);
            _applicationHandler = new ApplicationHandler(Settings);
            _markTrustHandler = new MarkTrustCommandHandler(_trustStore!, _logService);
            _logService.Info("All handlers initialized");
        }

        private void NotifyAllCommandsAvailable()
        {
            OnPropertyChanged(nameof(PackCommand));
            OnPropertyChanged(nameof(TestPackageCommand));
            OnPropertyChanged(nameof(BrowseFilesCommand));
            OnPropertyChanged(nameof(ClearAllFilesCommand));
            OnPropertyChanged(nameof(ExportListCommand));
            OnPropertyChanged(nameof(SetOutputLocationCommand));
            OnPropertyChanged(nameof(SetVirusApiKeyCommand));
            OnPropertyChanged(nameof(DeleteVirusApiKeyCommand));
            OnPropertyChanged(nameof(ClearCacheCommand));
            OnPropertyChanged(nameof(ExportLogsCommand));
            OnPropertyChanged(nameof(PackItProSettingsCommand));
            OnPropertyChanged(nameof(ViewCacheCommand));
            OnPropertyChanged(nameof(ScanFilesCommand));
            OnPropertyChanged(nameof(CancelScanCommand));
            OnPropertyChanged(nameof(MarkAsTrustedCommand));
            OnPropertyChanged(nameof(RemoveTrustCommand));
            OnPropertyChanged(nameof(DocumentationCommand));
            OnPropertyChanged(nameof(GitHubCommand));
            OnPropertyChanged(nameof(ReportIssueCommand));
            OnPropertyChanged(nameof(CheckUpdatesCommand));
            OnPropertyChanged(nameof(AboutCommand));
            OnPropertyChanged(nameof(ExitCommand));
            _logService.Info("All command bindings refreshed");
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {
                _logService.Info("Disposing MainViewModel...");
                _packagingHandler?.Dispose();
                _virusTotalHandler?.Dispose();
                _fileOperationsHandler?.Dispose();
                _settingsHandler?.Dispose();
                _helpHandler?.Dispose();
                _applicationHandler?.Dispose();
                _markTrustHandler?.Dispose();
                FileList?.Dispose();
                Summary?.Dispose();
                Settings?.Dispose();
                _virusTotalClient?.Dispose();
                _httpClient?.Dispose();
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
