// ViewModels/MainViewModel.cs - v2.7 ULTIMATE FIX
using PackItPro.Services;
using PackItPro.ViewModels.CommandHandlers;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// Main ViewModel — orchestrates CommandHandlers with proper command initialization.
    /// FIX v2.7: Notifies UI when commands become available after InitializeAsync().
    /// </summary>
    public class MainViewModel : INotifyPropertyChanged, IDisposable
    {
        #region Fields
        private readonly string _appDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PackItPro");
        private readonly string _cacheFilePath;
        private readonly HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
            ".scr", ".pif", ".gadget", ".application", ".msc", ".cpl", ".hta", ".reg",
            ".vb", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".lnk", ".inf", ".scf"
        };
        private VirusTotalClient? _virusTotalClient;
        private readonly ILogService _logService;
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
        #endregion

        #region Commands
        public ICommand PackCommand => _packagingHandler?.PackCommand ?? NullCommand;
        public ICommand TestPackageCommand => _packagingHandler?.TestPackageCommand ?? NullCommand;
        public ICommand BrowseFilesCommand => _fileOperationsHandler?.BrowseFilesCommand ?? NullCommand;
        public ICommand ClearAllFilesCommand => _fileOperationsHandler?.ClearAllFilesCommand ?? NullCommand;
        public ICommand ExportListCommand => _fileOperationsHandler?.ExportListCommand ?? NullCommand;
        public ICommand SetOutputLocationCommand => _settingsHandler?.SetOutputLocationCommand ?? NullCommand;
        public ICommand SetVirusApiKeyCommand => _settingsHandler?.SetVirusApiKeyCommand ?? NullCommand;
        public ICommand ClearCacheCommand => _settingsHandler?.ClearCacheCommand ?? NullCommand;
        public ICommand ExportLogsCommand => _settingsHandler?.ExportLogsCommand ?? NullCommand;
        public ICommand PackItProSettingsCommand => _settingsHandler?.PackItProSettingsCommand ?? NullCommand;
        public ICommand ViewCacheCommand => _settingsHandler?.ViewCacheCommand ?? NullCommand;
        public ICommand ScanFilesCommand => _virusTotalHandler?.ScanFilesCommand ?? NullCommand;
        public ICommand CancelScanCommand => _virusTotalHandler?.CancelScanCommand ?? NullCommand;
        public ICommand DocumentationCommand => _helpHandler?.DocumentationCommand ?? NullCommand;
        public ICommand GitHubCommand => _helpHandler?.GitHubCommand ?? NullCommand;
        public ICommand ReportIssueCommand => _helpHandler?.ReportIssueCommand ?? NullCommand;
        public ICommand CheckUpdatesCommand => _helpHandler?.CheckUpdatesCommand ?? NullCommand;
        public ICommand AboutCommand => _helpHandler?.AboutCommand ?? NullCommand;
        public ICommand ExitCommand => _applicationHandler?.ExitCommand ?? NullCommand;

        private static readonly ICommand NullCommand = new RelayCommand(_ => { });
        #endregion

        public MainViewModel()
        {
            _cacheFilePath = Path.Combine(_appDataDir, "virusscancache.json");
            EnsureAppDataDirectoryExists();

            var logPath = Path.Combine(_appDataDir, "packitpro.log");
            _logService = new FileLogService(logPath);

            Settings = new SettingsViewModel(Path.Combine(_appDataDir, "settings.json"));
            FileList = new FileListViewModel(Settings.SettingsModel, _executableExtensions);
            Summary = new SummaryViewModel(FileList, Settings);
            Status = new StatusViewModel();
            Error = new ErrorViewModel();

            _logService.Info("MainViewModel constructed");
        }

        private void EnsureAppDataDirectoryExists()
        {
            if (!Directory.Exists(_appDataDir))
                Directory.CreateDirectory(_appDataDir);
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            try
            {
                _logService.Info("========== INITIALIZATION START ==========");

                await Settings.LoadSettingsAsync();
                _logService.Info("Settings loaded");

                _virusTotalClient = new VirusTotalClient(_cacheFilePath, Settings.VirusTotalApiKey);
                await _virusTotalClient.LoadCacheAsync(_logService);
                _logService.Info("VirusTotal initialized");

                InitializeHandlers();

                // ✅ CRITICAL FIX: Notify ALL command properties
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
            _virusTotalHandler = new VirusTotalCommandHandler(FileList, Settings, Status, Error, _virusTotalClient!, _logService, _executableExtensions);
            _fileOperationsHandler = new FileOperationsHandler(FileList, Settings, ScanFilesCommand);
            _settingsHandler = new SettingsHandler(Settings, Status, Error, _virusTotalClient, _cacheFilePath, _appDataDir, _logService);
            _helpHandler = new HelpHandler();
            _applicationHandler = new ApplicationHandler(Settings);
            _logService.Info("Handlers initialized");
        }

        // ✅ FIX: Tell WPF that commands are now available
        private void NotifyAllCommandsAvailable()
        {
            OnPropertyChanged(nameof(PackCommand));
            OnPropertyChanged(nameof(TestPackageCommand));
            OnPropertyChanged(nameof(BrowseFilesCommand));
            OnPropertyChanged(nameof(ClearAllFilesCommand));
            OnPropertyChanged(nameof(ExportListCommand));
            OnPropertyChanged(nameof(SetOutputLocationCommand));
            OnPropertyChanged(nameof(SetVirusApiKeyCommand));
            OnPropertyChanged(nameof(ClearCacheCommand));
            OnPropertyChanged(nameof(ExportLogsCommand));
            OnPropertyChanged(nameof(PackItProSettingsCommand));
            OnPropertyChanged(nameof(ViewCacheCommand));
            OnPropertyChanged(nameof(ScanFilesCommand));
            OnPropertyChanged(nameof(CancelScanCommand));
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
                _logService.Info("Disposing...");
                _packagingHandler?.Dispose();
                _virusTotalHandler?.Dispose();
                _fileOperationsHandler?.Dispose();
                _settingsHandler?.Dispose();
                _helpHandler?.Dispose();
                _applicationHandler?.Dispose();
                FileList?.Dispose();
                Summary?.Dispose();
                Settings?.Dispose();
                _virusTotalClient?.Dispose();
                _logService.Info("Disposed");
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