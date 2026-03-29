// StubInstaller/ViewModels/MainInstallViewModel.cs
// Orchestrates the entire install flow and exposes bindable state to MainInstallWindow.
//
// Design:
//   - Constructed with the already-extracted tempDir and loaded manifest.
//   - BeginInstallAsync() is called by the window when the user clicks "Install".
//   - Progress is reported by mutating InstallerItemViewModel properties, which
//     the WPF bindings pick up automatically via INotifyPropertyChanged.
//   - All InstallerRunner calls happen on Task.Run; all ViewModel mutations
//     are marshalled back to the UI thread via _dispatcher.
using StubInstaller.Core;
using StubInstaller.Infrastrucure;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Threading;

namespace StubInstaller.ViewModels
{
    public enum InstallPhase
    {
        Disclaimer,  // user must accept terms before the app list
        Selection,   // user is reviewing the app list
        Installing,  // install is running
        Complete,    // all done (success or partial)
        Failed,      // fatal error before any installer ran
    }

    public class MainInstallViewModel : ViewModelBase
    {
        private readonly string _tempDir;
        private readonly PackageManifest _manifest;
        private readonly Dispatcher _dispatcher;
        private CancellationTokenSource? _cts;

        // ── Observable collections ────────────────────────────────────────────

        public ObservableCollection<InstallerItemViewModel> Items { get; } = new();

        // ── Phase ─────────────────────────────────────────────────────────────

        private InstallPhase _phase = InstallPhase.Disclaimer;
        public InstallPhase Phase
        {
            get => _phase;
            private set
            {
                if (SetField(ref _phase, value))
                {
                    OnPropertyChanged(nameof(IsDisclaimerPhase));
                    OnPropertyChanged(nameof(IsSelectionPhase));
                    OnPropertyChanged(nameof(IsInstallingPhase));
                    OnPropertyChanged(nameof(IsCompletePhase));
                    OnPropertyChanged(nameof(InstallButtonLabel));
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        public bool IsDisclaimerPhase => Phase == InstallPhase.Disclaimer;
        public bool IsSelectionPhase => Phase == InstallPhase.Selection;
        public bool IsInstallingPhase => Phase == InstallPhase.Installing;
        public bool IsCompletePhase => Phase == InstallPhase.Complete
                                      || Phase == InstallPhase.Failed;

        // ── Disclaimer ───────────────────────────────────────────────────────────

        private bool _disclaimerAccepted;
        public bool DisclaimerAccepted
        {
            get => _disclaimerAccepted;
            set
            {
                if (SetField(ref _disclaimerAccepted, value))
                    CommandManager.InvalidateRequerySuggested();
            }
        }

        // ── Reboot ───────────────────────────────────────────────────────────────

        private bool _rebootRequired;
        public bool RebootRequired
        {
            get => _rebootRequired;
            private set => SetField(ref _rebootRequired, value);
        }

        // ── Progress ──────────────────────────────────────────────────────────

        private int _overallPercent;
        public int OverallPercent
        {
            get => _overallPercent;
            private set => SetField(ref _overallPercent, value);
        }

        private string _statusMessage = "Please review and accept the terms below.";
        public string StatusMessage
        {
            get => _statusMessage;
            private set => SetField(ref _statusMessage, value);
        }

        private bool _installSucceeded;
        public bool InstallSucceeded
        {
            get => _installSucceeded;
            private set => SetField(ref _installSucceeded, value);
        }

        // ── Package info ──────────────────────────────────────────────────────

        public string PackageName => _manifest.PackageName;
        public bool RequiresAdmin => _manifest.RequiresAdmin;
        public int TotalAppCount => Items.Count;

        /// <summary>Total size of ALL items regardless of selection. Shown in header.</summary>
        public string TotalSizeDisplay
        {
            get
            {
                long bytes = Items.Where(i => i.FileSizeBytes > 0).Sum(i => i.FileSizeBytes);
                return bytes > 0 ? $"{TotalAppCount} app{(TotalAppCount != 1 ? "s" : "")} · {FormatBytes(bytes)}" : $"{TotalAppCount} app{(TotalAppCount != 1 ? "s" : "")}";
            }
        }

        private int _selectedCount;
        public int SelectedCount
        {
            get => _selectedCount;
            private set
            {
                if (SetField(ref _selectedCount, value))
                {
                    OnPropertyChanged(nameof(SelectionSummary));
                    OnPropertyChanged(nameof(SelectedSizeDisplay));
                    OnPropertyChanged(nameof(InstallButtonLabel));
                }
            }
        }

        public string SelectionSummary => $"{SelectedCount} of {TotalAppCount} selected";

        public string SelectedSizeDisplay
        {
            get
            {
                long bytes = Items
                    .Where(i => i.IsSelected && i.FileSizeBytes > 0)
                    .Sum(i => i.FileSizeBytes);
                return bytes > 0 ? $" · {FormatBytes(bytes)}" : string.Empty;
            }
        }

        /// <summary>Install button label — shows selected size when known.</summary>
        public string InstallButtonLabel
        {
            get
            {
                long bytes = Items
                    .Where(i => i.IsSelected && i.FileSizeBytes > 0)
                    .Sum(i => i.FileSizeBytes);
                return bytes > 0 ? $"Install  ({FormatBytes(bytes)})" : "Install";
            }
        }

        // ── Commands ──────────────────────────────────────────────────────────

        public ICommand AcceptDisclaimerCommand { get; }
        public ICommand InstallCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand SelectAllCommand { get; }
        public ICommand DeselectAllCommand { get; }
        public ICommand RetryFailedCommand { get; }
        public ICommand OpenLogCommand { get; }

        // ── Constructor ───────────────────────────────────────────────────────

        public MainInstallViewModel(PackageManifest manifest, string tempDir, Dispatcher dispatcher)
        {
            _manifest = manifest ?? throw new ArgumentNullException(nameof(manifest));
            _tempDir = tempDir ?? throw new ArgumentNullException(nameof(tempDir));
            _dispatcher = dispatcher;

            // Build item list from manifest
            foreach (var file in manifest.Files.OrderBy(f => f.InstallOrder))
                Items.Add(new InstallerItemViewModel(file, tempDir));

            // Watch each item's IsSelected so totals stay in sync
            foreach (var item in Items)
                item.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(InstallerItemViewModel.IsSelected))
                        RecalculateTotals();
                };

            RecalculateTotals();

            AcceptDisclaimerCommand = new RelayCommand(
                _ => { Phase = InstallPhase.Selection; },
                _ => DisclaimerAccepted);
            InstallCommand = new RelayCommand(_ => _ = BeginInstallAsync(),
                                                  _ => Phase == InstallPhase.Selection && SelectedCount > 0);
            CancelCommand = new RelayCommand(_ => _cts?.Cancel(),
                                                  _ => Phase == InstallPhase.Installing);
            SelectAllCommand = new RelayCommand(_ => SetAllSelected(true),
                                                  _ => Phase == InstallPhase.Selection);
            DeselectAllCommand = new RelayCommand(_ => SetAllSelected(false),
                                                  _ => Phase == InstallPhase.Selection);
            RetryFailedCommand = new RelayCommand(_ => _ = RetryFailedAsync(),
                                                  _ => Phase == InstallPhase.Complete
                                                    && Items.Any(i => i.Status == InstallItemStatus.Failed));
            OpenLogCommand = new RelayCommand(_ =>
            {
                var path = Infrastrucure.StubLogger.LogPath;
                if (!string.IsNullOrEmpty(path) && System.IO.File.Exists(path))
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = path,
                        UseShellExecute = true
                    });
            }, _ => !string.IsNullOrEmpty(Infrastrucure.StubLogger.LogPath));
        }

        // ── Install flow ──────────────────────────────────────────────────────

        private async Task BeginInstallAsync()
        {
            if (Phase != InstallPhase.Selection) return;

            Phase = InstallPhase.Installing;
            StatusMessage = "Installing...";
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;

            var toRun = Items.Where(i => i.IsSelected).ToList();
            int done = 0;

            try
            {
                foreach (var item in toRun)
                {
                    ct.ThrowIfCancellationRequested();

                    Dispatch(() =>
                    {
                        item.Status = InstallItemStatus.Installing;
                        StatusMessage = $"Installing {item.DisplayName}... ({done + 1}/{toRun.Count})";
                        OverallPercent = done * 100 / toRun.Count;
                    });

                    var file = _manifest.Files.First(f => f.Name == item.FileName);
                    string filePath = System.IO.Path.Combine(_tempDir, file.Name);
                    var silentArgs = InstallerRunner.ResolveSilentArgs(file, StubLogger.Log);

                    int exitCode = await InstallerRunner.RunSingleInstallerAsync(
                        file, filePath, silentArgs, _tempDir,
                        msg => Dispatch(() => StubLogger.Log(msg)),
                        msg => Dispatch(() => StubLogger.LogError(msg, null)));

                    var result = ExitCodeClassifier.Classify(exitCode);
                    bool success = ExitCodeClassifier.IsSuccess(result);
                    bool reboot = result is ExitCodeResult.SuccessRebootRequired
                                         or ExitCodeResult.SuccessRebootInitiated;

                    Dispatch(() =>
                    {
                        item.Status = success ? InstallItemStatus.Done : InstallItemStatus.Failed;
                        item.StatusDetail = ExitCodeClassifier.Describe(exitCode);
                        if (reboot) RebootRequired = true;
                    });

                    done++;
                }
            }
            catch (OperationCanceledException)
            {
                Dispatch(() =>
                {
                    // Mark remaining waiting items as skipped
                    foreach (var item in Items.Where(i => i.Status == InstallItemStatus.Waiting
                                                       || i.Status == InstallItemStatus.Installing))
                        item.Status = InstallItemStatus.Skipped;
                    StatusMessage = "Installation cancelled.";
                });
            }
            finally
            {
                _cts.Dispose();
                _cts = null;

                bool anyFailed = Items.Any(i => i.Status == InstallItemStatus.Failed);
                bool allDone = Items.Where(i => i.IsSelected)
                                      .All(i => i.Status is InstallItemStatus.Done
                                                          or InstallItemStatus.Failed
                                                          or InstallItemStatus.Skipped);

                Dispatch(() =>
                {
                    InstallSucceeded = !anyFailed;
                    OverallPercent = 100;
                    Phase = InstallPhase.Complete;
                    StatusMessage = anyFailed
                        ? "Completed with errors — see details below."
                        : RebootRequired
                            ? "All apps installed. A restart is required to complete setup."
                            : "All apps installed successfully.";
                });
            }
        }

        private async Task RetryFailedAsync()
        {
            // Reset failed items back to Waiting and re-select them
            foreach (var item in Items.Where(i => i.Status == InstallItemStatus.Failed))
            {
                item.Status = InstallItemStatus.Waiting;
                item.StatusDetail = string.Empty;
                item.IsSelected = true;
            }
            // Deselect everything else so only the previously-failed items run
            foreach (var item in Items.Where(i => i.Status != InstallItemStatus.Waiting))
                item.IsSelected = false;

            Phase = InstallPhase.Selection;
            await BeginInstallAsync();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void RecalculateTotals()
        {
            SelectedCount = Items.Count(i => i.IsSelected);
        }

        private void SetAllSelected(bool value)
        {
            foreach (var item in Items)
                item.IsSelected = value;
        }

        private void Dispatch(Action action)
        {
            if (_dispatcher.CheckAccess())
                action();
            else
                _dispatcher.Invoke(action);
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] u = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return $"{v:0.#} {u[i]}";
        }
    }

    // Minimal RelayCommand — same pattern as PackItPro, avoids a dependency on it
    internal class RelayCommand : ICommand
    {
        private readonly Action<object?> _execute;
        private readonly Func<object?, bool>? _canExecute;

        public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public bool CanExecute(object? p) => _canExecute?.Invoke(p) ?? true;
        public void Execute(object? p) => _execute(p);
    }
}