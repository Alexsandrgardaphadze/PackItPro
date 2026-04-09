// PackItPro/App.xaml.cs
//
// Resilient error handling strategy:
//   · DispatcherUnhandledException  — UI-thread errors: show dialog, stay open
//   · AppDomain.UnhandledException  — Fatal background crashes: log + close
//   · TaskScheduler.UnobservedTaskException — Fire-and-forget Task errors: log only
//
// The key insight: DispatcherUnhandledException can be marked Handled=true
// to prevent WPF from shutting down. We only shut down for truly unrecoverable
// errors (AppDomain-level, which usually mean a corrupted process state).
using PackItPro.Services;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace PackItPro
{
    public partial class App : Application
    {
        private static string? _logPath;

        // Tracks whether a dispatcher error dialog is already on screen to
        // prevent stacking multiple error dialogs if exceptions fire rapidly.
        private bool _dispatcherErrorDialogOpen;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var appDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppConstants.AppName);
            Directory.CreateDirectory(Path.Combine(appDataDir, AppConstants.CacheSubDir));
            Directory.CreateDirectory(Path.Combine(appDataDir, AppConstants.LogsSubDir));

            _logPath = Path.Combine(appDataDir, AppConstants.LogsSubDir, AppConstants.CrashLogFileName);

            ToastService.Initialize();

            // ── AppDomain — truly fatal, process is corrupted ─────────────────
            // These come from background threads that WPF can't intercept.
            // isTerminating will be true if the CLR is already shutting down —
            // in that case we can only log and let it die.
            AppDomain.CurrentDomain.UnhandledException += (s, ex) =>
            {
                var exception = (Exception)ex.ExceptionObject;
                LogError($"[AppDomain FATAL] {exception}");

                // Only try to show a dialog if the runtime isn't already tearing down.
                if (!ex.IsTerminating)
                {
                    try
                    {
                        MessageBox.Show(
                            $"A critical background error occurred.\n\n" +
                            $"The application will now close to prevent data corruption.\n\n" +
                            $"Error: {exception.Message}\n\n" +
                            $"Log file: {_logPath}",
                            "Fatal Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                    catch { /* If MessageBox itself fails, nothing more we can do */ }
                }

                // AppDomain-level exceptions = always fatal.
                Current?.Shutdown(1);
            };

            // ── Dispatcher — UI-thread errors, recoverable ────────────────────
            // Setting e.Handled = true keeps the app running.
            // We show a non-modal error message via the MainWindow's ErrorViewModel
            // when possible, falling back to MessageBox for very early failures.
            DispatcherUnhandledException += (s, ex) =>
            {
                LogError($"[Dispatcher] {ex.Exception}");

                // Mark as handled FIRST — this keeps WPF from shutting down.
                ex.Handled = true;

                // Avoid stacking dialogs if a rapid sequence of exceptions fires.
                if (_dispatcherErrorDialogOpen)
                    return;

                _dispatcherErrorDialogOpen = true;
                try
                {
                    // Try to surface the error via the ErrorViewModel (non-disruptive inline banner).
                    if (Current?.MainWindow?.DataContext is ViewModels.MainViewModel mainVm)
                    {
                        mainVm.Error.ShowError(
                            $"An unexpected error occurred: {ex.Exception.Message}\n" +
                            $"The app is still running. Check the log for details.");
                    }
                    else
                    {
                        // Fallback: MessageBox (early startup, or no MainWindow yet).
                        MessageBox.Show(
                            $"An unexpected error occurred but the application is still running.\n\n" +
                            $"Error: {ex.Exception.Message}\n\n" +
                            $"Log: {_logPath}",
                            "Unexpected Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                }
                catch
                {
                    // If even the error handling fails, swallow silently — we already
                    // marked e.Handled = true so the app won't crash.
                }
                finally
                {
                    _dispatcherErrorDialogOpen = false;
                }
            };

            // ── Task exceptions — fire-and-forget async methods ───────────────
            // These are usually programming errors (forgotten await). Log them
            // and mark observed so the finalizer doesn't crash the process.
            TaskScheduler.UnobservedTaskException += (s, ex) =>
            {
                LogError($"[UnobservedTask] {ex.Exception}");
                ex.SetObserved();
                // Don't show a dialog — these are usually low-priority background ops.
            };
        }

        protected override void OnExit(ExitEventArgs e)
        {
            LogError($"[OnExit] Application exited with code {e.ApplicationExitCode}.");
            base.OnExit(e);
        }

        private static void LogError(string message)
        {
            try
            {
                if (!string.IsNullOrEmpty(_logPath))
                    File.AppendAllText(_logPath,
                        $"[{DateTime.UtcNow:dd-MM-yyyy HH:mm:ss}] {message}\n\n");
            }
            catch { /* Log failures must be swallowed — never let logging crash the app */ }
        }
    }
}
