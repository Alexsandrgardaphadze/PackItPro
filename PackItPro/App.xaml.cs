// App.xaml.cs
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace PackItPro
{
    public partial class App : Application
    {
        private static string? _logPath;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var appDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PackItPro");
            Directory.CreateDirectory(appDataDir);

            _logPath = Path.Combine(appDataDir, "crash.log");

            AppDomain.CurrentDomain.UnhandledException += (s, ex) =>
                HandleFatalException("AppDomain", (Exception)ex.ExceptionObject);

            DispatcherUnhandledException += (s, ex) =>
            {
                HandleFatalException("Dispatcher", ex.Exception);
                ex.Handled = true;
                Current.Shutdown(1);
            };

            TaskScheduler.UnobservedTaskException += (s, ex) =>
            {
                LogError($"Unobserved task exception: {ex.Exception}");
                ex.SetObserved();
            };
        }

        protected override void OnExit(ExitEventArgs e)
        {
            // MainWindow.Window_Closing handles ViewModel save + dispose before we reach here.
            base.OnExit(e);
        }

        private void HandleFatalException(string source, Exception ex)
        {
            try
            {
                LogError($"[{source}] FATAL: {ex}");

                MessageBox.Show(
                    $"A critical error occurred. The application must close.\n\n" +
                    $"Log file: {_logPath}",
                    "Fatal Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch
            {
                MessageBox.Show("Critical error occurred.", "Fatal Error");
            }
            finally
            {
                Current.Shutdown(1);
            }
        }

        private void LogError(string message)
        {
            try
            {
                if (!string.IsNullOrEmpty(_logPath))
                    File.AppendAllText(_logPath, $"[{DateTime.UtcNow:dd-MM-yyyy HH:mm:ss}] {message}\n\n");
            }
            catch { }
        }
    }
}