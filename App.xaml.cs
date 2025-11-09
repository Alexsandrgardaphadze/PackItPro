using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace PackItPro
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Single instance check
            /* using var mutex = new Mutex(true, "PackItPro-InstanceMutex", out bool createdNew);
            if (!createdNew)
            {
                MessageBox.Show("Another instance is already running.");
                Current.Shutdown();
                return;
            } */

            // Global exception handlers
            AppDomain.CurrentDomain.UnhandledException += (s, ex) =>
                HandleFatalException("AppDomain", (Exception)ex.ExceptionObject);

            DispatcherUnhandledException += (s, ex) =>
            {
                HandleFatalException("Dispatcher", ex.Exception);
                ex.Handled = true;
                Current.Shutdown();
            };

            TaskScheduler.UnobservedTaskException += (s, ex) =>
            {
                HandleFatalException("Task", ex.Exception);
                ex.SetObserved();
            };
        }

        private void HandleFatalException(string source, Exception ex)
        {
            try
            {
                // Log the error with timestamp
                File.AppendAllText("crash.log",
                    $"[{DateTime.UtcNow:u}] [{source}] CRASH: {ex}\n\n");

                // Show user-friendly message
                MessageBox.Show(
                    "A critical error occurred. The application must close.\n" +
                    "Technical details have been saved to crash.log",
                    "Fatal Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch (Exception loggingEx)
            {
                MessageBox.Show($"Failed to handle error: {loggingEx.Message}");
            }
            finally
            {
                Current.Shutdown(1);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            // Add any cleanup logic here if needed
            base.OnExit(e);
        }
    }
}