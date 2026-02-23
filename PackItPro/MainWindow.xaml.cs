using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using PackItPro.ViewModels;

namespace PackItPro
{
    /// <summary>
    /// Main application window with proper initialization and cleanup
    /// </summary>
    public partial class MainWindow : Window
    {
        private MainViewModel? _viewModel;

        public MainWindow()
        {
            InitializeComponent();
            
            // ✅ Add window event handlers for proper lifecycle management
            Loaded += Window_Loaded;
            Closing += Window_Closing;
        }

        /// <summary>
        /// Initialize the application when window loads
        /// </summary>
        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Get the ViewModel from DataContext
            if (this.DataContext is MainViewModel vm)
            {
                _viewModel = vm;

                try
                {
                    // Initialize asynchronously
                    await vm.InitializeAsync();
                }
                catch (Exception ex)
                {
                    // Show critical error if initialization completely fails
                    MessageBox.Show(
                        $"Failed to initialize application:\n{ex.Message}\n\nThe application will now close.",
                        "Initialization Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    // Close application if initialization fails
                    Application.Current.Shutdown(1);
                }
            }
            else
            {
                MessageBox.Show(
                    "Failed to initialize application: ViewModel not found.\n\nThe application will now close.",
                    "Critical Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);

                Application.Current.Shutdown(1);
            }
        }

        /// <summary>
        /// Clean up resources when window is closing
        /// </summary>
        private void Window_Closing(object? sender, CancelEventArgs e)
        {
            // ✅ Save settings before closing
            if (_viewModel != null)
            {
                try
                {
                    // Fire-and-forget save (already async in ViewModel)
                    _ = _viewModel.Settings.SaveSettingsAsync();
                }
                catch
                {
                    // Ignore save errors on close
                }
            }

            // ✅ Dispose ViewModel to prevent memory leaks
            _viewModel?.Dispose();
        }

        /// <summary>
        /// Handle unhandled exceptions in the UI thread
        /// This is a safety net for unexpected errors
        /// </summary>
        protected override void OnInitialized(EventArgs e)
        {
            base.OnInitialized(e);

            // ✅ Subscribe to global exception handler
            Application.Current.DispatcherUnhandledException += (s, args) =>
            {
                // Log the error
                System.Diagnostics.Debug.WriteLine($"Unhandled exception: {args.Exception}");

                // Show error to user via ErrorViewModel if available
                if (_viewModel?.Error != null)
                {
                    _viewModel.Error.ShowError(
                        $"An unexpected error occurred:\n{args.Exception.Message}\n\nCheck logs for details.");
                }
                else
                {
                    MessageBox.Show(
                        $"An unexpected error occurred:\n{args.Exception.Message}",
                        "Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }

                // Mark as handled to prevent crash
                args.Handled = true;
            };
        }
    }
}