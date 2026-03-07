using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using PackItPro.ViewModels;

namespace PackItPro
{
    public partial class MainWindow : Window
    {
        private MainViewModel? _viewModel;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += Window_Loaded;
            Closing += Window_Closing;
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (this.DataContext is MainViewModel vm)
            {
                _viewModel = vm;

                try
                {
                    await vm.InitializeAsync();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        $"Failed to initialize application:\n{ex.Message}\n\nThe application will now close.",
                        "Initialization Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

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

        private void Window_Closing(object? sender, CancelEventArgs e)
        {
            if (_viewModel != null)
            {
                try { _ = _viewModel.Settings.SaveSettingsAsync(); }
                catch { }
            }

            _viewModel?.Dispose();
        }

        protected override void OnInitialized(EventArgs e)
        {
            base.OnInitialized(e);

            // Safety net for unexpected UI-thread exceptions — logged and shown via ErrorViewModel.
            Application.Current.DispatcherUnhandledException += (s, args) =>
            {
                System.Diagnostics.Debug.WriteLine($"Unhandled exception: {args.Exception}");

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

                args.Handled = true;
            };
        }
    }
}