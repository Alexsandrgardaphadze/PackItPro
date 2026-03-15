// PackItPro/MainWindow.xaml.cs
using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using PackItPro.ViewModels;
using PackItPro.Views;

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
                    AlertDialog.Show(
                        this,
                        "Initialization Error",
                        "Failed to initialize application. The application will now close.",
                        detail: ex.Message,
                        kind: AlertDialog.Kind.Error);

                    Application.Current.Shutdown(1);
                }
            }
            else
            {
                AlertDialog.Show(
                    this,
                    "Critical Error",
                    "Failed to initialize application: ViewModel not found. The application will now close.",
                    kind: AlertDialog.Kind.Error);

                Application.Current.Shutdown(1);
            }
        }

        private void Window_Closing(object? sender, CancelEventArgs e)
        {
            if (_viewModel != null)
            {
                try { _ = _viewModel.Settings.SaveSettingsAsync(); }
                catch { /* ignore save errors on close */ }
            }

            _viewModel?.Dispose();
        }

        // OnInitialized override removed entirely.
        // The second DispatcherUnhandledException subscription that lived here:
        //   (a) caused a memory leak by capturing 'this' in a lambda held by Application
        //   (b) caused double-dialogs because App.xaml.cs already handles the same event
        // App.xaml.cs OnStartup is the single authoritative place for global handlers.
    }
}