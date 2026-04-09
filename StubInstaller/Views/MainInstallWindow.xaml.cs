// StubInstaller/Views/MainInstallWindow.xaml.cs
using StubInstaller.Core;
using StubInstaller.ViewModels;
using System.Windows;

namespace StubInstaller.Views
{
    public partial class MainInstallWindow : Window
    {
        public MainInstallViewModel ViewModel { get; }

        public MainInstallWindow(MainInstallViewModel viewModel)
        {
            InitializeComponent();
            ViewModel = viewModel;
            DataContext = viewModel;

            // Apply the theme from the manifest (or default dark).
            // The manifest could carry a "preferLightTheme" field in future;
            // for now we default to dark and let the toggle button flip it.
            Core.StubThemeService.Apply(this, Core.StubTheme.Dark);
        }

        private void CancelClose_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsInstallingPhase)
                ViewModel.CancelCommand.Execute(null);
            else
                Close();
        }

        /// <summary>
        /// Toggles dark / light theme. Wired to the theme button in the window header.
        /// x:Name="ThemeToggleButton" in XAML.
        /// </summary>
        private void ThemeToggle_Click(object sender, RoutedEventArgs e) =>
            Core.StubThemeService.Toggle(this);
    }
}
