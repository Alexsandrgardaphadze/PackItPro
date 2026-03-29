// StubInstaller/Views/MainInstallWindow.xaml.cs
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
        }

        private void CancelClose_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsInstallingPhase)
                ViewModel.CancelCommand.Execute(null);
            else
                Close();
        }
    }
}