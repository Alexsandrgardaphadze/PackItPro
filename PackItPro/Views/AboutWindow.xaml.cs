// Views/AboutWindow.xaml.cs
using PackItPro.Services;
using System;
using System.Diagnostics;
using System.Windows;

namespace PackItPro.Views
{
    public partial class AboutWindow : Window
    {
        public AboutWindow()
        {
            InitializeComponent();
            VersionText.Text = UpdateService.CurrentVersion;
        }

        private void GitHubButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo(
                    "https://github.com/Alexsandrgardaphadze/PackItPro")
                { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AlertDialog.Show(this, "Cannot Open Browser",
                    "Could not open the GitHub page.",
                    detail: ex.Message, kind: AlertDialog.Kind.Error);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
    }
}
