// ViewModels/CommandHandlers/HelpHandler.cs - v2.2 FIXED
using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    /// <summary>
    /// Handles all help-related operations (Documentation, GitHub, About, etc.)
    /// </summary>
    public class HelpHandler : CommandHandlerBase
    {
        public ICommand DocumentationCommand { get; }
        public ICommand GitHubCommand { get; }
        public ICommand ReportIssueCommand { get; }
        public ICommand CheckUpdatesCommand { get; }
        public ICommand AboutCommand { get; }

        public HelpHandler()
        {
            DocumentationCommand = new RelayCommand(ExecuteDocumentation);
            GitHubCommand = new RelayCommand(ExecuteGitHub);
            ReportIssueCommand = new RelayCommand(ExecuteReportIssue);
            CheckUpdatesCommand = new RelayCommand(ExecuteCheckUpdates);
            AboutCommand = new RelayCommand(ExecuteAbout);
        }

        private void ExecuteDocumentation(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/Alexsandrgardaphadze/PackItPro/wiki",
                    UseShellExecute = true
                });
            }
            catch
            {
                MessageBox.Show(
                    "Could not open documentation.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro/wiki",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteGitHub(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/Alexsandrgardaphadze/PackItPro",
                    UseShellExecute = true
                });
            }
            catch
            {
                MessageBox.Show(
                    "Could not open GitHub repository.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteReportIssue(object? parameter)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/Alexsandrgardaphadze/PackItPro/issues",
                    UseShellExecute = true
                });
            }
            catch
            {
                MessageBox.Show(
                    "Could not open issue tracker.\nVisit: https://github.com/Alexsandrgardaphadze/PackItPro/issues",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExecuteCheckUpdates(object? parameter)
        {
            MessageBox.Show(
                "Update check feature not yet implemented.",
                "Check for Updates",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ExecuteAbout(object? parameter)
        {
            MessageBox.Show(
                "PackItPro v0.6.1\n\n" +
                "A secure package builder for bundling multiple applications.\n\n" +
                "Still in development, but already close to finishing.\n\n" +
                "© 2026 Maybe all rights reserved.\n\n" +
                "GitHub: https://github.com/Alexsandrgardaphadze/PackItPro",
                "About PackItPro",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }
}