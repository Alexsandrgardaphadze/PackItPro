// PackItPro/Views/ShortcutsManagerWindow.xaml.cs
using PackItPro.ViewModels;
using System.Windows;
using System.Windows.Controls;

namespace PackItPro.Views
{
    /// <summary>
    /// Modal window for managing shortcuts.
    /// Displayed via Shortcuts > Manage Shortcuts or by pressing Alt+Shift+A.
    /// </summary>
    public partial class ShortcutsManagerWindow : Window
    {
        public ShortcutsManagerWindow(ShortcutListViewModel shortcuts)
        {
            InitializeComponent();
            var dataContext = shortcuts;
            DataContext = dataContext;

            // Wire the CloseCommand to close this window
            dataContext.CloseCommand = new RelayCommand(_ => Close());
        }

        /// <summary>
        /// Allows user to browse for an executable to set as the shortcut target.
        /// Triggered by the "…" button next to the TargetPath field.
        /// </summary>
        private void BrowseTargetPath_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
                Title = "Select target executable"
            };

            if (dlg.ShowDialog() == true)
            {
                // Get the data context of the shortcut being edited
                if ((sender as FrameworkElement)?.DataContext is ShortcutViewModel vm)
                {
                    vm.TargetPath = dlg.FileName;
                }
            }
        }
    }
}

