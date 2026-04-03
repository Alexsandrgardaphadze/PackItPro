// PackItPro/Views/ShortcutsManagerWindow.xaml.cs
using PackItPro.ViewModels;
using System.Windows;

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
    }
}

