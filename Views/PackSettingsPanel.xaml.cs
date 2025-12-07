using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace PackItPro.Views
{
    /// <summary>
    /// Interaction logic for PackSettingsPanel.xaml
    /// </summary>
    public partial class PackSettingsPanel : UserControl
    {
        public PackSettingsPanel()
        {
            InitializeComponent();
        }

        private void RequireAdminCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            // Event handler intentionally left minimal. Settings are bound to ViewModel.
        }

        private void OnlyScanExecutablesCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            // Event handler intentionally left minimal. Settings are bound to ViewModel.
        }

        private void AutoRemoveInfectedFilesCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            // Event handler intentionally left minimal. Settings are bound to ViewModel.
        }
    }
}
