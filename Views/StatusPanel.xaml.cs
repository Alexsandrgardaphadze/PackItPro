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
    /// Interaction logic for StatusPanel.xaml
    /// </summary>
    public partial class StatusPanel : UserControl
    {
        public StatusPanel()
        {
            InitializeComponent();
        }

        private void PackNow_Click(object sender, RoutedEventArgs e)
        {
            // Intentionally minimal: actual command is bound in MainViewModel.
        }

        private void Retry_Click(object sender, RoutedEventArgs e)
        {
            // Intentionally minimal: actual logic is handled by ViewModel command.
        }

        private void DismissError_Click(object sender, RoutedEventArgs e)
        {
            // Intentionally minimal: actual logic is handled by ViewModel command.
        }
    }
}
