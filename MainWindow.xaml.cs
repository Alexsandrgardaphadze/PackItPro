using System.Threading.Tasks;
using System.Windows;
using PackItPro.ViewModels;

namespace PackItPro
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Initialize the MainViewModel after window is loaded
            if (this.DataContext is MainViewModel vm)
            {
                await vm.InitializeAsync();
            }
        }
    }
}