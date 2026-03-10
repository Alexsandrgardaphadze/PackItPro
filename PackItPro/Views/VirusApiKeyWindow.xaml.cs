// PackItPro/Views/VirusApiKeyWindow.xaml.cs
using System.Windows;

namespace PackItPro.Views
{
    public partial class VirusApiKeyWindow : Window
    {
        public string ApiKey => ApiKeyBox.Text;

        public VirusApiKeyWindow(string currentKey)
        {
            InitializeComponent();
            ApiKeyBox.Text = currentKey;
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}