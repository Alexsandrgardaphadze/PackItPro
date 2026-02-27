using System.Windows.Controls;

namespace PackItPro.Views
{
    /// <summary>
    /// Interaction logic for PackSettingsPanel.xaml
    /// Pure MVVM implementation - all data binding handled in XAML
    /// </summary>
    public partial class PackSettingsPanel : UserControl
    {
        public PackSettingsPanel()
        {
            InitializeComponent();
        }

        // ✅ No event handlers needed - all settings are two-way bound to SettingsViewModel
        // The XAML uses:
        // - IsChecked="{Binding PropertyName, Mode=TwoWay}" for checkboxes
        // - Text="{Binding PropertyName, Mode=TwoWay}" for textboxes
        // - SelectedIndex="{Binding PropertyName, Mode=TwoWay}" for comboboxes
        
        // This approach ensures:
        // 1. Immediate updates to ViewModel when user changes settings
        // 2. No manual event handling required
        // 3. Settings automatically persist via SettingsViewModel.SaveSettingsAsync()
    }
}
