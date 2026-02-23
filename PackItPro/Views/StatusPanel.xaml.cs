using System.Windows.Controls;

namespace PackItPro.Views
{
    /// <summary>
    /// Interaction logic for StatusPanel.xaml
    /// Pure MVVM implementation - all actions handled via Command bindings
    /// </summary>
    public partial class StatusPanel : UserControl
    {
        public StatusPanel()
        {
            InitializeComponent();
        }

        // ✅ No event handlers needed - StatusPanel uses Command binding
        // The XAML uses:
        // - Command="{Binding PackCommand}" for the Pack button
        // - All status display is data-bound to StatusViewModel properties
        
        // Note: The original Retry_Click and DismissError_Click handlers were for ErrorPanel,
        // not StatusPanel. Those are now properly implemented in ErrorPanel.xaml with
        // ErrorViewModel commands (RetryCommand and DismissErrorCommand).
    }
}
