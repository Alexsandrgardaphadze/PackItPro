// PackItPro/Views/ShortcutsPanel.xaml.cs
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using PackItPro.ViewModels;

namespace PackItPro.Views
{
    /// <summary>
    /// Interaction logic for ShortcutsPanel.xaml
    /// Pure MVVM — all logic lives in <see cref="ViewModels.ShortcutListViewModel"/>.
    /// 
    /// Code-behind handles:
    /// - Keyboard shortcuts (Alt+A for Add)
    /// - Initial focus management
    /// - Accessibility event handling
    /// </summary>
    public partial class ShortcutsPanel : UserControl
    {
        public ShortcutsPanel()
        {
            InitializeComponent();
            
            // Focus management: when panel loads with no shortcuts,
            // focus the Add button so keyboard users know where to start
            Loaded += ShortcutsPanel_Loaded;
        }

        private void ShortcutsPanel_Loaded(object sender, RoutedEventArgs e)
        {
            if (DataContext is ShortcutListViewModel vm && !vm.HasShortcuts)
            {
                // Set focus to the Add button when the panel is first loaded empty
                AddShortcutButton?.Focus();
                Keyboard.Focus(AddShortcutButton);
            }
        }
    }
}

// ============================================================
// MainViewModel.cs — 4 small changes needed
// ============================================================
//
// 1. Add property (alongside FileList, Summary, etc.):
//
//    public ShortcutListViewModel Shortcuts { get; }
//
// 2. In the constructor, after Summary = ...:
//
//    Shortcuts = new ShortcutListViewModel();
//
// 3. Pass Shortcuts to PackagingCommandHandler (InitializeHandlers):
//
//    _packagingHandler = new PackagingCommandHandler(
//        FileList, Settings, Status, Error, _logService, Shortcuts);
//
// 4. Add to NotifyAllCommandsAvailable():
//
//    OnPropertyChanged(nameof(Shortcuts));
//
// ============================================================
// MainWindow.xaml — add ShortcutsPanel to the right-hand column
// ============================================================
//
// Inside the ScrollViewer > StackPanel in Grid.Column="1", add
// ShortcutsPanel ABOVE PackSettingsPanel:
//
//   <views:ShortcutsPanel  DataContext="{Binding Shortcuts}" Margin="0,0,0,10"/>
//   <views:PackSettingsPanel DataContext="{Binding Settings}" Margin="0,0,0,10"/>
//   <views:SummaryPanel    DataContext="{Binding Summary}"/>
//
// Also register ShortcutsPanel in PackItPro.csproj if you have explicit
// <Page> entries — add the same block as the other panels:
//
//   <Page Update="Views\ShortcutsPanel.xaml">
//     <Generator></Generator>
//     <CopyToOutputDirectory>Never</CopyToOutputDirectory>
//   </Page>