// Views/ErrorPanel.xaml.cs - UPDATED VERSION
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using PackItPro.ViewModels;

namespace PackItPro.Views
{
    /// <summary>
    /// Interaction logic for ErrorPanel.xaml
    /// </summary>
    public partial class ErrorPanel : UserControl
    {
        public ErrorPanel()
        {
            InitializeComponent();

            // ✅ FIX: Subscribe to DataContext changes to wire up animation
            DataContextChanged += OnDataContextChanged;
        }

        private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            // Unsubscribe from old ViewModel
            if (e.OldValue is ErrorViewModel oldVm)
            {
                oldVm.ErrorShown -= OnErrorShown;
            }

            // Subscribe to new ViewModel
            if (e.NewValue is ErrorViewModel newVm)
            {
                newVm.ErrorShown += OnErrorShown;
            }
        }

        // ✅ FIX: Trigger animation when error is shown
        private void OnErrorShown(object? sender, EventArgs e)
        {
            // Play the slide-in animation
            var storyboard = (Storyboard)Resources["SlideInAnimation"];
            storyboard?.Begin();
        }
    }
}
