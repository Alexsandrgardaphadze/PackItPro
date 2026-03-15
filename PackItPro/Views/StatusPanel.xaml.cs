// PackItPro/Views/StatusPanel.xaml.cs
using PackItPro.ViewModels;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace PackItPro.Views
{
    public partial class StatusPanel : UserControl
    {
        private Storyboard? _spinAnimation;
        private bool _isSpinning;

        public StatusPanel()
        {
            InitializeComponent();
            DataContextChanged += OnDataContextChanged;
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            _spinAnimation = (Storyboard)Resources["SpinAnimation"];
            // Sync state in case IsBusy was already true when we loaded
            if (DataContext is StatusViewModel vm)
                ApplySpinnerState(vm.IsBusy);
        }

        private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (e.OldValue is StatusViewModel oldVm)
                oldVm.PropertyChanged -= OnStatusPropertyChanged;

            if (e.NewValue is StatusViewModel newVm)
            {
                newVm.PropertyChanged += OnStatusPropertyChanged;
                // Sync immediately (DataContext can be set before or after Loaded)
                if (_spinAnimation != null)
                    ApplySpinnerState(newVm.IsBusy);
            }
        }

        private void OnStatusPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(StatusViewModel.IsBusy)) return;
            if (sender is StatusViewModel vm)
            {
                // PropertyChanged can fire from a background thread (e.g. scan task)
                Dispatcher.InvokeAsync(() => ApplySpinnerState(vm.IsBusy));
            }
        }

        private void ApplySpinnerState(bool isBusy)
        {
            // _spinAnimation may be null if called before Loaded fires
            if (_spinAnimation == null) return;

            if (isBusy && !_isSpinning)
            {
                _spinAnimation.Begin();
                _isSpinning = true;
            }
            else if (!isBusy && _isSpinning)
            {
                _spinAnimation.Stop();
                _isSpinning = false;
            }
        }
    }
}
