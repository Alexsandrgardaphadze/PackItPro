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
        private Storyboard? _progressStoryboard;
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
            _progressStoryboard = (Storyboard)Resources["ProgressSmoothStoryboard"];

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
                if (_spinAnimation != null)
                    ApplySpinnerState(newVm.IsBusy);
            }
        }

        private void OnStatusPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (sender is not StatusViewModel vm) return;

            switch (e.PropertyName)
            {
                case nameof(StatusViewModel.IsBusy):
                    Dispatcher.InvokeAsync(() => ApplySpinnerState(vm.IsBusy));
                    break;

                case nameof(StatusViewModel.ProgressPercentage):
                    // Animate the progress bar to the new value smoothly.
                    // Must run on the UI thread.
                    Dispatcher.InvokeAsync(() => AnimateProgress(vm.ProgressPercentage));
                    break;
            }
        }

        private void ApplySpinnerState(bool isBusy)
        {
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

        /// <summary>
        /// Smoothly animates the ProgressBar to <paramref name="target"/> over 250 ms.
        /// Uses the storyboard defined in XAML so the animation is GPU-composited.
        /// </summary>
        private void AnimateProgress(double target)
        {
            if (_progressStoryboard == null) return;

            // Get the DoubleAnimation from the storyboard and set its To value.
            if (_progressStoryboard.Children[0] is DoubleAnimation anim)
            {
                anim.From = ProgressBar.Value;
                anim.To = target;
                _progressStoryboard.Begin(this, isControllable: true);
            }
        }
    }
}
