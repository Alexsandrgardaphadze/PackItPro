// PackItPro/MainWindow.xaml.cs
using PackItPro.Services;
using PackItPro.ViewModels;
using PackItPro.Views;
using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media.Animation;

namespace PackItPro
{
    public partial class MainWindow : Window
    {
        private MainViewModel? _viewModel;
        private bool _themeTransitionRunning;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += Window_Loaded;
            Closing += Window_Closing;

            // Subscribe to theme changes for a smooth fade transition.
            // The handler fades the root grid to 0.85 opacity, swaps the
            // dictionary (already done by ThemeService), then fades back to 1.
            ThemeService.ThemeChanged += OnThemeChanged;
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                _viewModel = vm;
                try
                {
                    await vm.InitializeAsync();
                }
                catch (Exception ex)
                {
                    AlertDialog.Show(this, "Initialization Error",
                        "Failed to initialize application. The application will now close.",
                        detail: ex.Message, kind: AlertDialog.Kind.Error);
                    Application.Current.Shutdown(1);
                }
            }
            else
            {
                AlertDialog.Show(this, "Critical Error",
                    "Failed to initialize application: ViewModel not found.",
                    kind: AlertDialog.Kind.Error);
                Application.Current.Shutdown(1);
            }
        }

        private void Window_Closing(object? sender, CancelEventArgs e)
        {
            ThemeService.ThemeChanged -= OnThemeChanged;

            if (_viewModel != null)
            {
                try { _ = _viewModel.Settings.SaveSettingsAsync(); }
                catch { }
            }
            _viewModel?.Dispose();
        }

        // ── Theme crossfade ───────────────────────────────────────────────────

        /// <summary>
        /// Brief opacity dip (0.85) when the theme dictionary is swapped so the
        /// color transition feels intentional rather than a jarring instant flash.
        /// The animation is 80ms — fast enough to feel snappy, slow enough to be
        /// perceptible. Guard against re-entrancy (_themeTransitionRunning).
        /// </summary>
        private void OnThemeChanged(object? sender, string themeName)
        {
            if (_themeTransitionRunning) return;
            _themeTransitionRunning = true;

            // Fade out
            var fadeOut = new DoubleAnimation(1.0, 0.82, TimeSpan.FromMilliseconds(60))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };

            // Fade back in — started when fade-out completes
            fadeOut.Completed += (_, _) =>
            {
                var fadeIn = new DoubleAnimation(0.82, 1.0, TimeSpan.FromMilliseconds(100))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                fadeIn.Completed += (_, _) => _themeTransitionRunning = false;
                RootGrid.BeginAnimation(OpacityProperty, fadeIn);
            };

            RootGrid.BeginAnimation(OpacityProperty, fadeOut);
        }
    }
}
