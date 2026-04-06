// PackItPro/MainWindow.xaml.cs
using PackItPro.Services;
using PackItPro.ViewModels;
using PackItPro.Views;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;

namespace PackItPro
{
    public partial class MainWindow : Window
    {
        private MainViewModel? _viewModel;
        private bool _themeTransitionRunning;

        // ── Konami code Easter egg ────────────────────────────────────────────
        // Sequence: ↑ ↑ ↓ ↓ ← → ← → B A
        // Pressing this while the main window is focused shows a brief
        // Miku-themed celebration overlay. A small gift for curious users.
        private static readonly Key[] KonamiSequence =
        {
            Key.Up, Key.Up, Key.Down, Key.Down,
            Key.Left, Key.Right, Key.Left, Key.Right,
            Key.B, Key.A
        };
        private readonly Queue<Key> _konamiBuffer = new();
        private bool _easterEggShown;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += Window_Loaded;
            Closing += Window_Closing;

            // Subscribe to theme changes for a smooth fade transition.
            ThemeService.ThemeChanged += OnThemeChanged;

            // Wire Konami code detection.
            PreviewKeyDown += OnPreviewKeyDownKonami;
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

        private void OnThemeChanged(object? sender, string themeName)
        {
            if (_themeTransitionRunning) return;
            _themeTransitionRunning = true;

            var fadeOut = new DoubleAnimation(1.0, 0.82, TimeSpan.FromMilliseconds(60))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
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

        // ── Konami code Easter egg ────────────────────────────────────────────

        /// <summary>
        /// Accumulates key presses into a sliding window buffer and checks
        /// whether the last N keys match the Konami sequence.
        /// Only fires once per session so it doesn't get annoying.
        /// </summary>
        private void OnPreviewKeyDownKonami(object sender, KeyEventArgs e)
        {
            // Only track when not typing in a TextBox (don't intercept user input).
            if (Keyboard.FocusedElement is System.Windows.Controls.TextBox)
            {
                _konamiBuffer.Clear();
                return;
            }

            _konamiBuffer.Enqueue(e.Key);

            // Keep only the last N keys (sliding window).
            while (_konamiBuffer.Count > KonamiSequence.Length)
                _konamiBuffer.Dequeue();

            if (_konamiBuffer.Count == KonamiSequence.Length && !_easterEggShown)
            {
                var buf = _konamiBuffer.ToArray();
                bool match = true;
                for (int i = 0; i < KonamiSequence.Length; i++)
                    if (buf[i] != KonamiSequence[i]) { match = false; break; }

                if (match)
                {
                    _easterEggShown = true;
                    ShowEasterEgg();
                }
            }
        }

        /// <summary>
        /// Shows a brief full-window overlay with a Miku-themed celebration.
        /// The overlay fades in over 300ms, stays for 3s, then fades out.
        /// It's purely visual — no buttons, no interaction required.
        /// </summary>
        private void ShowEasterEgg()
        {
            var overlay = new EasterEggOverlay
            {
                Owner = this,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                ShowInTaskbar = false,
            };
            overlay.Show();
        }
    }
}
