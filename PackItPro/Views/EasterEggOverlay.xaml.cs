// PackItPro/Views/EasterEggOverlay.xaml.cs
using System;
using System.Windows;
using System.Windows.Threading;

namespace PackItPro.Views
{
    /// <summary>
    /// A brief celebration overlay triggered by the Konami code.
    /// Auto-closes after 3.7 seconds (matching the fade-out animation end time).
    /// IsHitTestVisible=False on the Window means clicks pass through to the
    /// main window — the overlay is purely cosmetic and never blocks interaction.
    /// </summary>
    public partial class EasterEggOverlay : Window
    {
        // Total animation duration: 0.35s fade-in + 3.2s hold + 0.5s fade-out = 3.7s
        private static readonly TimeSpan AutoCloseDelay = TimeSpan.FromSeconds(3.8);

        public EasterEggOverlay()
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            // Position centred over the owner window.
            if (Owner != null)
            {
                Left = Owner.Left + (Owner.Width - Width) / 2;
                Top = Owner.Top + (Owner.Height - Height) / 2;
            }

            // Auto-close when the animation finishes.
            var timer = new DispatcherTimer
            {
                Interval = AutoCloseDelay
            };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                Close();
            };
            timer.Start();
        }
    }
}
