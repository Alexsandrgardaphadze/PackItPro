// PackItPro/Views/EasterEggOverlay.xaml.cs
using System;
using System.Media;
using System.Windows;
using System.Windows.Threading;

namespace PackItPro.Views
{
    /// <summary>
    /// Miku-themed celebration overlay triggered by the Konami code (↑↑↓↓←→←→BA).
    /// Auto-closes after ~4.8 seconds matching the fade-out animation.
    /// IsHitTestVisible=False means all clicks pass through to the main window.
    /// </summary>
    public partial class EasterEggOverlay : Window
    {
        private static readonly TimeSpan AutoCloseDelay = TimeSpan.FromSeconds(4.8);

        private static readonly string[] Quotes =
        {
            "Hatsune Miku says: keep packaging and never stop. 💙",
            "\"The world is filled with lots of people. I want to meet them all!\" — Miku",
            "You pressed the Konami code in a packaging tool.\nMiku respects your priorities. 🎵",
            "Packaging is just music for files. — Miku, probably",
            "\"Even if we can't meet, I'll always be singing for you.\" — Miku",
            "39 (サンキュー) means 'thank you' in Miku-speak.\nThanks for using PackItPro! 🌟",
            "Miku has packaged 39,390,390 songs.\nYou've packed maybe fewer. Keep going! ✨",
            "In another life, StubInstaller.exe was a concert hall. — Miku lore",
            "\"I'll keep on singing until everyone can hear me!\" — Miku",
            "The real package was the friends we made along the way. 💙",
        };

        private static readonly Random _rng = new();

        public EasterEggOverlay()
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            QuoteText.Text = Quotes[_rng.Next(Quotes.Length)];

            if (Owner != null)
            {
                Left = Owner.Left + (Owner.Width - Width) / 2;
                Top = Owner.Top + (Owner.Height - Height) / 2;
            }

            TryPlaySound();

            var timer = new DispatcherTimer { Interval = AutoCloseDelay };
            timer.Tick += (_, _) => { timer.Stop(); Close(); };
            timer.Start();
        }

        private static void TryPlaySound()
        {
            try { SystemSounds.Asterisk.Play(); }
            catch { }
        }
    }
}
