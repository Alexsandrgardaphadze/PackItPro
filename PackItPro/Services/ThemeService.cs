// PackItPro/Services/ThemeService.cs
using System;
using System.Windows;

namespace PackItPro.Services
{
    /// <summary>
    /// Switches between dark and light themes at runtime by swapping the first
    /// merged dictionary in <c>App.xaml</c> (the color dictionary) for the
    /// appropriate <c>ColorsDark.xaml</c> or <c>ColorsLight.xaml</c>.
    ///
    /// All other resource dictionaries (Controls, Styles, etc.) use
    /// <c>{StaticResource}</c> keys that are resolved at load time — they do not
    /// need to be reloaded because the color brushes themselves are replaced in the
    /// merged dictionary, and WPF re-evaluates <c>{DynamicResource}</c> references
    /// automatically when the source dictionary changes.
    ///
    /// Usage:
    ///   ThemeService.Apply(AppTheme.Light);   // switch to light
    ///   ThemeService.Apply(AppTheme.Dark);    // switch back to dark
    ///   ThemeService.Toggle();                // flip current theme
    ///   bool isDark = ThemeService.IsDark;
    /// </summary>
    public static class ThemeService
    {
        private const string DarkUri = "/Themes/ColorsDark.xaml";
        private const string LightUri = "/Themes/ColorsLight.xaml";

        /// <summary>Current active theme. Dark by default on first run.</summary>
        public static AppTheme Current { get; private set; } = AppTheme.Dark;

        /// <summary>True when the dark theme is active.</summary>
        public static bool IsDark => Current == AppTheme.Dark;

        /// <summary>Raised after the theme changes. Carries the new theme value.</summary>
        public static event EventHandler<AppTheme>? ThemeChanged;

        /// <summary>
        /// Applies <paramref name="theme"/> immediately.
        /// Safe to call from any thread — marshals to the UI dispatcher.
        /// </summary>
        public static void Apply(AppTheme theme)
        {
            var app = Application.Current;
            if (app == null) return;

            // Always execute on the UI thread.
            if (!app.Dispatcher.CheckAccess())
            {
                app.Dispatcher.Invoke(() => Apply(theme));
                return;
            }

            string uri = theme == AppTheme.Light ? LightUri : DarkUri;
            var newDict = new ResourceDictionary
            {
                Source = new Uri(uri, UriKind.Relative)
            };

            var merged = app.Resources.MergedDictionaries;

            // Replace the first dictionary (always the color dictionary).
            // Index 0 is guaranteed by App.xaml merge order:
            //   [0] Colors*.xaml  [1] Converters  [2] FluentIcons  [3] Controls  [4] Styles
            if (merged.Count > 0)
                merged[0] = newDict;
            else
                merged.Add(newDict);

            Current = theme;
            ThemeChanged?.Invoke(null, theme);
        }

        /// <summary>Toggles between dark and light.</summary>
        public static void Toggle() =>
            Apply(Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);

        /// <summary>
        /// Restores the theme that was last saved to <see cref="AppSettings"/>.
        /// Call this during app startup after settings are loaded.
        /// </summary>
        public static void ApplyFromSettings(bool preferLight) =>
            Apply(preferLight ? AppTheme.Light : AppTheme.Dark);
    }

    /// <summary>Available application themes.</summary>
    public enum AppTheme { Dark, Light }
}
