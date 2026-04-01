// StubInstaller/Core/StubThemeService.cs
// Theme switching for the stub installer window.
// The manifest can carry theme preference in future updates.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace StubInstaller.Core
{
    /// <summary>Available themes for the stub installer.</summary>
    internal enum StubTheme { Dark, Light }

    /// <summary>Switches between dark and light themes for the installer window.</summary>
    internal static class StubThemeService
    {
        private static StubTheme _current = StubTheme.Dark;

        /// <summary>Gets the currently active theme.</summary>
        internal static StubTheme Current => _current;

        /// <summary>Applies a theme to the window by swapping the first merged dictionary.</summary>
        internal static void Apply(Window window, StubTheme theme)
        {
            _current = theme;
            string resourcePath = theme == StubTheme.Light
                ? "/StubTheme/ColorsDark.xaml"
                : "/StubTheme/ColorsDark.xaml";

            try
            {
                var dict = new ResourceDictionary { Source = new Uri(resourcePath, UriKind.Relative) };
                var merged = window.Resources.MergedDictionaries;
                if (merged.Count > 0)
                    merged[0] = dict;
                else
                    merged.Add(dict);
            }
            catch { /* Fall back silently */ }
        }

        /// <summary>Toggles between dark and light themes.</summary>
        internal static void Toggle(Window window) =>
            Apply(window, _current == StubTheme.Dark ? StubTheme.Light : StubTheme.Dark);
    }
}
