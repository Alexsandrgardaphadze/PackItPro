// PackItPro/Services/ThemeService.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace PackItPro.Services
{
    /// <summary>
    /// Manages application themes at runtime.
    ///
    /// Built-in themes:
    ///   Dark  → /Themes/ColorsDark.xaml
    ///   Light → /Themes/ColorsLight.xaml
    ///
    /// Custom theme packs:
    ///   Drop a .xaml ResourceDictionary into
    ///   %AppData%\PackItPro\Themes\  and it appears in
    ///   <see cref="AvailableThemes"/> automatically.
    ///   The file must define all AppXxx brush keys (copy ColorsDark.xaml as a template).
    ///
    /// Switching:
    ///   ThemeService.Apply(AppTheme.Light);
    ///   ThemeService.Apply("MyTheme");   // custom pack by display name
    ///   ThemeService.Toggle();           // flips between Dark and Light
    ///
    /// App.Resources.MergedDictionaries[0] is always the active color dictionary.
    /// All other consumers use {DynamicResource} so changes propagate instantly.
    /// </summary>
    public static class ThemeService
    {
        // ── Built-in URIs ─────────────────────────────────────────────────────
        private const string DarkUri = "/Themes/ColorsDark.xaml";
        private const string LightUri = "/Themes/ColorsLight.xaml";

        // ── Custom themes folder ──────────────────────────────────────────────
        private static readonly string CustomThemesFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PackItPro", "Themes");

        // ── State ─────────────────────────────────────────────────────────────

        /// <summary>Current active theme (built-in enum value).</summary>
        public static AppTheme Current { get; private set; } = AppTheme.Dark;

        /// <summary>Display name of the active theme (e.g. "Dark", "Light", "Neon").</summary>
        public static string CurrentName { get; private set; } = "Dark";

        /// <summary>True when the dark built-in theme is active.</summary>
        public static bool IsDark => Current == AppTheme.Dark;

        /// <summary>Raised after the theme changes. Carries the new theme name.</summary>
        public static event EventHandler<string>? ThemeChanged;

        // ── Available themes ──────────────────────────────────────────────────

        /// <summary>
        /// Returns all available theme display names: built-ins first, then
        /// any valid .xaml files found in the custom themes folder.
        /// </summary>
        public static IReadOnlyList<string> AvailableThemes
        {
            get
            {
                var list = new List<string> { "Dark", "Light" };
                foreach (var pack in DiscoverCustomPacks())
                    list.Add(Path.GetFileNameWithoutExtension(pack));
                return list;
            }
        }

        // ── Apply ─────────────────────────────────────────────────────────────

        /// <summary>Applies a built-in theme. Thread-safe — marshals to UI thread.</summary>
        public static void Apply(AppTheme theme)
        {
            string uri = theme == AppTheme.Light ? LightUri : DarkUri;
            string name = theme.ToString();

            SwapColorDictionary(
                new ResourceDictionary { Source = new Uri(uri, UriKind.Relative) },
                name);

            Current = theme;
            CurrentName = name;
        }

        /// <summary>
        /// Applies a theme by display name.
        /// "Dark" and "Light" resolve to built-ins.
        /// Any other name is looked up in the custom themes folder.
        /// Returns false if the name is not found or the file fails to load.
        /// </summary>
        public static bool Apply(string name)
        {
            if (string.Equals(name, "Dark", StringComparison.OrdinalIgnoreCase))
            { Apply(AppTheme.Dark); return true; }
            if (string.Equals(name, "Light", StringComparison.OrdinalIgnoreCase))
            { Apply(AppTheme.Light); return true; }

            // Look for a matching .xaml in the custom folder.
            foreach (var path in DiscoverCustomPacks())
            {
                if (!string.Equals(
                    Path.GetFileNameWithoutExtension(path), name,
                    StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    var dict = new ResourceDictionary
                    { Source = new Uri(path, UriKind.Absolute) };
                    SwapColorDictionary(dict, name);
                    Current = AppTheme.Custom;
                    CurrentName = name;
                    return true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"[ThemeService] Failed to load custom theme '{name}': {ex.Message}");
                    return false;
                }
            }
            return false;
        }

        /// <summary>Toggles between Dark and Light (ignores custom themes).</summary>
        public static void Toggle() =>
            Apply(Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);

        /// <summary>
        /// Restores the saved theme after settings are loaded at startup.
        /// <paramref name="savedName"/> can be "Dark", "Light", or a custom pack name.
        /// Falls back to Dark if the name is invalid.
        /// </summary>
        public static void ApplyFromSettings(string? savedName)
        {
            if (string.IsNullOrWhiteSpace(savedName) || !Apply(savedName))
                Apply(AppTheme.Dark);
        }

        // ── Custom pack discovery ─────────────────────────────────────────────

        /// <summary>
        /// Returns all .xaml files in the custom themes folder.
        /// The folder is created automatically if it doesn't exist.
        /// </summary>
        public static IReadOnlyList<string> DiscoverCustomPacks()
        {
            try
            {
                if (!Directory.Exists(CustomThemesFolder))
                    Directory.CreateDirectory(CustomThemesFolder);

                return Directory.GetFiles(CustomThemesFolder, "*.xaml",
                    SearchOption.TopDirectoryOnly);
            }
            catch { return Array.Empty<string>(); }
        }

        /// <summary>
        /// Opens the custom themes folder in Windows Explorer so the user
        /// can drop in their own .xaml packs.
        /// </summary>
        public static void OpenThemesFolder()
        {
            try
            {
                if (!Directory.Exists(CustomThemesFolder))
                    Directory.CreateDirectory(CustomThemesFolder);

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = CustomThemesFolder,
                    UseShellExecute = true
                });
            }
            catch { }
        }

        // ── Core swap ─────────────────────────────────────────────────────────

        private static void SwapColorDictionary(ResourceDictionary newDict, string name)
        {
            var app = Application.Current;
            if (app == null) return;

            if (!app.Dispatcher.CheckAccess())
            {
                app.Dispatcher.Invoke(() => SwapColorDictionary(newDict, name));
                return;
            }

            var merged = app.Resources.MergedDictionaries;
            if (merged.Count > 0)
                merged[0] = newDict;
            else
                merged.Add(newDict);

            ThemeChanged?.Invoke(null, name);
        }
    }

    /// <summary>Built-in theme identifiers.</summary>
    public enum AppTheme
    {
        /// <summary>Dark (default) built-in theme.</summary>
        Dark,
        /// <summary>Light built-in theme.</summary>
        Light,
        /// <summary>A user-supplied custom theme pack.</summary>
        Custom,
    }
}
