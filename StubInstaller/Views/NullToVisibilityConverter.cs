// StubInstaller/Views/NullToVisibilityConverter.cs
// Collapses an element when its binding value is null or empty string.
// Used to hide the Notes sub-line in the app list when no note was set.
using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace StubInstaller
{
    public class NullToVisibilityConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => value != null && value.ToString() != string.Empty
               ? Visibility.Visible
               : Visibility.Collapsed;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}