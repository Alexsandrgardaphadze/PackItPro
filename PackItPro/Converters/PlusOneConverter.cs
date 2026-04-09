// PackItPro/Converters/PlusOneConverter.cs
using System;
using System.Globalization;
using System.Windows.Data;

namespace PackItPro.Converters
{
    /// <summary>
    /// Adds 1 to an integer value and returns it as a string.
    /// Used by the install-order badge in FileListPanel to convert
    /// the 0-based <c>InstallOrder</c> to a 1-based display number.
    /// </summary>
    [ValueConversion(typeof(int), typeof(string))]
    public sealed class PlusOneConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is int n ? (n + 1).ToString() : "?";

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
