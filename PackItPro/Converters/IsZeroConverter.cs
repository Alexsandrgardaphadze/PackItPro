// PackItPro/Converters/IsZeroConverter.cs
using System;
using System.Globalization;
using System.Windows.Data;

namespace PackItPro.Converters
{
    /// <summary>
    /// Returns <c>true</c> when the bound integer equals zero, <c>false</c> otherwise.
    /// Used in the StatusPanel scan-before-pack indicator MultiDataTrigger.
    /// </summary>
    [ValueConversion(typeof(int), typeof(bool))]
    public sealed class IsZeroConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is int n && n == 0;

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
