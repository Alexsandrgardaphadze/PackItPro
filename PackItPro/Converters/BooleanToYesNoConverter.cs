using System;
using System.Globalization;
using System.Windows.Data;

namespace PackItPro.Converters
{
    public class BooleanToYesNoConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool b ? (b ? "Yes" : "No") : "No";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value?.ToString()?.Equals("Yes", StringComparison.OrdinalIgnoreCase) == true;
        }
    }
}