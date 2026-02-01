using System;
using System.Globalization;
using System.Windows.Data;

namespace PackItPro.Converters
{
    [ValueConversion(typeof(bool), typeof(string))]
    public class BooleanToYesNoConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (value is bool boolValue)
                {
                    return boolValue ? "Yes" : "No";
                }
                return "No";
            }
            catch
            {
                return "No";
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (value is string stringValue)
                {
                    return stringValue.Equals("Yes", StringComparison.OrdinalIgnoreCase);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}