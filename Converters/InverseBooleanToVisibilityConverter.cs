using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace PackItPro.Converters
{
    [ValueConversion(typeof(bool), typeof(Visibility))]
    public class InverseBooleanToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (value is bool boolValue)
                {
                    return boolValue ? Visibility.Collapsed : Visibility.Visible;
                }
                return Visibility.Visible;
            }
            catch
            {
                return Visibility.Visible;
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (value is Visibility visibility)
                {
                    return visibility != Visibility.Visible;
                }
                return true;
            }
            catch
            {
                return true;
            }
        }
    }
}