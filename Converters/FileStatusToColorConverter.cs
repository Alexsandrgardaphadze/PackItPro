using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.ViewModels;

namespace PackItPro.Converters
{
    public class FileStatusToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not FileStatusEnum status)
                return Brushes.Gray;

            return status switch
            {
                FileStatusEnum.Clean => Brushes.Green,
                FileStatusEnum.Infected => Brushes.Red,
                FileStatusEnum.Pending => Brushes.DodgerBlue,
                FileStatusEnum.ScanFailed => Brushes.Orange,
                FileStatusEnum.Skipped => Brushes.Gray,
                _ => Brushes.Gray
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}
