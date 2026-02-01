using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models; // Ensure FileStatusEnum is in Models namespace

namespace PackItPro.Converters
{
    public class FileStatusToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not FileStatusEnum status)
                return new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)); // AppTextQuaternaryColor

            return status switch
            {
                FileStatusEnum.Clean => new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)), // AppStatusCleanColor
                FileStatusEnum.Infected => new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)), // AppStatusErrorColor
                FileStatusEnum.ScanFailed => new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)), // AppStatusWarningColor
                FileStatusEnum.Skipped => new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)), // AppStatusPendingColor
                FileStatusEnum.Pending => new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)),
                _ => new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8))  // AppTextTertiaryColor
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}