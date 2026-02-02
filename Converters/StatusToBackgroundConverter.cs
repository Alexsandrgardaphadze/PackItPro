// Converters/StatusToBackgroundConverter.cs
using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models;

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts a status color (SolidColorBrush or FileStatusEnum) to a semi-transparent background brush
    /// Used for status badges in the file list
    /// </summary>
    public class StatusToBackgroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // Handle SolidColorBrush input (direct color)
            if (value is SolidColorBrush brush)
            {
                var color = brush.Color;
                // Create semi-transparent version (15% opacity = 38/255)
                return new SolidColorBrush(Color.FromArgb(38, color.R, color.G, color.B));
            }

            // Handle FileStatusEnum input
            if (value is FileStatusEnum status)
            {
                // Convert enum to color, then to semi-transparent background
                var color = status switch
                {
                    FileStatusEnum.Clean => Color.FromRgb(0x10, 0xB9, 0x81),      // Green
                    FileStatusEnum.Infected => Color.FromRgb(0xEF, 0x44, 0x44),   // Red
                    FileStatusEnum.ScanFailed => Color.FromRgb(0xF5, 0x9E, 0x0B), // Yellow/Orange
                    FileStatusEnum.Skipped => Color.FromRgb(0x3B, 0x82, 0xF6),    // Blue
                    FileStatusEnum.Pending => Color.FromRgb(0x3B, 0x82, 0xF6),    // Blue
                    _ => Color.FromRgb(0x94, 0xA3, 0xB8)                          // Gray
                };
                return new SolidColorBrush(Color.FromArgb(38, color.R, color.G, color.B));
            }

            // Fallback: transparent
            return new SolidColorBrush(Colors.Transparent);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException("StatusToBackgroundConverter is one-way only");
        }
    }
}
