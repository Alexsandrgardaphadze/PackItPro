// Converters/StatusToBackgroundConverter.cs - v2.3 FIXED
using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models;

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts FileStatusEnum to semi-transparent background brush (15% opacity).
    /// FIX: Uses static frozen brushes to avoid allocating on every call.
    /// </summary>
    public class StatusToBackgroundConverter : IValueConverter
    {
        // FIX: Static brushes with 15% opacity (38/255), frozen for performance
        private static readonly SolidColorBrush CleanBackground = new(Color.FromArgb(38, 0x10, 0xB9, 0x81)); // Green bg
        private static readonly SolidColorBrush InfectedBackground = new(Color.FromArgb(38, 0xEF, 0x44, 0x44)); // Red bg
        private static readonly SolidColorBrush FailedBackground = new(Color.FromArgb(38, 0xF5, 0x9E, 0x0B)); // Yellow bg
        private static readonly SolidColorBrush SkippedBackground = new(Color.FromArgb(38, 0x3B, 0x82, 0xF6)); // Blue bg
        private static readonly SolidColorBrush PendingBackground = new(Color.FromArgb(38, 0x3B, 0x82, 0xF6)); // Blue bg
        private static readonly SolidColorBrush UnknownBackground = new(Color.FromArgb(38, 0x94, 0xA3, 0xB8)); // Gray bg
        private static readonly SolidColorBrush TransparentBrush = new(Colors.Transparent);

        static StatusToBackgroundConverter()
        {
            CleanBackground.Freeze();
            InfectedBackground.Freeze();
            FailedBackground.Freeze();
            SkippedBackground.Freeze();
            PendingBackground.Freeze();
            UnknownBackground.Freeze();
            TransparentBrush.Freeze();
        }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // Handle direct SolidColorBrush input (if ever passed from code)
            if (value is SolidColorBrush brush)
            {
                var color = brush.Color;
                // Create a semi-transparent version dynamically (rare path)
                return new SolidColorBrush(Color.FromArgb(38, color.R, color.G, color.B));
            }

            // Handle FileStatusEnum input (main path)
            if (value is FileStatusEnum status)
            {
                return status switch
                {
                    FileStatusEnum.Clean => CleanBackground,
                    FileStatusEnum.Infected => InfectedBackground,
                    FileStatusEnum.ScanFailed => FailedBackground,
                    FileStatusEnum.Skipped => SkippedBackground,
                    FileStatusEnum.Pending => PendingBackground,
                    _ => UnknownBackground,
                };
            }

            return TransparentBrush;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("StatusToBackgroundConverter is one-way only.");
        }
    }
}