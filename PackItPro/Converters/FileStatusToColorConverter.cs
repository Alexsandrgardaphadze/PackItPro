// Converters/FileStatusToColorConverter.cs - v2.3 FIXED
using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models;

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts FileStatusEnum to status color brush.
    /// FIX: Uses static frozen brushes to avoid allocating on every call.
    /// </summary>
    public class FileStatusToColorConverter : IValueConverter
    {
        // FIX: Static brushes allocated once, frozen for thread safety + performance
        private static readonly SolidColorBrush CleanBrush = new(Color.FromRgb(0x10, 0xB9, 0x81)); // Green
        private static readonly SolidColorBrush InfectedBrush = new(Color.FromRgb(0xEF, 0x44, 0x44)); // Red
        private static readonly SolidColorBrush FailedBrush = new(Color.FromRgb(0xF5, 0x9E, 0x0B)); // Yellow
        private static readonly SolidColorBrush SkippedBrush = new(Color.FromRgb(0x3B, 0x82, 0xF6)); // Blue
        private static readonly SolidColorBrush PendingBrush = new(Color.FromRgb(0x3B, 0x82, 0xF6)); // Blue
        private static readonly SolidColorBrush UnknownBrush = new(Color.FromRgb(0x94, 0xA3, 0xB8)); // Gray
        private static readonly SolidColorBrush FallbackBrush = new(Color.FromRgb(0x64, 0x74, 0x8B)); // Fallback

        static FileStatusToColorConverter()
        {
            // Freeze all brushes for thread safety and performance
            CleanBrush.Freeze();
            InfectedBrush.Freeze();
            FailedBrush.Freeze();
            SkippedBrush.Freeze();
            PendingBrush.Freeze();
            UnknownBrush.Freeze();
            FallbackBrush.Freeze();
        }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not FileStatusEnum status)
                return FallbackBrush;

            return status switch
            {
                FileStatusEnum.Clean => CleanBrush,
                FileStatusEnum.Infected => InfectedBrush,
                FileStatusEnum.ScanFailed => FailedBrush,
                FileStatusEnum.Skipped => SkippedBrush,
                FileStatusEnum.Pending => PendingBrush,
                _ => UnknownBrush,
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("FileStatusToColorConverter is one-way only.");
        }
    }
}