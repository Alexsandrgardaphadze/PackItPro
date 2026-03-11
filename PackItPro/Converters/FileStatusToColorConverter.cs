// Converters/FileStatusToColorConverter.cs - v2.4
// Added: Trusted → cyan-500 solid brush (matches StatusToBackgroundConverter palette)
using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models;

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts FileStatusEnum to a solid foreground colour brush.
    /// </summary>
    public class FileStatusToColorConverter : IValueConverter
    {
        private static readonly SolidColorBrush CleanBrush = new(Color.FromRgb(0x10, 0xB9, 0x81)); // emerald
        private static readonly SolidColorBrush InfectedBrush = new(Color.FromRgb(0xEF, 0x44, 0x44)); // red
        private static readonly SolidColorBrush FailedBrush = new(Color.FromRgb(0xF5, 0x9E, 0x0B)); // amber
        private static readonly SolidColorBrush SkippedBrush = new(Color.FromRgb(0x3B, 0x82, 0xF6)); // blue
        private static readonly SolidColorBrush PendingBrush = new(Color.FromRgb(0x3B, 0x82, 0xF6)); // blue
        private static readonly SolidColorBrush TrustedBrush = new(Color.FromRgb(0x06, 0xB6, 0xD4)); // cyan-500
        private static readonly SolidColorBrush UnknownBrush = new(Color.FromRgb(0x94, 0xA3, 0xB8)); // slate
        private static readonly SolidColorBrush FallbackBrush = new(Color.FromRgb(0x64, 0x74, 0x8B)); // fallback

        static FileStatusToColorConverter()
        {
            CleanBrush.Freeze();
            InfectedBrush.Freeze();
            FailedBrush.Freeze();
            SkippedBrush.Freeze();
            PendingBrush.Freeze();
            TrustedBrush.Freeze();
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
                FileStatusEnum.Trusted => TrustedBrush,
                _ => UnknownBrush,
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException("FileStatusToColorConverter is one-way only.");
    }
}