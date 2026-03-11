// Converters/StatusToBackgroundConverter.cs - v2.4
// Added: Trusted → teal semi-transparent background (matches IsTrustedFalsePositive visual language)
using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models;

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts FileStatusEnum to semi-transparent background brush (15% opacity).
    /// </summary>
    public class StatusToBackgroundConverter : IValueConverter
    {
        // 15% opacity = alpha 38 (0x26)
        private static readonly SolidColorBrush CleanBackground = new(Color.FromArgb(38, 0x10, 0xB9, 0x81)); // emerald
        private static readonly SolidColorBrush InfectedBackground = new(Color.FromArgb(38, 0xEF, 0x44, 0x44)); // red
        private static readonly SolidColorBrush FailedBackground = new(Color.FromArgb(38, 0xF5, 0x9E, 0x0B)); // amber
        private static readonly SolidColorBrush SkippedBackground = new(Color.FromArgb(38, 0x3B, 0x82, 0xF6)); // blue
        private static readonly SolidColorBrush PendingBackground = new(Color.FromArgb(38, 0x3B, 0x82, 0xF6)); // blue
        private static readonly SolidColorBrush TrustedBackground = new(Color.FromArgb(38, 0x06, 0xB6, 0xD4)); // cyan-500 — distinct from Clean
        private static readonly SolidColorBrush UnknownBackground = new(Color.FromArgb(38, 0x94, 0xA3, 0xB8)); // slate
        private static readonly SolidColorBrush TransparentBrush = new(Colors.Transparent);

        static StatusToBackgroundConverter()
        {
            CleanBackground.Freeze();
            InfectedBackground.Freeze();
            FailedBackground.Freeze();
            SkippedBackground.Freeze();
            PendingBackground.Freeze();
            TrustedBackground.Freeze();
            UnknownBackground.Freeze();
            TransparentBrush.Freeze();
        }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // Rare code-behind path: accept a brush and return a semi-transparent version
            if (value is SolidColorBrush brush)
            {
                var c = brush.Color;
                return new SolidColorBrush(Color.FromArgb(38, c.R, c.G, c.B));
            }

            if (value is FileStatusEnum status)
            {
                return status switch
                {
                    FileStatusEnum.Clean => CleanBackground,
                    FileStatusEnum.Infected => InfectedBackground,
                    FileStatusEnum.ScanFailed => FailedBackground,
                    FileStatusEnum.Skipped => SkippedBackground,
                    FileStatusEnum.Pending => PendingBackground,
                    FileStatusEnum.Trusted => TrustedBackground,
                    _ => UnknownBackground,
                };
            }

            return TransparentBrush;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException("StatusToBackgroundConverter is one-way only.");
    }
}