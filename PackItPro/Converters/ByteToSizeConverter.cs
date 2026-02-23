// Converters/ByteToSizeConverter.cs - v2.3 OPTIMIZED
using System;
using System.Globalization;
using System.Windows.Data;

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts byte count to human-readable size string (e.g., "1.5 MB").
    /// FIX: Uses static array to avoid allocation on every call.
    /// </summary>
    public class ByteToSizeConverter : IValueConverter
    {
        // FIX: Static array — allocated once, reused forever
        private static readonly string[] Sizes = { "B", "KB", "MB", "GB", "TB" };

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not long bytes)
                return "0 B";

            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < Sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {Sizes[order]}";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("ByteToSizeConverter is one-way only.");
        }
    }
}