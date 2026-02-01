using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using PackItPro.Models; // Only if you use enums; otherwise remove

namespace PackItPro.Converters
{
    /// <summary>
    /// Converts a file status string or enum to a background Brush for the ListView badge.
    /// </summary>
    public class StatusToBackgroundConverter : IValueConverter
    {
        // Convert Status string to a background Brush
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null)
                return Brushes.LightGray;

            // If you have an enum FileStatusEnum:
            if (value is string statusString)
            {
                switch (statusString.ToLower())
                {
                    case "pending": return new SolidColorBrush(Color.FromRgb(59, 130, 246)); // blue
                    case "completed": return new SolidColorBrush(Color.FromRgb(198, 239, 206)); // green
                    case "error": return new SolidColorBrush(Color.FromRgb(239, 68, 68));   // red
                    default: return Brushes.LightGray;
                }
            }

            return Brushes.LightGray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
