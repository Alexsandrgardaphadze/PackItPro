// Views/FileListPanel.xaml.cs - UPDATED VERSION
using PackItPro.ViewModels;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace PackItPro.Views
{
    public partial class FileListPanel : UserControl
    {
        private Storyboard? _pulseAnimation;

        public FileListPanel()
        {
            InitializeComponent();

            // ✅ FIX: Only start animation when empty state is visible
            EmptyDropState.IsVisibleChanged += EmptyDropState_IsVisibleChanged;
        }

        // ✅ FIX: Control animation based on visibility
        private void EmptyDropState_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (EmptyDropState.Visibility == Visibility.Visible)
            {
                // Start animation when empty state becomes visible
                _pulseAnimation = (Storyboard)Resources["PulseAnimation"];
                _pulseAnimation?.Begin();
            }
            else
            {
                // Stop animation when empty state is hidden
                _pulseAnimation?.Stop();
            }
        }

        private void UserControl_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                var hoverBrush = TryFindResource("AppDropAreaHoverColor") as SolidColorBrush
                                 ?? new SolidColorBrush(Colors.LightBlue);
                var color = hoverBrush.Color;
                this.BorderBrush = hoverBrush;
                this.Background = new SolidColorBrush(Color.FromArgb(30, color.R, color.G, color.B));
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void UserControl_DragLeave(object sender, DragEventArgs e)
        {
            var defaultBorderBrush = TryFindResource("AppBorderColor") as SolidColorBrush
                                     ?? new SolidColorBrush(Colors.Gray);
            var defaultBackgroundBrush = TryFindResource("AppPanelColor") as SolidColorBrush
                                         ?? new SolidColorBrush(Colors.Black);
            this.BorderBrush = defaultBorderBrush;
            this.Background = defaultBackgroundBrush;
            e.Handled = true;
        }

        private void UserControl_Drop(object sender, DragEventArgs e)
        {
            UserControl_DragLeave(sender, e);

            if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
            {
                if (this.DataContext is FileListViewModel viewModel)
                {
                    viewModel.AddFilesWithValidation(files, out var result);

                    // Show feedback to user
                    if (result.SuccessCount > 0)
                    {
                        string message = $"✓ Added {result.SuccessCount} file(s)";
                        if (result.SkippedCount > 0)
                        {
                            message += $"\n\n⚠ Skipped {result.SkippedCount}:\n";
                            message += string.Join("\n", result.SkipReasons.Take(5));
                            if (result.SkipReasons.Count > 5)
                                message += $"\n...and {result.SkipReasons.Count - 5} more";
                        }

                        MessageBox.Show(message, "Files Added", MessageBoxButton.OK,
                            result.SkippedCount > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
                    }
                    else if (result.SkippedCount > 0)
                    {
                        MessageBox.Show(
                            $"⚠ All files were skipped:\n\n{string.Join("\n", result.SkipReasons.Take(5))}" +
                            (result.SkipReasons.Count > 5 ? $"\n...and {result.SkipReasons.Count - 5} more" : ""),
                            "No Files Added",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                }
            }
        }
    }
}
