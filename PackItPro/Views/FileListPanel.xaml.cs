// Views/FileListPanel.xaml.cs - FINAL VERSION
using PackItPro.ViewModels;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace PackItPro.Views
{
    public partial class FileListPanel : UserControl
    {
        private Storyboard? _pulseAnimation;
        private int _draggedIndex = -1;
        private int _dragOverIndex = -1;

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

        // ── Drag-to-Reorder Support ───────────────────────────────────────────

        private void FileListView_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed) return;
            if (sender is not ListView lv) return;

            var hit = lv.InputHitTest(e.GetPosition(lv)) as DependencyObject;
            var listViewItem = WalkUpVisualTree<ListViewItem>(hit);
            if (listViewItem == null) return;

            var fileItem = listViewItem.DataContext as FileItemViewModel;
            if (fileItem == null) return;

            _draggedIndex = lv.Items.IndexOf(fileItem);
            DragDrop.DoDragDrop(lv, fileItem, DragDropEffects.Move);
        }

        private void FileListView_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetData(typeof(FileItemViewModel)) != null)
            {
                e.Effects = DragDropEffects.Move;
            }
            e.Handled = true;
        }

        private void FileListView_DragLeave(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }

        private void FileListView_Drop(object sender, DragEventArgs e)
        {
            if (sender is not ListView lv) return;
            if (e.Data.GetData(typeof(FileItemViewModel)) is not FileItemViewModel fileItem) return;

            int fromIndex = lv.Items.IndexOf(fileItem);
            int toIndex = GetInsertIndex(lv, e.GetPosition(lv));

            if (fromIndex < 0 || toIndex < 0 || fromIndex == toIndex) return;

            var vm = (FileListViewModel)lv.DataContext;
            vm.Items.Move(fromIndex, toIndex);

            // Update InstallOrder to match list position
            for (int i = 0; i < vm.Items.Count; i++)
            {
                vm.Items[i].InstallOrder = i;
            }

            e.Handled = true;
        }

        private int GetInsertIndex(ListView lv, Point point)
        {
            var item = lv.InputHitTest(point) as DependencyObject;
            var listViewItem = WalkUpVisualTree<ListViewItem>(item);

            if (listViewItem == null)
                return lv.Items.Count;

            int index = lv.Items.IndexOf(listViewItem.DataContext);
            var rect = VisualTreeHelper.GetDescendantBounds(listViewItem);

            // Drop in upper half = before this item, lower half = after
            return point.Y < rect.Height / 2 ? index : index + 1;
        }

        private static T? WalkUpVisualTree<T>(DependencyObject? element) where T : DependencyObject
        {
            while (element != null)
            {
                if (element is T match) return match;
                element = VisualTreeHelper.GetParent(element);
            }
            return null;
        }

        // ── File Drop Support (External Files) ─────────────────────────────────

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
