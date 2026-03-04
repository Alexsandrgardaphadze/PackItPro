// Views/FileListPanel.xaml.cs - v3.0

using PackItPro.ViewModels;
using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace PackItPro.Views
{
    public partial class FileListPanel : UserControl
    {
        private Storyboard? _pulseAnimation;

        // ── Drag-threshold state ──────────────────────────────────────────────
        // Set in PreviewMouseLeftButtonDown, read in PreviewMouseMove.

        private Point _dragStartPoint;
        private bool _isDragStartPending;   // mouse is down, drag not yet started
        private bool _suppressDrag;         // mouse-down was on a Button — never drag

        // ── Static frozen brushes ─────────────────────────────────────────────
        // Allocated once at class init. Pattern matches FileItemViewModel v3.1
        // and StatusToBackgroundConverter v2.3.

        private static readonly SolidColorBrush DragHoverBorderBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x60, 0xA5, 0xFA)));      // blue-400
        private static readonly SolidColorBrush DragHoverFillBrush =
            Frozen(new SolidColorBrush(Color.FromArgb(30, 0x60, 0xA5, 0xFA))); // blue-400 @ ~12%
        private static readonly SolidColorBrush FallbackBorderBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x3F, 0x3F, 0x46)));      // zinc-700
        private static readonly SolidColorBrush FallbackPanelBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x18, 0x18, 0x1B)));      // zinc-950

        private static SolidColorBrush Frozen(SolidColorBrush b) { b.Freeze(); return b; }

        // ─────────────────────────────────────────────────────────────────────

        public FileListPanel()
        {
            InitializeComponent();
            EmptyDropState.IsVisibleChanged += EmptyDropState_IsVisibleChanged;
        }

        // ── Empty-state pulse animation ───────────────────────────────────────

        private void EmptyDropState_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (EmptyDropState.Visibility == Visibility.Visible)
            {
                _pulseAnimation ??= (Storyboard)Resources["PulseAnimation"];
                _pulseAnimation.Begin();
            }
            else
            {
                _pulseAnimation?.Stop();
            }
        }

        // ── Drag-to-reorder (internal list items) ────────────────────────────

        /// <summary>
        /// Records where the mouse went down and whether it landed on a Button.
        /// We use PreviewMouseLeftButtonDown (not MouseLeftButtonDown) because
        /// the ListView's selection logic marks MouseLeftButtonDown as Handled,
        /// preventing it from bubbling up to us.
        /// </summary>
        private void FileListView_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _dragStartPoint = e.GetPosition(FileListView);
            _isDragStartPending = true;

            // If the click originated inside any ButtonBase (i.e. the ✕ remove button),
            // suppress drag for the entire duration of this mouse-down/up cycle.
            var clicked = e.OriginalSource as DependencyObject;
            _suppressDrag = WalkUpVisualTree<ButtonBase>(clicked) != null;
        }

        private void FileListView_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            // Clean up drag state when the mouse is released without a drag starting.
            _isDragStartPending = false;
            _suppressDrag = false;
        }

        private void FileListView_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed) return;
            if (!_isDragStartPending) return;   // no pending mouse-down
            if (_suppressDrag) return;           // click was on ✕ — leave it alone
            if (sender is not ListView lv) return;

            var currentPos = e.GetPosition(lv);
            var dx = Math.Abs(currentPos.X - _dragStartPoint.X);
            var dy = Math.Abs(currentPos.Y - _dragStartPoint.Y);

            // Only begin drag after the cursor has moved beyond the system threshold.
            // This is what distinguishes an intentional drag from a jittery click.
            if (dx < SystemParameters.MinimumHorizontalDragDistance &&
                dy < SystemParameters.MinimumVerticalDragDistance)
                return;

            // Resolve the item under the original down-point (not current position,
            // which may have drifted off the row by now).
            var hit = lv.InputHitTest(_dragStartPoint) as DependencyObject;
            var listViewItem = WalkUpVisualTree<ListViewItem>(hit);
            if (listViewItem?.DataContext is not FileItemViewModel fileItem) return;

            // Clear the pending flag before DoDragDrop so we don't restart a drag
            // if the mouse keeps moving during the (synchronous) DoDragDrop call.
            _isDragStartPending = false;

            DragDrop.DoDragDrop(lv, fileItem, DragDropEffects.Move);
        }

        private void FileListView_DragEnter(object sender, DragEventArgs e)
        {
            e.Effects = e.Data.GetData(typeof(FileItemViewModel)) != null
                ? DragDropEffects.Move
                : DragDropEffects.None;
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
            if (lv.DataContext is not FileListViewModel vm) return;

            int fromIndex = lv.Items.IndexOf(fileItem);
            int rawToIndex = GetInsertIndex(lv, e.GetPosition(lv));

            // Clamp: ObservableCollection.Move() only accepts 0..Count-1.
            // GetInsertIndex returns Count when dropped below all items.
            int toIndex = Math.Clamp(rawToIndex, 0, vm.Items.Count - 1);

            if (fromIndex < 0 || fromIndex == toIndex) return;

            vm.Items.Move(fromIndex, toIndex);

            // Keep InstallOrder in sync with the new visual order
            for (int i = 0; i < vm.Items.Count; i++)
                vm.Items[i].InstallOrder = i;

            e.Handled = true;
        }

        /// <summary>
        /// Returns the index at which a dropped item should be inserted.
        /// Returns <c>lv.Items.Count</c> when dropped below all items (caller must clamp).
        /// </summary>
        private static int GetInsertIndex(ListView lv, Point point)
        {
            var hit = lv.InputHitTest(point) as DependencyObject;
            var listViewItem = WalkUpVisualTree<ListViewItem>(hit);

            if (listViewItem == null)
                return lv.Items.Count;

            int index = lv.Items.IndexOf(listViewItem.DataContext);
            if (index < 0) return lv.Items.Count;

            var itemPos = listViewItem.TranslatePoint(new Point(0, 0), lv);
            return point.Y < itemPos.Y + listViewItem.ActualHeight / 2
                ? index       // upper half → insert before
                : index + 1;  // lower half → insert after
        }

        // ── Shared visual tree helper ─────────────────────────────────────────

        private static T? WalkUpVisualTree<T>(DependencyObject? element) where T : DependencyObject
        {
            while (element != null)
            {
                if (element is T match) return match;
                element = VisualTreeHelper.GetParent(element);
            }
            return null;
        }

        // ── External file drop (from Windows Explorer) ───────────────────────

        private void UserControl_DragEnter(object sender, DragEventArgs e)
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.None;
                e.Handled = true;
                return;
            }

            e.Effects = DragDropEffects.Copy;

            var borderBrush = TryFindResource("AppDropAreaHoverColor") as SolidColorBrush
                              ?? DragHoverBorderBrush;
            MainBorder.BorderBrush = borderBrush;
            MainBorder.Background = DragHoverFillBrush;

            e.Handled = true;
        }

        private void UserControl_DragLeave(object sender, DragEventArgs e)
        {
            RestoreMainBorderDefaults();
            e.Handled = true;
        }

        private void UserControl_Drop(object sender, DragEventArgs e)
        {
            RestoreMainBorderDefaults();

            if (e.Data.GetData(DataFormats.FileDrop) is not string[] files) return;
            if (DataContext is not FileListViewModel viewModel) return;

            viewModel.AddFilesWithValidation(files, out var result);

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
                var reasons = string.Join("\n", result.SkipReasons.Take(5));
                var extra = result.SkipReasons.Count > 5
                    ? $"\n...and {result.SkipReasons.Count - 5} more" : "";
                MessageBox.Show(
                    $"⚠ All files were skipped:\n\n{reasons}{extra}",
                    "No Files Added", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RestoreMainBorderDefaults()
        {
            MainBorder.BorderBrush = TryFindResource("AppBorderColor") as SolidColorBrush
                                     ?? FallbackBorderBrush;
            MainBorder.Background = TryFindResource("AppPanelColor") as SolidColorBrush
                                    ?? FallbackPanelBrush;
        }
    }
}