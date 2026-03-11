// Views/FileListPanel.xaml.cs - v2.2
// Added: FileListView_SizeChanged — keeps NotesColumn.Width = available space minus
//        the sum of all fixed columns, so the Notes column always fills the gap between
//        Status and the Delete button regardless of window width.
//
// Fixed columns and their widths (must match XAML exactly):
//   Icon     35
//   FileName 200
//   Size     75
//   Status   110
//   Delete   32
//   ──────────── = 452px + ~18px scrollbar allowance = 470px reserved
//
// Notes gets: FileListView.ActualWidth - 470, clamped to a minimum of 60px so the
// column header stays visible even at the minimum window width (900px).
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

        // Sum of every fixed-width column + scrollbar allowance.
        // If you ever change a column width in XAML, update this constant too.
        private const double FixedColumnsWidth = 452 + 18; // 470

        // Minimum width for the Notes column — keeps the header legible.
        private const double NotesMinWidth = 60;

        // ── Drag-threshold state ──────────────────────────────────────────────
        private Point _dragStartPoint;
        private bool _isDragStartPending;
        private bool _suppressDrag;

        // ── Static frozen brushes ─────────────────────────────────────────────
        private static readonly SolidColorBrush DragHoverBorderBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x60, 0xA5, 0xFA)));
        private static readonly SolidColorBrush DragHoverFillBrush =
            Frozen(new SolidColorBrush(Color.FromArgb(30, 0x60, 0xA5, 0xFA)));
        private static readonly SolidColorBrush FallbackBorderBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x3F, 0x3F, 0x46)));
        private static readonly SolidColorBrush FallbackPanelBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x18, 0x18, 0x1B)));

        private static SolidColorBrush Frozen(SolidColorBrush b) { b.Freeze(); return b; }

        // ─────────────────────────────────────────────────────────────────────

        public FileListPanel()
        {
            InitializeComponent();
            EmptyDropState.IsVisibleChanged += EmptyDropState_IsVisibleChanged;
        }

        // ── Notes column stretching ───────────────────────────────────────────

        /// <summary>
        /// Recalculates NotesColumn.Width every time the ListView is resized so the
        /// column absorbs all space between the Status column and the Delete button.
        /// Throttling is not needed — WPF coalesces layout passes, so this only fires
        /// once per completed resize frame, not per pixel.
        /// </summary>
        private void FileListView_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            if (!e.WidthChanged) return; // height-only resize — nothing to recalculate

            double notesWidth = Math.Max(
                FileListView.ActualWidth - FixedColumnsWidth,
                NotesMinWidth);

            NotesColumn.Width = notesWidth;
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

        private void FileListView_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _dragStartPoint = e.GetPosition(FileListView);
            _isDragStartPending = true;
            var clicked = e.OriginalSource as DependencyObject;
            _suppressDrag = WalkUpVisualTree<ButtonBase>(clicked) != null;
        }

        private void FileListView_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _isDragStartPending = false;
            _suppressDrag = false;
        }

        private void FileListView_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed) return;
            if (!_isDragStartPending) return;
            if (_suppressDrag) return;
            if (sender is not ListView lv) return;

            var currentPos = e.GetPosition(lv);
            var dx = Math.Abs(currentPos.X - _dragStartPoint.X);
            var dy = Math.Abs(currentPos.Y - _dragStartPoint.Y);

            if (dx < SystemParameters.MinimumHorizontalDragDistance &&
                dy < SystemParameters.MinimumVerticalDragDistance)
                return;

            var hit = lv.InputHitTest(_dragStartPoint) as DependencyObject;
            var listViewItem = WalkUpVisualTree<ListViewItem>(hit);
            if (listViewItem?.DataContext is not FileItemViewModel fileItem) return;

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

        private void FileListView_DragLeave(object sender, DragEventArgs e) => e.Handled = true;

        private void FileListView_Drop(object sender, DragEventArgs e)
        {
            if (sender is not ListView lv) return;
            if (e.Data.GetData(typeof(FileItemViewModel)) is not FileItemViewModel fileItem) return;
            if (lv.DataContext is not FileListViewModel vm) return;

            int fromIndex = lv.Items.IndexOf(fileItem);
            int rawToIndex = GetInsertIndex(lv, e.GetPosition(lv));
            int toIndex = Math.Clamp(rawToIndex, 0, vm.Items.Count - 1);

            if (fromIndex < 0 || fromIndex == toIndex) return;

            vm.Items.Move(fromIndex, toIndex);

            for (int i = 0; i < vm.Items.Count; i++)
                vm.Items[i].InstallOrder = i;

            e.Handled = true;
        }

        private static int GetInsertIndex(ListView lv, Point point)
        {
            var hit = lv.InputHitTest(point) as DependencyObject;
            var listViewItem = WalkUpVisualTree<ListViewItem>(hit);

            if (listViewItem == null) return lv.Items.Count;

            int index = lv.Items.IndexOf(listViewItem.DataContext);
            if (index < 0) return lv.Items.Count;

            var itemPos = listViewItem.TranslatePoint(new Point(0, 0), lv);
            return point.Y < itemPos.Y + listViewItem.ActualHeight / 2 ? index : index + 1;
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

            if (result.SuccessCount > 0 || result.SkippedCount > 0)
                FileAddResultWindow.Show(
                    Window.GetWindow(this),
                    result.SuccessCount,
                    result.SkippedCount,
                    result.SkipReasons);

            // Scan-on-add: resolve MainViewModel through the Window's DataContext
            // so FileListPanel doesn't need a direct ViewModel reference injected.
            if (result.SuccessCount > 0)
                TriggerScanOnAddIfEnabled();
        }

        /// <summary>
        /// Fires ScanFilesCommand if ScanOnAdd is enabled and the command can execute.
        /// MainViewModel is reached via Window.DataContext — keeps the panel decoupled.
        /// </summary>
        private void TriggerScanOnAddIfEnabled()
        {
            if (Window.GetWindow(this)?.DataContext is not MainViewModel mainVm) return;
            if (!mainVm.Settings.ScanOnAdd) return;
            if (!mainVm.ScanFilesCommand.CanExecute(null)) return;

            mainVm.ScanFilesCommand.Execute(null);
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