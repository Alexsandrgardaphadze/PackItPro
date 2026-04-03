// PackItPro/Views/FileListPanel.xaml.cs
using PackItPro.ViewModels;
using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace PackItPro.Views
{
    public partial class FileListPanel : UserControl
    {
        private Storyboard? _pulseAnimation;

        // ── Column width constants ────────────────────────────────────────────
        // Sum of every fixed-width column + scrollbar allowance.
        private const double FixedColumnsWidth = 452 + 18; // 470
        private const double ArgsMinWidth = 60;

        // ── Resize debounce ───────────────────────────────────────────────────
        // Instead of recalculating on every pixel of a drag, we wait 16 ms
        // (one 60 fps frame) after the last SizeChanged event fires.
        // This cuts layout work by ~95% during a resize drag.
        private readonly DispatcherTimer _resizeDebounce;
        private double _pendingArgsWidth;

        // ── Drag-threshold state ──────────────────────────────────────────────
        private Point _dragStartPoint;
        private bool _isDragStartPending;
        private bool _suppressDrag;

        // ── Drag insertion indicator ──────────────────────────────────────────
        // A thin 2px accent line shown between rows to indicate drop position.
        private readonly System.Windows.Shapes.Rectangle _insertionLine;

        // ── Static frozen brushes ─────────────────────────────────────────────
        private static readonly SolidColorBrush DragHoverBorderBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x60, 0xA5, 0xFA)));
        private static readonly SolidColorBrush DragHoverFillBrush =
            Frozen(new SolidColorBrush(Color.FromArgb(30, 0x60, 0xA5, 0xFA)));
        private static readonly SolidColorBrush FallbackBorderBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x3F, 0x3F, 0x46)));
        private static readonly SolidColorBrush FallbackPanelBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x18, 0x18, 0x1B)));
        private static readonly SolidColorBrush InsertionBrush =
            Frozen(new SolidColorBrush(Color.FromRgb(0x63, 0x66, 0xF1)));

        private static SolidColorBrush Frozen(SolidColorBrush b) { b.Freeze(); return b; }

        // ─────────────────────────────────────────────────────────────────────

        public FileListPanel()
        {
            InitializeComponent();

            // Debounce timer — fires once, 16 ms after the last resize event.
            _resizeDebounce = new DispatcherTimer(DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(16)
            };
            _resizeDebounce.Tick += (_, _) =>
            {
                _resizeDebounce.Stop();
                NotesColumn.Width = _pendingArgsWidth;
            };

            // Insertion line — added to the ListView's adorner layer at runtime.
            _insertionLine = new System.Windows.Shapes.Rectangle
            {
                Height = 2,
                Fill = InsertionBrush,
                IsHitTestVisible = false,
                Visibility = Visibility.Collapsed,
                HorizontalAlignment = HorizontalAlignment.Stretch,
            };

            EmptyDropState.IsVisibleChanged += EmptyDropState_IsVisibleChanged;
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            // Inject insertion line into an AdornerDecorator above the ListView
            // so it renders on top of all rows without affecting layout.
            // We use the ListView's parent Panel instead, which is simpler and reliable.
            if (FileListView.Parent is Panel parentPanel &&
                !parentPanel.Children.Contains(_insertionLine))
            {
                parentPanel.Children.Add(_insertionLine);
            }
        }

        // ── Args column stretching (debounced) ───────────────────────────────

        /// <summary>
        /// Queues a column-width recalculation instead of doing it immediately.
        /// The DispatcherTimer fires once per ~16 ms after resize ends.
        /// </summary>
        private void FileListView_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            if (!e.WidthChanged) return;

            _pendingArgsWidth = Math.Max(
                FileListView.ActualWidth - FixedColumnsWidth,
                ArgsMinWidth);

            // Restart the debounce window.
            _resizeDebounce.Stop();
            _resizeDebounce.Start();
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

        // ── Keyboard navigation ──────────────────────────────────────────────

        private void FileListView_KeyDown(object sender, KeyEventArgs e)
        {
            if (DataContext is not FileListViewModel vm) return;

            // Delete — remove selected item
            if (e.Key == Key.Delete &&
                FileListView.SelectedItem is FileItemViewModel selected)
            {
                selected.RemoveCommand?.Execute(null);
                e.Handled = true;
                return;
            }

            // Ctrl+A — select all (WPF ListView already supports this by default)
            // Tab is handled by WPF naturally
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
            HideInsertionLine();
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
            HideInsertionLine();
        }

        private void FileListView_DragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetData(typeof(FileItemViewModel)) == null)
            {
                e.Effects = DragDropEffects.None;
                e.Handled = true;
                return;
            }
            e.Effects = DragDropEffects.Move;
            ShowInsertionLine(sender as ListView, e.GetPosition(sender as ListView));
            e.Handled = true;
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
            HideInsertionLine();
            e.Handled = true;
        }

        private void FileListView_Drop(object sender, DragEventArgs e)
        {
            HideInsertionLine();

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

        // ── Insertion line helpers ────────────────────────────────────────────

        private void ShowInsertionLine(ListView? lv, Point mousePos)
        {
            if (lv == null || lv.Items.Count == 0) { HideInsertionLine(); return; }

            // Find the item nearest the pointer to place the line above/below it.
            ListViewItem? nearest = null;
            double nearestY = double.MaxValue;
            bool insertAfter = false;

            foreach (var item in lv.Items)
            {
                var container = lv.ItemContainerGenerator.ContainerFromItem(item) as ListViewItem;
                if (container == null) continue;

                var pos = container.TranslatePoint(new Point(0, 0), lv);
                var mid = pos.Y + container.ActualHeight / 2;
                var dist = Math.Abs(mousePos.Y - mid);
                if (dist < nearestY) { nearestY = dist; nearest = container; insertAfter = mousePos.Y > mid; }
            }

            if (nearest == null) { HideInsertionLine(); return; }

            var itemTopInLv = nearest.TranslatePoint(new Point(0, 0), lv);
            double lineY = insertAfter
                ? itemTopInLv.Y + nearest.ActualHeight
                : itemTopInLv.Y;

            // Translate into the parent panel's coordinate space.
            if (lv.Parent is Panel panel)
            {
                var lvOriginInPanel = lv.TranslatePoint(new Point(0, 0), panel);
                Canvas.SetTop(_insertionLine, lvOriginInPanel.Y + lineY - 1);
                _insertionLine.Width = lv.ActualWidth;
                _insertionLine.Visibility = Visibility.Visible;
            }
        }

        private void HideInsertionLine() =>
            _insertionLine.Visibility = Visibility.Collapsed;

        // ── Static helpers ────────────────────────────────────────────────────

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
            var borderBrush = TryFindResource("AppDropAreaHoverColor") as SolidColorBrush ?? DragHoverBorderBrush;
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

            if (result.SuccessCount > 0)
                TriggerScanOnAddIfEnabled();
        }

        private void TriggerScanOnAddIfEnabled()
        {
            if (Window.GetWindow(this)?.DataContext is not MainViewModel mainVm) return;
            if (!mainVm.Settings.ScanOnAdd) return;
            if (!mainVm.ScanFilesCommand.CanExecute(null)) return;
            mainVm.ScanFilesCommand.Execute(null);
        }

        private void RestoreMainBorderDefaults()
        {
            MainBorder.BorderBrush = TryFindResource("AppBorderColor") as SolidColorBrush ?? FallbackBorderBrush;
            MainBorder.Background = TryFindResource("AppPanelColor") as SolidColorBrush ?? FallbackPanelBrush;
        }
    }
}
