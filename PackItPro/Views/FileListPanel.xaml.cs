// PackItPro/Views/FileListPanel.xaml.cs
//
// Fixes in this version:
//   1. Insertion line now uses AdornerLayer (renders on top of everything, no layout impact)
//   2. Drag still works with VirtualizingPanel because we only iterate visible containers
//   3. Delete key guard — only fires on the ListView when no TextBox has focus
//   4. _suppressDrag also guards against TextBox edits in the Custom Args column
using PackItPro.ViewModels;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
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
        private const double FixedColumnsWidth = 452 + 18; // 470
        private const double ArgsMinWidth = 60;

        // ── Resize debounce ───────────────────────────────────────────────────
        private readonly DispatcherTimer _resizeDebounce;
        private double _pendingArgsWidth;

        // ── Drag state ────────────────────────────────────────────────────────
        private Point _dragStartPoint;
        private bool _isDragStartPending;
        private bool _suppressDrag;

        // ── Drag insertion indicator (AdornerLayer) ───────────────────────────
        // InsertionAdorner renders the 2px line on top of the ListView via
        // the WPF adorner system — no layout impact, always on top, correct coords.
        private InsertionLineAdorner? _insertionAdorner;

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

            _resizeDebounce = new DispatcherTimer(DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(16)
            };
            _resizeDebounce.Tick += (_, _) =>
            {
                _resizeDebounce.Stop();
                NotesColumn.Width = _pendingArgsWidth;
            };

            EmptyDropState.IsVisibleChanged += EmptyDropState_IsVisibleChanged;
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            // Create the adorner once the ListView is in the visual tree.
            // AdornerLayer.GetAdornerLayer walks up from FileListView to find
            // the nearest AdornerDecorator (provided by Window/UserControl).
            var layer = AdornerLayer.GetAdornerLayer(FileListView);
            if (layer != null)
            {
                _insertionAdorner = new InsertionLineAdorner(FileListView);
                layer.Add(_insertionAdorner);
            }
        }

        // ── Args column stretching (debounced) ───────────────────────────────

        private void FileListView_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            if (!e.WidthChanged) return;
            _pendingArgsWidth = Math.Max(FileListView.ActualWidth - FixedColumnsWidth, ArgsMinWidth);
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

        // ── Keyboard navigation ───────────────────────────────────────────────

        private void FileListView_KeyDown(object sender, KeyEventArgs e)
        {
            if (DataContext is not FileListViewModel vm) return;

            // Only handle Delete when the ListView itself (not a child TextBox) has focus.
            // This prevents eating the Delete key while the user edits Custom Args.
            if (e.Key == Key.Delete &&
                Keyboard.FocusedElement is not TextBox &&
                FileListView.SelectedItem is FileItemViewModel selected)
            {
                selected.RemoveCommand?.Execute(null);
                e.Handled = true;
            }
        }

        // ── Drag-to-reorder ───────────────────────────────────────────────────

        private void FileListView_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _dragStartPoint = e.GetPosition(FileListView);
            _isDragStartPending = true;
            var clicked = e.OriginalSource as DependencyObject;
            // Suppress drag if click originated inside a Button OR a TextBox
            // (so the Custom Args editor doesn't trigger a drag).
            _suppressDrag = WalkUpVisualTree<ButtonBase>(clicked) != null
                         || WalkUpVisualTree<TextBox>(clicked) != null;
        }

        private void FileListView_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _isDragStartPending = false;
            _suppressDrag = false;
            _insertionAdorner?.Hide();
        }

        private void FileListView_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed) return;
            if (!_isDragStartPending) return;
            if (_suppressDrag) return;
            if (sender is not ListView lv) return;

            var pos = e.GetPosition(lv);
            if (Math.Abs(pos.X - _dragStartPoint.X) < SystemParameters.MinimumHorizontalDragDistance &&
                Math.Abs(pos.Y - _dragStartPoint.Y) < SystemParameters.MinimumVerticalDragDistance)
                return;

            var hit = lv.InputHitTest(_dragStartPoint) as DependencyObject;
            var item = WalkUpVisualTree<ListViewItem>(hit);
            if (item?.DataContext is not FileItemViewModel fileItem) return;

            _isDragStartPending = false;
            DragDrop.DoDragDrop(lv, fileItem, DragDropEffects.Move);
            _insertionAdorner?.Hide();
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
            _insertionAdorner?.Update(e.GetPosition(FileListView));
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
            _insertionAdorner?.Hide();
            e.Handled = true;
        }

        private void FileListView_Drop(object sender, DragEventArgs e)
        {
            _insertionAdorner?.Hide();

            if (sender is not ListView lv) return;
            if (e.Data.GetData(typeof(FileItemViewModel)) is not FileItemViewModel fileItem) return;
            if (lv.DataContext is not FileListViewModel vm) return;

            int fromIndex = lv.Items.IndexOf(fileItem);
            int toIndex = Math.Clamp(GetInsertIndex(lv, e.GetPosition(lv)), 0, vm.Items.Count - 1);

            if (fromIndex < 0 || fromIndex == toIndex) return;

            vm.Items.Move(fromIndex, toIndex);
            for (int i = 0; i < vm.Items.Count; i++)
                vm.Items[i].InstallOrder = i;

            e.Handled = true;
        }

        // ── Index helper ──────────────────────────────────────────────────────

        private static int GetInsertIndex(ListView lv, Point point)
        {
            var hit = lv.InputHitTest(point) as DependencyObject;
            var item = WalkUpVisualTree<ListViewItem>(hit);
            if (item == null) return lv.Items.Count;
            int index = lv.Items.IndexOf(item.DataContext);
            if (index < 0) return lv.Items.Count;
            var itemPos = item.TranslatePoint(new Point(0, 0), lv);
            return point.Y < itemPos.Y + item.ActualHeight / 2 ? index : index + 1;
        }

        // ── Visual tree helper ────────────────────────────────────────────────

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
                FileAddResultWindow.Show(Window.GetWindow(this),
                    result.SuccessCount, result.SkippedCount, result.SkipReasons);

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

    // ── InsertionLineAdorner ──────────────────────────────────────────────────
    //
    // Renders the 2px drop-position indicator using the WPF adorner system.
    // Adorners render in a separate layer (AdornerLayer) that floats above all
    // other visual content, so the line is always visible and never clipped by
    // the ListView's scroll container.
    //
    // Usage:
    //   adorner.Update(mousePositionRelativeToListView)  — reposition and show
    //   adorner.Hide()                                   — hide
    //
    internal sealed class InsertionLineAdorner : Adorner
    {
        private static readonly Pen LinePen = MakePen();
        private double _lineY = -1;
        private bool _visible;

        public InsertionLineAdorner(ListView adornedElement)
            : base(adornedElement) { IsHitTestVisible = false; }

        private ListView ListView => (ListView)AdornedElement;

        /// <summary>
        /// Recalculates line position based on <paramref name="mousePos"/>
        /// (in ListView coordinates) and triggers a redraw.
        /// </summary>
        public void Update(Point mousePos)
        {
            _lineY = CalculateLineY(mousePos);
            _visible = _lineY >= 0;
            InvalidateVisual();
        }

        public void Hide()
        {
            _visible = false;
            InvalidateVisual();
        }

        protected override void OnRender(DrawingContext dc)
        {
            if (!_visible || _lineY < 0) return;

            // The adorner's render coordinate space matches the adornedElement,
            // so we can draw directly in ListView-local coordinates.
            dc.DrawLine(LinePen,
                new Point(0, _lineY),
                new Point(ListView.ActualWidth, _lineY));
        }

        private double CalculateLineY(Point mousePos)
        {
            if (ListView.Items.Count == 0) return -1;

            ListViewItem? nearest = null;
            double nearestDist = double.MaxValue;
            bool insertAfter = false;

            foreach (var dataItem in ListView.Items)
            {
                var container = ListView.ItemContainerGenerator
                    .ContainerFromItem(dataItem) as ListViewItem;
                if (container == null) continue;

                var origin = container.TranslatePoint(new Point(0, 0), ListView);
                var mid = origin.Y + container.ActualHeight / 2.0;
                var dist = Math.Abs(mousePos.Y - mid);

                if (dist < nearestDist)
                {
                    nearestDist = dist;
                    nearest = container;
                    insertAfter = mousePos.Y > mid;
                }
            }

            if (nearest == null) return -1;

            var itemOrigin = nearest.TranslatePoint(new Point(0, 0), ListView);
            return insertAfter
                ? itemOrigin.Y + nearest.ActualHeight
                : itemOrigin.Y;
        }

        private static Pen MakePen()
        {
            // Indigo accent — matches AppPrimaryColor in both themes.
            // Frozen so WPF caches it as a shared resource.
            var brush = new SolidColorBrush(Color.FromRgb(0x63, 0x66, 0xF1));
            brush.Freeze();
            var pen = new Pen(brush, 2.0) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            pen.Freeze();
            return pen;
        }
    }
}
