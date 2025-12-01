using System.Windows;
using System.Windows.Controls;

namespace PackItPro.Views
{
    public partial class FileListPanel : UserControl
    {
        public FileListPanel()
        {
            InitializeComponent();
        }

        // These events will be handled by the parent MainWindow
        public event DragEventHandler DragEnter;
        public event DragEventHandler DragLeave;
        public event DragEventHandler Drop;
        public event RoutedEventHandler BrowseFilesClick;

        private void DropArea_DragEnter(object sender, DragEventArgs e)
        {
            DragEnter?.Invoke(sender, e);
        }

        private void DropArea_DragLeave(object sender, DragEventArgs e)
        {
            DragLeave?.Invoke(sender, e);
        }

        private void DropArea_Drop(object sender, DragEventArgs e)
        {
            Drop?.Invoke(sender, e);
        }

        private void BrowseFiles_Click(object sender, RoutedEventArgs e)
        {
            BrowseFilesClick?.Invoke(sender, e);
        }
    }
}