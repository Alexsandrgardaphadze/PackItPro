using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace PackItPro.Views
{
    public partial class FileListPanel : UserControl
    {
        public FileListPanel()
        {
            InitializeComponent();
        }

        // The DataContext of this control will be a FileListViewModel.
        // We can cast it to get access to its commands.

        private void UserControl_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                var hoverBrush = TryFindResource("AppDropAreaHoverColor") as SolidColorBrush
                                 ?? new SolidColorBrush(Colors.LightBlue);
                var color = hoverBrush.Color;
                // Since DropAreaBorder is the root, we can style it directly.
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
                // Now, forward the files to the ViewModel's command.
                if (this.DataContext is ViewModels.FileListViewModel viewModel)
                {
                    // We can invoke the command directly and pass the files as a parameter.
                    // The command logic will be inside the ViewModel.
                    viewModel.AddFilesCommand?.Execute(files);
                }
            }
        }
    }
}