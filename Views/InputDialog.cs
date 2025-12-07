// Views/InputDialog.cs
using System.Windows;
using System.Windows.Controls;

namespace PackItPro.Views
{
    /// <summary>
    /// Minimal input dialog used by MainViewModel for simple text input (e.g., API key).
    /// Programmatically builds a small Window so no XAML file is required.
    /// </summary>
    public class InputDialog : Window
    {
        private readonly TextBox _textBox;
        public string Answer
        {
            get => _textBox.Text;
            set => _textBox.Text = value;
        }

        public InputDialog(string title, string message, string initial = "")
        {
            Title = title;
            Width = 420;
            Height = 160;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            Owner = Application.Current?.Windows.Count > 0 ? Application.Current.Windows[0] : null;

            var panel = new StackPanel { Margin = new Thickness(12) };
            var txt = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,8) };
            panel.Children.Add(txt);

            _textBox = new TextBox { Text = initial ?? string.Empty, Margin = new Thickness(0,0,0,8) };
            panel.Children.Add(_textBox);

            var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var ok = new Button { Content = "OK", Width = 80, Margin = new Thickness(0,0,8,0) };
            var cancel = new Button { Content = "Cancel", Width = 80 };

            ok.Click += (s, e) => { DialogResult = true; Close(); };
            cancel.Click += (s, e) => { DialogResult = false; Close(); };

            btnPanel.Children.Add(ok);
            btnPanel.Children.Add(cancel);

            panel.Children.Add(btnPanel);
            Content = panel;
        }
    }
}
