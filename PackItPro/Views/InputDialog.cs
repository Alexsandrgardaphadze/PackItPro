// Views/InputDialog.cs - v2.0 OPTIMIZED
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace PackItPro.Views
{
    /// <summary>
    /// Minimal input dialog with keyboard support and optional password masking.
    /// v2.0: Added Enter/Esc keys, password masking, better styling
    /// </summary>
    public class InputDialog : Window
    {
        private readonly TextBox? _textBox;
        private readonly PasswordBox? _passwordBox;
        private readonly bool _isMasked;

        public string Answer
        {
            get => _isMasked ? (_passwordBox?.Password ?? "") : (_textBox?.Text ?? "");
            set
            {
                if (_isMasked && _passwordBox != null)
                    _passwordBox.Password = value ?? "";
                else if (_textBox != null)
                    _textBox.Text = value ?? "";
            }
        }

        public InputDialog(string title, string message, string initial = "", bool maskInput = false)
        {
            _isMasked = maskInput;
            Title = title;
            Width = 420;
            Height = 160;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.NoResize;
            Owner = Application.Current?.Windows.Count > 0 ? Application.Current.Windows[0] : null;

            var panel = new StackPanel { Margin = new Thickness(12) };

            // Message
            var txt = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };
            panel.Children.Add(txt);

            // Input field (TextBox or PasswordBox)
            if (maskInput)
            {
                _passwordBox = new PasswordBox
                {
                    Password = initial ?? "",
                    Margin = new Thickness(0, 0, 0, 8)
                };
                // ✅ NEW: Keyboard support for PasswordBox
                _passwordBox.KeyDown += OnInputKeyDown;
                panel.Children.Add(_passwordBox);
            }
            else
            {
                _textBox = new TextBox
                {
                    Text = initial ?? "",
                    Margin = new Thickness(0, 0, 0, 8)
                };
                // ✅ NEW: Keyboard support for TextBox
                _textBox.KeyDown += OnInputKeyDown;
                panel.Children.Add(_textBox);
            }

            // Buttons
            var btnPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var ok = new Button
            {
                Content = "OK",
                Width = 80,
                Margin = new Thickness(0, 0, 8, 0),
                IsDefault = true // ✅ NEW: Enter key triggers this
            };
            var cancel = new Button
            {
                Content = "Cancel",
                Width = 80,
                IsCancel = true // ✅ NEW: Escape key triggers this
            };

            ok.Click += (s, e) => { DialogResult = true; Close(); };
            cancel.Click += (s, e) => { DialogResult = false; Close(); };

            btnPanel.Children.Add(ok);
            btnPanel.Children.Add(cancel);
            panel.Children.Add(btnPanel);

            Content = panel;
        }

        // ✅ NEW: Keyboard handler
        private void OnInputKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                DialogResult = true;
                Close();
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                DialogResult = false;
                Close();
                e.Handled = true;
            }
        }
    }
}