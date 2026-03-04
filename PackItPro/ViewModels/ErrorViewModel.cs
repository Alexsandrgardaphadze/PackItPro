// ViewModels/ErrorViewModel.cs - v2.3
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// ViewModel for error display and handling with support for both sync and async retry actions.
    /// FIX: Since ErrorPanel is removed from UI, errors fallback to MessageBox to ensure visibility.
    /// </summary>
    public class ErrorViewModel : INotifyPropertyChanged
    {
        private bool _isErrorVisible;
        private string _errorMessage = string.Empty;
        private bool _canRetry;

        private Func<Task>? _retryActionAsync;
        private Action? _retryActionSync;

        public bool IsErrorVisible
        {
            get => _isErrorVisible;
            set { _isErrorVisible = value; OnPropertyChanged(); }
        }

        public string ErrorMessage
        {
            get => _errorMessage;
            set { _errorMessage = value; OnPropertyChanged(); }
        }

        public bool CanRetry
        {
            get => _canRetry;
            set
            {
                _canRetry = value;
                OnPropertyChanged();
                ((RelayCommand)RetryCommand).RaiseCanExecuteChanged();
            }
        }

        public ICommand RetryCommand { get; }
        public ICommand DismissErrorCommand { get; }

        public event EventHandler? ErrorShown;

        public ErrorViewModel()
        {
            RetryCommand = new RelayCommand(async _ => await ExecuteRetryAsync(), CanExecuteRetry);
            DismissErrorCommand = new RelayCommand(ExecuteDismiss);
        }

        private bool CanExecuteRetry(object? parameter) =>
            CanRetry && (_retryActionAsync != null || _retryActionSync != null);

        private async Task ExecuteRetryAsync()
        {
            try
            {
                if (_retryActionAsync != null)
                {
                    await _retryActionAsync();
                }
                else if (_retryActionSync != null)
                {
                    _retryActionSync();
                }
            }
            catch (Exception ex)
            {
                ShowError($"Retry failed: {ex.Message}");
                return;
            }

            IsErrorVisible = false;
        }

        private void ExecuteDismiss(object? parameter)
        {
            IsErrorVisible = false;
            _retryActionAsync = null;
            _retryActionSync = null;
            CanRetry = false;
        }

        /// <summary>
        /// Shows an error with a synchronous retry action.
        /// FIX: Falls back to MessageBox since ErrorPanel is not displayed.
        /// </summary>
        public void ShowError(string message, Action? retryAction = null)
        {
            ErrorMessage = message;
            _retryActionSync = retryAction;
            _retryActionAsync = null;
            CanRetry = retryAction != null;
            IsErrorVisible = true;
            ErrorShown?.Invoke(this, EventArgs.Empty);

            // FIX: Fallback to MessageBox for visibility
            var result = MessageBox.Show(
                message + (retryAction != null ? "\n\nTry again?" : ""),
                "Error",
                retryAction != null ? MessageBoxButton.YesNo : MessageBoxButton.OK,
                MessageBoxImage.Error);

            if (result == MessageBoxResult.Yes && retryAction != null)
            {
                retryAction();
            }
        }

        /// <summary>
        /// Shows an error with an asynchronous retry action.
        /// FIX: Falls back to MessageBox since ErrorPanel is not displayed.
        /// </summary>
        public void ShowErrorAsync(string message, Func<Task>? retryActionAsync = null)
        {
            ErrorMessage = message;
            _retryActionAsync = retryActionAsync;
            _retryActionSync = null;
            CanRetry = retryActionAsync != null;
            IsErrorVisible = true;
            ErrorShown?.Invoke(this, EventArgs.Empty);

            // FIX: Fallback to MessageBox for visibility
            var result = MessageBox.Show(
                message + (retryActionAsync != null ? "\n\nTry again?" : ""),
                "Error",
                retryActionAsync != null ? MessageBoxButton.YesNo : MessageBoxButton.OK,
                MessageBoxImage.Error);

            if (result == MessageBoxResult.Yes && retryActionAsync != null)
            {
                _ = retryActionAsync();
            }
        }

        /// <summary>
        /// Clears the current error
        /// </summary>
        public void ClearError()
        {
            IsErrorVisible = false;
            ErrorMessage = string.Empty;
            _retryActionAsync = null;
            _retryActionSync = null;
            CanRetry = false;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}