// PackItPro/ViewModels/ErrorViewModel.cs
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    public class ErrorViewModel : INotifyPropertyChanged
    {
        private bool _isErrorVisible;
        private string _errorMessage = string.Empty;
        private bool _canRetry;
        // ✅ NEW: Support for async retry actions
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
                // Notify the command that its CanExecute state has changed
                if (RetryCommand is RelayCommand relayCommand)
                    relayCommand.RaiseCanExecuteChanged();
            }
        }

        public ICommand RetryCommand { get; }
        public ICommand DismissErrorCommand { get; }

        public event EventHandler? ErrorShown;

        public ErrorViewModel()
        {
            // ✅ FIX: Use async wrapper for retry command
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
                // If retry fails, show the new error
                ShowError($"Retry failed: {ex.Message}");
                return;
            }

            // Hide error after successful retry
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
        /// Shows an error with a synchronous retry action
        /// </summary>
        public void ShowError(string message, Action? retryAction = null)
        {
            ErrorMessage = message;
            _retryActionSync = retryAction;
            _retryActionAsync = null; // Clear async action
            CanRetry = retryAction != null;
            IsErrorVisible = true;
            ErrorShown?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Shows an error with an asynchronous retry action
        /// </summary>
        public void ShowErrorAsync(string message, Func<Task>? retryActionAsync = null)
        {
            ErrorMessage = message;
            _retryActionAsync = retryActionAsync;
            _retryActionSync = null; // Clear sync action
            CanRetry = retryActionAsync != null;
            IsErrorVisible = true;
            ErrorShown?.Invoke(this, EventArgs.Empty);
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