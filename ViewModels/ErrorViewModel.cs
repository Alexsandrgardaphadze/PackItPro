// ViewModels/ErrorViewModel.cs
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// ViewModel for error display and handling
    /// </summary>
    public class ErrorViewModel : INotifyPropertyChanged
    {
        private bool _isErrorVisible;
        private string _errorMessage = string.Empty;
        private bool _canRetry;
        private Action? _retryAction;

        /// <summary>
        /// Gets or sets whether the error panel is visible
        /// </summary>
        public bool IsErrorVisible
        {
            get => _isErrorVisible;
            set
            {
                _isErrorVisible = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Gets or sets the error message to display
        /// </summary>
        public string ErrorMessage
        {
            get => _errorMessage;
            set
            {
                _errorMessage = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Gets or sets whether the retry button should be shown
        /// </summary>
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

        /// <summary>
        /// Command to retry the failed operation
        /// </summary>
        public ICommand RetryCommand { get; }

        /// <summary>
        /// Command to dismiss the error
        /// </summary>
        public ICommand DismissErrorCommand { get; }

        /// <summary>
        /// Event fired when error is shown (for animation triggers)
        /// </summary>
        public event EventHandler? ErrorShown;

        public ErrorViewModel()
        {
            RetryCommand = new RelayCommand(ExecuteRetry, CanExecuteRetry);
            DismissErrorCommand = new RelayCommand(ExecuteDismiss);
        }

        private bool CanExecuteRetry(object? parameter) => CanRetry && _retryAction != null;

        private void ExecuteRetry(object? parameter)
        {
            // Execute the retry action if available
            _retryAction?.Invoke();

            // Hide error after retry
            IsErrorVisible = false;
        }

        private void ExecuteDismiss(object? parameter)
        {
            IsErrorVisible = false;
            _retryAction = null;
            CanRetry = false;
        }

        /// <summary>
        /// Shows an error message
        /// </summary>
        /// <param name="message">The error message to display</param>
        /// <param name="retryAction">Optional action to execute on retry</param>
        public void ShowError(string message, Action? retryAction = null)
        {
            ErrorMessage = message;
            _retryAction = retryAction;
            CanRetry = retryAction != null;
            IsErrorVisible = true;

            // Trigger animation
            ErrorShown?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Clears the current error
        /// </summary>
        public void ClearError()
        {
            IsErrorVisible = false;
            ErrorMessage = string.Empty;
            _retryAction = null;
            CanRetry = false;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
