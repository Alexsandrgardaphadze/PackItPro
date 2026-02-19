// ViewModels/AsyncRelayCommand.cs - v2.4 PRODUCTION
using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace PackItPro.ViewModels
{
    /// <summary>
    /// Async command implementation that properly tracks execution state.
    /// Prevents double-execution and updates CanExecute during async operations.
    /// </summary>
    public class AsyncRelayCommand : ICommand
    {
        private readonly Func<object?, Task> _execute;
        private readonly Func<object?, bool>? _canExecute;
        private bool _isExecuting;

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public AsyncRelayCommand(Func<object?, Task> execute, Func<object?, bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter)
        {
            // Can't execute if already running OR if custom condition fails
            return !_isExecuting && (_canExecute?.Invoke(parameter) ?? true);
        }

        public async void Execute(object? parameter)
        {
            if (!CanExecute(parameter)) return;

            _isExecuting = true;
            RaiseCanExecuteChanged();

            try
            {
                await _execute(parameter);
            }
            catch (Exception ex)
            {
                // Log but don't crash — caller should handle exceptions
                System.Diagnostics.Debug.WriteLine($"[AsyncRelayCommand] Unhandled exception: {ex}");
                throw;
            }
            finally
            {
                _isExecuting = false;
                RaiseCanExecuteChanged();
            }
        }

        public void RaiseCanExecuteChanged()
        {
            CommandManager.InvalidateRequerySuggested();
        }
    }
}