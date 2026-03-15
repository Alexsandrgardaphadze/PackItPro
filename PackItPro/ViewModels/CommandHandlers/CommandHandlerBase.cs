// ViewModels/CommandHandlers/CommandHandlerBase.cs
using System;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    public abstract class CommandHandlerBase : IDisposable
    {
        // CanExecuteChanged on the base class was never subscribed to by anything —
        // MainViewModel proxies commands via _handler?.SomeCommand ?? NullCommand,
        // so the ICommand that WPF binds to is RelayCommand/AsyncRelayCommand, not
        // CommandHandlerBase. Calling RaiseCanExecuteChanged() must invalidate the
        // WPF CommandManager so all bound RelayCommands re-evaluate CanExecute.
        protected static void RaiseCanExecuteChanged() =>
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(
                System.Windows.Threading.DispatcherPriority.Normal,
                new Action(CommandManager.InvalidateRequerySuggested));

        public virtual void Dispose() { }
    }
}