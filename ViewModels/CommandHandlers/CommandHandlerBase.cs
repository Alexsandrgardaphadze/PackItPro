// ViewModels/CommandHandlers/CommandHandlerBase.cs
using System;

namespace PackItPro.ViewModels.CommandHandlers
{
    public abstract class CommandHandlerBase : IDisposable
    {
        public event EventHandler? CanExecuteChanged;

        protected void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

        public virtual void Dispose() { }
    }
}