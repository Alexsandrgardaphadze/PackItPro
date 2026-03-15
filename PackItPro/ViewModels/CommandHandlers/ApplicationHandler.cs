// ViewModels/CommandHandlers/ApplicationHandler.cs
using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace PackItPro.ViewModels.CommandHandlers
{
    /// <summary>
    /// Handles application-level operations (Exit, etc.)
    /// </summary>
    public class ApplicationHandler : CommandHandlerBase
    {
        private readonly SettingsViewModel _settings;

        public ICommand ExitCommand { get; }

        public ApplicationHandler(SettingsViewModel settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            // AsyncRelayCommand is required here — RelayCommand takes Action<object?>
            // which would silently create an async void delegate. Exceptions from
            // SaveSettingsAsync would be unobserved and crash the process on exit.
            ExitCommand = new AsyncRelayCommand(async _ => await ExecuteExitAsync());
        }

        private async Task ExecuteExitAsync()
        {
            // Save settings before exiting
            await _settings.SaveSettingsAsync();
            Application.Current.Shutdown();
        }
    }
}