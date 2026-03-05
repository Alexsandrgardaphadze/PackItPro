using System;
using System.Threading.Tasks;

namespace StubInstaller
{
    internal class Program
    {
        static async Task<int> Main(string[] args)
        {
            SilentMode.Initialize(args);

            try
            {
                return await InstallOrchestrator.RunAsync(args);
            }
            catch (Exception ex)
            {
                // Last-resort handler — InstallOrchestrator has its own try/catch
                // but if something throws before the logger is ready, we still exit cleanly
                StubLogger.LogError("UNHANDLED EXCEPTION IN MAIN", ex);
                StubUI.ShowError(
                    $"An unexpected error occurred.\n\nError: {ex.Message}\n\nLog: {StubLogger.LogPath}",
                    "Fatal Error");
                return 1;
            }
        }
    }
}