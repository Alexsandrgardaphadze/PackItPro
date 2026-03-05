// StubInstaller/SilentMode.cs - v1.0
// Global state for the /silent flag.
//
// When silent mode is active:
//   - No dialogs are shown (completion, errors, integrity warnings)
//   - All output goes to the log file only
//   - Integrity mismatch is treated as fatal (can't prompt user)
//   - AMSI malware detection is still shown (it's always fatal regardless)
//   - Exit codes are still returned for automation/CI use
//
// Usage:
//   Pass --silent or /silent on the command line when running the packaged EXE.
//   Example: MyBundle.exe --silent
//   Example: MyBundle.exe --silent --log-path C:\Logs\install.log
//
// The flag is parsed once by Program.Main and stored here.
// Every component reads SilentMode.IsEnabled rather than passing a bool around.

namespace StubInstaller
{
    internal static class SilentMode
    {
        /// <summary>True when the stub was launched with --silent or /silent.</summary>
        internal static bool IsEnabled { get; private set; }

        /// <summary>Called once by Program.Main after parsing args.</summary>
        internal static void Initialize(string[] args)
        {
            foreach (var arg in args)
            {
                // ✅ FIX Issue 7: Use Constants.ArgSilent instead of hardcoded string
                if (arg.Equals(Constants.ArgSilent, System.StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("/silent", System.StringComparison.OrdinalIgnoreCase))
                {
                    IsEnabled = true;
                    return;
                }
            }
        }
    }
}