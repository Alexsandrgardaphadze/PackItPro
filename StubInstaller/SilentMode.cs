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