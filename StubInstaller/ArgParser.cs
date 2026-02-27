// StubInstaller/ArgParser.cs
// Parses the stub's command-line arguments.
// Supports: --key value,  --key=value,  --key="value with spaces"
using System;

namespace StubInstaller
{
    internal static class ArgParser
    {
        /// <summary>Returns the value for <paramref name="key"/>, or null if absent.</summary>
        internal static string? GetValue(string[] args, string key)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];

                // --key=value  or  --key="value"
                if (arg.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                    return arg[(key.Length + 1)..].Trim('"');

                // --key value  or  --key "value"
                if (arg.Equals(key, StringComparison.OrdinalIgnoreCase) && i < args.Length - 1)
                {
                    string val = args[i + 1];
                    return val.Length >= 2 && val[0] == '"' && val[^1] == '"'
                        ? val[1..^1]
                        : val;
                }
            }
            return null;
        }
    }
}