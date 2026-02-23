// StubInstaller/InstallerDetector.cs - v1.5 DETECTION FIX
// Changes vs v1.4:
//   - Added "squirrel" type: silent flag is "--silent" (not /S)
//     Used by UniGetUI, GitHub Desktop, Slack, Discord, Teams, etc.
//   - Added "burn" type: WiX Burn bootstrapper, silent flag is "/quiet /norestart"
//   - Type strings must stay in sync with ManifestGenerator.DetectInstallType()

namespace StubInstaller
{
    public static class InstallerDetector
    {
        /// <summary>
        /// Returns silent arguments for a given installer type string.
        /// Type strings match ManifestGenerator.DetectInstallType() output exactly:
        ///   "msi", "msp", "appx", "msix", "inno", "nsis", "squirrel", "burn", "exe", "file"
        /// </summary>
        public static string[] GetSilentArgs(string installType)
        {
            return installType.ToLowerInvariant() switch
            {
                "msi" => new[] { "/quiet", "/norestart" },
                "msp" => new[] { "/quiet", "/norestart" },
                "inno" => new[] { "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" },
                "nsis" => new[] { "/S" },

                // Squirrel / Electron installers (UniGetUI, GitHub Desktop, Discord, Slack...)
                // These use "--silent", not "/S"
                "squirrel" => new[] { "--silent" },

                // WiX Burn bootstrapper
                "burn" => new[] { "/quiet", "/norestart" },

                // Generic EXE: try /S (most universal single flag)
                "exe" => new[] { "/S" },

                // Store / patch formats — no standard silent CLI flag
                "appx" => Array.Empty<string>(),
                "msix" => Array.Empty<string>(),
                "file" => Array.Empty<string>(),

                // Unknown type — attempt /S, may or may not work
                _ => new[] { "/S" },
            };
        }
    }
}