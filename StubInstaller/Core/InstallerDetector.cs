// StubInstaller/InstallerDetector.cs
using System;

namespace StubInstaller.Core
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
                "sharex" => new[] { "/VERYSILENT", "/NORUN" },
                "git-inno" => new[] { "/VERYSILENT", "/NORESTART", "/NOCANCEL", "/SP-",
                                           "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS" },
                "unigetui" => new[] { "/SP", "/VERYSILENT", "/SUPPRESSMSGBOXES",
                                           "/NORESTART", "/NoAutoStart", "/ALLUSERS", "/LANG=english" },
                "vscode-inno" => new[] { "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES",
                                           "/NORESTART", "/MERGETASKS=!runcode" },
                "netfxtool" => new[] { "/q", "/n" },
                "nsis" => new[] { "/S" },
                "squirrel" => new[] { "--silent" },
                "burn" => new[] { "/quiet", "/norestart" },
                "office-c2r" => new[] { "/quiet" },
                "dxcab" => new[] { "/Q", "/T:{tempdir}" }, // handled specially by InstallerRunner

                "jdk" => new[] { "/s" },
                "edgewebview2" => new[] { "--silent", "--system-level" },
                "vcredist" => new[] { "/ai", "/gm2" },
                "vcredist-ms" => new[] { "/install", "/quiet", "/norestart" },
                "dxweb" => new[] { "/Q" },
                "exe" => new[] { "/S" },
                "appx" => Array.Empty<string>(),
                "msix" => Array.Empty<string>(),
                "file" => Array.Empty<string>(),
                _ => new[] { "/S" },
            };
        }
    }
}