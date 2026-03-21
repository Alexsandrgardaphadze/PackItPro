// StubInstaller/DesignTimeHelper.cs
// Developer utility — creates a fake manifest and temp dir so you can
// launch the WPF window without building a real package first.
// Usage: in Program.cs RunWpfInstaller, temporarily call
//   RunWpfInstaller(DesignTimeHelper.CreateFakePackage());
// Delete or #if DEBUG guard this file before shipping.
#if DEBUG
using StubInstaller.Core;
using System;
using System.Collections.Generic;
using System.IO;

namespace StubInstaller
{
    internal static class DesignTimeHelper
    {
        /// <summary>
        /// Creates a temp directory with fake installer files and returns
        /// (tempDir, manifest) ready to pass straight to RunWpfInstaller.
        /// </summary>
        public static (string tempDir, PackageManifest manifest) CreateFakePackage()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "PackItPro", "UI_Test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

            // Write placeholder files so FileSizeBytes shows realistic values
            var files = new[]
            {
                ("VLC Media Player-x64.exe",      "vlc",    "nsis",   41_000_000L),
                ("Git-2.42.0-64-bit.exe",         null,     "inno",   58_000_000L),
                ("OfficeSetup.exe",               "Microsoft Office", "burn",  750_000_000L),
                ("dotnet-sdk-8.0-win-x64.exe",   ".NET SDK 8.0",     "exe",   221_000_000L),
                ("OBS-Studio-Installer.exe",      "OBS Studio",       "nsis",  133_000_000L),
            };

            var manifestFiles = new List<ManifestFile>();
            int order = 0;
            foreach (var (name, displayName, type, size) in files)
            {
                // Write a file of approximately the right size
                string path = Path.Combine(tempDir, name);
                using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
                fs.SetLength(size);

                manifestFiles.Add(new ManifestFile
                {
                    Name = name,
                    DisplayName = displayName,
                    InstallType = type,
                    DetectionSource = displayName != null ? "header" : "extension",
                    SilentArgs = null,
                    InstallOrder = order++,
                    TimeoutMinutes = 10,
                    Notes = name.Contains("Office") ? "Requires product key" : null,
                });
            }

            var manifest = new PackageManifest
            {
                PackageName = "My Software Bundle",
                Version = "1.0",
                Files = manifestFiles,
                RequiresAdmin = true,
                Cleanup = false,  // keep temp dir for repeated testing
            };

            return (tempDir, manifest);
        }
    }
}
#endif