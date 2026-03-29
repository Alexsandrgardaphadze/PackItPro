// StubInstaller/DesignTimeHelper.cs
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

            // Write placeholder files so FileSizeBytes shows realistic values.
            // Includes variety of VT scan states and detection confidence
            // so all UI states can be verified visually without a real package.
            var files = new[]
            {
                // (name, displayName, type, size, scanResult, requiresAdmin)
                ("VLC Media Player-x64.exe",    "VLC Media Player",  "nsis",  41_000_000L,  "clean",    false),
                ("Git-2.42.0-64-bit.exe",       "Git",               "inno",  58_000_000L,  "clean",    true),
                ("OfficeSetup.exe",             "Microsoft Office",  "burn",  750_000_000L, null,       true),
                ("dotnet-sdk-8.0-win-x64.exe",  ".NET SDK 8.0",      "burn",  221_000_000L, "clean",    true),
                ("OBS-Studio-Installer.exe",    "OBS Studio",        "nsis",  133_000_000L, "infected", false),
                ("SomeRedist.exe",              null,                "exe",   2_500_000L,   null,       false),
            };

            var manifestFiles = new List<ManifestFile>();
            int order = 0;
            foreach (var (name, displayName, type, size, scanResult, requiresAdmin) in files)
            {
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
                    ScanResult = scanResult,
                    RequiresAdmin = requiresAdmin,
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