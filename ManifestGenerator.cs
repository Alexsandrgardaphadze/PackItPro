// ManifestGenerator.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace PackItPro
{
    public static class ManifestGenerator
    {
        public static string Generate(List<string> filePaths, string packageName, bool requiresAdmin, bool includeWingetUpdateScript = false)
        {
            var files = filePaths.Select((path, index) => new ManifestFile
            {
                Name = Path.GetFileName(path),
                InstallType = GetInstallTypeFromExtension(Path.GetExtension(path)),
                SilentArgs = GetDefaultSilentArgs(Path.GetExtension(path)), // Use string[] now
                RequiresAdmin = false, // Could be configurable per file later
                InstallOrder = index
                // TODO: Add WingetId mapping here if available
            }).ToList();

            var manifest = new PackageManifest
            {
                PackageName = packageName,
                Files = files,
                RequiresAdmin = requiresAdmin,
                Cleanup = true // Default to true
            };

            if (includeWingetUpdateScript)
            {
                manifest.AutoUpdateScript = "update_all.bat";
            }

            return JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        }

        private static string GetInstallTypeFromExtension(string ext)
        {
            switch (ext.ToLower())
            {
                case ".msi":
                    return "msi";
                case ".exe":
                    // Could attempt deeper inspection here (e.g., check file headers for Inno, NSIS)
                    return "exe";
                case ".appx":
                case ".appxbundle":
                    return "appx";
                default:
                    return "file"; // Generic file type
            }
        }

        // NEW: Return string[] for silent args
        private static string[]? GetDefaultSilentArgs(string ext)
        {
            switch (ext.ToLower())
            {
                case ".msi":
                    return new[] { "/quiet", "/norestart" };
                case ".exe":
                    // Return an array of common silent flags. The stub installer can try them sequentially.
                    return new[] { "/S", "/silent", "/quiet", "/SILENT", "/VERYSILENT" };
                default:
                    return null;
            }
        }
    }

    // Manifest model (defined here or shared)
    public class PackageManifest
    {
        public string Version { get; set; } = "1.0";
        public string PackageName { get; set; } = "MySoftwareBundle";
        public List<ManifestFile> Files { get; set; } = new List<ManifestFile>();
        public bool Cleanup { get; set; } = true;
        public string? AutoUpdateScript { get; set; } // Optional script name
        public string? SHA256Checksum { get; set; } // NEW: Add SHA256Checksum for integrity verification
        public bool RequiresAdmin { get; set; } = false; // NEW: Add overall package admin requirement
    }

    public class ManifestFile
    {
        public string Name { get; set; } = "";
        public string InstallType { get; set; } = "exe"; // e.g., exe, msi, appx
        public string[]? SilentArgs { get; set; } // Changed to string[]
        public bool RequiresAdmin { get; set; } = false;
        public int InstallOrder { get; set; } = 0;
        // TODO: Add WingetId field for mapping during packaging/update
        // public string? WingetId { get; set; }
    }
}