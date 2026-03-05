// StubInstaller/ManifestLoader.cs - v1.0
// Loads and validates packitmeta.json from the extraction directory.
// Extracted from Program.cs so manifest logic lives in one focused place.
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace StubInstaller
{
    internal static class ManifestLoader
    {
        /// <summary>
        /// Reads and deserializes the manifest from <paramref name="tempDir"/>.
        /// Returns null and shows an error dialog on any failure — caller just checks for null.
        /// </summary>
        internal static async Task<PackageManifest?> LoadAsync(string tempDir)
        {
            string manifestPath = Path.Combine(tempDir, Constants.ManifestFileName);

            if (!File.Exists(manifestPath))
            {
                StubLogger.LogError($"Manifest not found: {manifestPath}", null);
                StubUI.ShowError(
                    $"Package manifest ({Constants.ManifestFileName}) not found.\n\n" +
                    "This package may be corrupted.",
                    "Invalid Package");
                return null;
            }

            try
            {
                var json = await File.ReadAllTextAsync(manifestPath);
                var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var m = JsonSerializer.Deserialize<PackageManifest>(json, opts)
                        ?? throw new InvalidOperationException("Deserialized to null.");

                if (m.Files == null)
                    throw new InvalidOperationException("Manifest.Files is null.");

                StubLogger.Log($"✅ Manifest: '{m.PackageName}' v{m.Version}  " +
                               $"({m.Files.Count} file(s), admin={m.RequiresAdmin}, cleanup={m.Cleanup})");

                StubLogger.Log("  Installers:");
                foreach (var f in m.Files.OrderBy(f => f.InstallOrder))
                {
                    string argsDisplay = f.SilentArgs?.Length > 0
                        ? string.Join(" ", f.SilentArgs)
                        : $"[fallback: {string.Join(" ", InstallerDetector.GetSilentArgs(f.InstallType))}]";

                    string confidence = f.DetectionSource switch
                    {
                        "header" => "header ✅",
                        "manifest" => "manifest ✅",
                        _ => "extension ⚠️",
                    };

                    StubLogger.Log(
                        $"    [{f.InstallOrder}] {f.Name}  " +
                        $"type={f.InstallType} ({confidence})  " +
                        $"args={argsDisplay}  " +
                        $"timeout={f.TimeoutMinutes}m");
                }

                return m;
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to parse manifest", ex);
                StubUI.ShowError(
                    $"Could not read the package manifest.\n\nError: {ex.Message}",
                    "Invalid Manifest");
                return null;
            }
        }
    }
}