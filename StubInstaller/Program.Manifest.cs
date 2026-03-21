// StubInstaller/Program.Manifest.cs
// Manifest loading and log migration helpers.
using StubInstaller.Core;
using StubInstaller.Infrastrucure;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace StubInstaller
{
    internal partial class Program
    {
        /// <summary>
        /// Loads and validates the package manifest from tempDir.
        /// Returns null and shows an error dialog if loading fails.
        /// Synchronous wrapper — safe to call before the WPF message loop starts.
        /// </summary>
        private static PackageManifest? LoadManifestSync(string tempDir)
        {
            string manifestPath = Path.Combine(tempDir, Constants.ManifestFileName);

            if (!File.Exists(manifestPath))
            {
                StubLogger.LogError($"Manifest not found: {manifestPath}", null);
                ShowError(
                    $"Package manifest ({Constants.ManifestFileName}) not found.\n\nThis package may be corrupted.",
                    "Invalid Package");
                return null;
            }

            try
            {
                var json = File.ReadAllText(manifestPath);
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
                    StubLogger.Log($"    [{f.InstallOrder}] {f.Name}  " +
                                   $"type={f.InstallType} ({confidence})  " +
                                   $"args={argsDisplay}  timeout={f.TimeoutMinutes}m");
                }

                return m;
            }
            catch (Exception ex)
            {
                StubLogger.LogError("FATAL: Failed to parse manifest", ex);
                ShowError($"Could not read the package manifest.\n\nError: {ex.Message}", "Invalid Manifest");
                return null;
            }
        }

        /// <summary>
        /// Moves the bootstrap log (written to %TEMP% before extraction) into the
        /// temp directory so it's co-located with the extracted files and cleaned up
        /// together with them.
        /// </summary>
        private static void MigrateLogToTempDir(string tempDir)
        {
            string newLogPath = Path.Combine(tempDir, Constants.LogFileName);
            try
            {
                string existing = !string.IsNullOrEmpty(StubLogger.LogPath) && File.Exists(StubLogger.LogPath)
                    ? File.ReadAllText(StubLogger.LogPath)
                    : string.Empty;

                File.WriteAllText(newLogPath, existing);
                try { File.Delete(StubLogger.LogPath!); } catch { }
                StubLogger.LogPath = newLogPath;
            }
            catch { /* Non-fatal — keep the bootstrap log path */ }
        }
    }
}