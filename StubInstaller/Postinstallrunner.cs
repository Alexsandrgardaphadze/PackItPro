// StubInstaller/PostInstallRunner.cs
// Executes the optional post-install script defined in the manifest.
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace StubInstaller
{
    internal static class PostInstallRunner
    {
        /// <summary>
        /// Runs <see cref="PackageManifest.AutoUpdateScript"/> if one is set.
        /// Silently skips if the field is empty or the file is missing.
        /// Script path is validated to be inside <paramref name="tempDir"/> to prevent traversal attacks.
        /// </summary>
        internal static async Task RunAsync(PackageManifest manifest, string tempDir)
        {
            if (string.IsNullOrEmpty(manifest.AutoUpdateScript)) return;

            StubLogger.Log("");
            StubLogger.Log("STEP 7: Running post-install script...");

            if (!PathHelper.TryResolveSafe(tempDir, manifest.AutoUpdateScript,
                    out string scriptPath, out string? pathError))
            {
                StubLogger.LogError(
                    $"SECURITY: {pathError} — skipping post-install script", null);
                return;
            }

            if (!File.Exists(scriptPath))
            {
                StubLogger.Log($"⚠️  Script not found: {scriptPath}");
                return;
            }

            try
            {
                var proc = Process.Start(new ProcessStartInfo(scriptPath)
                {
                    UseShellExecute = true,
                    WorkingDirectory = tempDir,
                });
                
                if (proc != null)
                {
                    await proc.WaitForExitAsync();
                    StubLogger.Log($"Script exited with code: {proc.ExitCode}");
                }
            }
            catch (Exception ex)
            {
                StubLogger.LogError("Post-install script failed", ex);
            }
        }
    }
}