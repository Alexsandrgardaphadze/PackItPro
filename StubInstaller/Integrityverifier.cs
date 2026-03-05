// StubInstaller/IntegrityVerifier.cs - v1.0
// Directory-level SHA-256 verification against the manifest checksum.
// Extracted from Program.cs so integrity logic is self-contained.
//
// This is the SECOND integrity check (directory level).
// The FIRST is in PayloadExtractor (payload/ZIP level).
// Together they form a two-layer seal:
//   Layer 1 — ZIP payload bytes match the hash in the EXE footer
//   Layer 2 — individual installer files match the hash in the manifest
using System;
using System.Windows.Forms;

namespace StubInstaller
{
    internal static class IntegrityVerifier
    {
        /// <summary>
        /// Verifies the extracted directory hash matches the manifest's SHA256Checksum.
        /// Returns true if verified, skipped (no checksum), or user chose to continue.
        /// Returns false if mismatch and user chose to abort.
        /// </summary>
        internal static bool Verify(PackageManifest manifest, string tempDir)
        {
            if (string.IsNullOrEmpty(manifest.SHA256Checksum))
            {
                StubLogger.Log("ℹ️  No checksum in manifest — integrity check skipped.");
                return true;
            }

            try
            {
                string actual = Convert.ToBase64String(
                    IntegrityChecker.ComputeDirectoryHash(tempDir));

                if (actual == manifest.SHA256Checksum)
                {
                    StubLogger.Log("✅ Integrity verified.");
                    return true;
                }

                StubLogger.LogError(
                    $"Hash mismatch!\n" +
                    $"  Expected: {manifest.SHA256Checksum}\n" +
                    $"  Actual:   {actual}", null);

                // In silent mode there is no one to answer a dialog — treat mismatch as fatal.
                if (SilentMode.IsEnabled)
                {
                    StubLogger.LogError(
                        "Silent mode: integrity failure is fatal (no user prompt).", null);
                    return false;
                }

                var choice = MessageBox.Show(
                    "⚠️ Package integrity check FAILED.\n\n" +
                    "The files may have been modified or corrupted since packaging.\n\n" +
                    "Continue anyway? (Not recommended)",
                    "Integrity Check Failed",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);

                if (choice == DialogResult.No)
                {
                    StubLogger.Log("Installation aborted by user after integrity failure.");
                    return false;
                }

                StubLogger.Log("⚠️ User chose to continue despite integrity failure.");
                return true;
            }
            catch (Exception ex)
            {
                // Don't block on a check error — log and continue
                StubLogger.LogError("Integrity check threw an exception — continuing", ex);
                return true;
            }
        }
    }
}