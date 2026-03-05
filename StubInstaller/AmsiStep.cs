// StubInstaller/AmsiStep.cs - v1.0
// Runs all extracted installers through the local AV engine via AMSI
// before any of them are executed.
//
// Design decisions:
//   - Scans happen AFTER extraction and integrity check, BEFORE execution.
//     At this point files are in temp — real bytes, no ZIP compression.
//   - A detected threat is ALWAYS fatal, even in silent mode.
//     There is no "continue anyway" for malware.
//   - AMSI unavailable (old OS, no AV) is non-fatal — logged and skipped.
//   - Non-installer files (the manifest, log) are skipped — no point scanning them.
//   - Results are summarised in the log so the user/admin can see what was scanned.
using System.Collections.Generic;
using System.IO;

namespace StubInstaller
{
    internal static class AmsiStep
    {
        // File extensions we actually want to scan.
        // Everything else (manifest JSON, log) is skipped.
        private static readonly HashSet<string> ScannableExtensions = new(
            System.StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".msi", ".msp", ".dll", ".bat", ".cmd",
            ".ps1", ".vbs", ".js", ".jar", ".com", ".scr",
        };

        /// <summary>
        /// Scans all installer files in <paramref name="tempDir"/> that are listed
        /// in the manifest. Returns false (blocking installation) only if a file is
        /// confirmed malicious. AMSI being unavailable is not a blocking condition.
        /// </summary>
        internal static bool ScanAll(List<ManifestFile> files, string tempDir)
        {
            int scanned = 0;
            int skipped = 0;
            int detected = 0;

            foreach (var file in files)
            {
                string filePath = Path.Combine(tempDir, file.Name);
                string ext = Path.GetExtension(file.Name);

                if (!ScannableExtensions.Contains(ext))
                {
                    StubLogger.Log($"  [AMSI] Skipped (not scannable type): {file.Name}");
                    skipped++;
                    continue;
                }

                if (!File.Exists(filePath))
                {
                    // Missing file will be caught properly in Step 6 — don't double-report
                    skipped++;
                    continue;
                }

                StubLogger.Log($"  [AMSI] Scanning: {file.Name} ({Util.FormatBytes(new FileInfo(filePath).Length)})...");

                var result = AmsiScanner.ScanFile(filePath);
                StubLogger.Log($"  [AMSI] Result:   {result.Message}");

                if (!result.Executed)
                {
                    // AMSI unavailable or scan couldn't run — non-fatal
                    skipped++;
                    continue;
                }

                scanned++;

                if (result.IsMalicious)
                {
                    detected++;
                    StubLogger.LogError(
                        $"AMSI MALWARE DETECTED in '{file.Name}' — installation blocked.", null);

                    // Always show malware dialog — bypasses silent mode intentionally.
                    StubUI.ShowMalwareDetected(file.Name);
                }
            }

            // Summary line
            StubLogger.Log($"  [AMSI] Summary: {scanned} scanned, {skipped} skipped, {detected} detected.");

            if (detected > 0)
            {
                StubLogger.LogError($"Installation blocked: {detected} file(s) flagged as malicious.", null);
                return false;
            }

            if (scanned == 0 && skipped > 0)
                StubLogger.Log("  [AMSI] ℹ️  No files were scanned (AMSI unavailable or all files skipped).");
            else
                StubLogger.Log("  ✅ AMSI scan passed.");

            return true;
        }
    }
}