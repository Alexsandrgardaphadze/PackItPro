// StubInstaller/PayloadExtractor.cs - FINAL CORRECTED VERSION v2.0
// Updated to extract and verify payload using footer-based SHA256 hash.
// Supports both old (v2.2: 18 bytes) and new (v2.3: 50 bytes) footer formats.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace StubInstaller
{
    public static class PayloadExtractor
    {
        // Constants for new v2.3 footer format with hash
        private const string PAYLOAD_MARKER = "PACKIT_END"; // 10 bytes ASCII
        private const int MARKER_LENGTH = 10;
        private const int SIZE_LENGTH = sizeof(long); // 8 bytes
        private const int HASH_LENGTH = 32; // SHA256 output is 32 bytes
        private const int FOOTER_LENGTH_V23 = SIZE_LENGTH + HASH_LENGTH + MARKER_LENGTH; // 50 bytes
        
        // Legacy v2.2 format
        private const int FOOTER_LENGTH_V22 = SIZE_LENGTH + MARKER_LENGTH; // 18 bytes

        /// <summary>
        /// Extracts the payload that was appended to the end of this executable file.
        /// Verifies integrity by computing SHA256 hash of extracted payload and comparing
        /// to hash stored in footer (if v2.3 format is detected).
        /// </summary>
        public static byte[] ExtractPayloadFromEndOfFile()
        {
            LogDebug("========== PAYLOAD EXTRACTION START ==========");

            // ============================================================
            // STEP 1: DETERMINE EXECUTABLE PATH
            // ============================================================
            LogDebug("Step 1: Determining executable path...");

            string? exePath = null;

            // Method 1: MainModule (most reliable)
            try
            {
                exePath = Process.GetCurrentProcess().MainModule?.FileName;
                LogDebug($"Method 1 (MainModule): {exePath ?? "null"}");
            }
            catch (Exception ex)
            {
                LogDebug($"Method 1 failed: {ex.Message}");
            }

            // Method 2: ProcessPath
            if (string.IsNullOrEmpty(exePath))
            {
                exePath = Environment.ProcessPath;
                LogDebug($"Method 2 (ProcessPath): {exePath ?? "null"}");
            }

            // Method 3: Command line arguments
            if (string.IsNullOrEmpty(exePath))
            {
                var args = Environment.GetCommandLineArgs();
                if (args.Length > 0)
                {
                    // Command line arg might be relative, make it absolute
                    string arg0 = args[0];
                    if (!Path.IsPathRooted(arg0))
                    {
                        arg0 = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, arg0));
                    }
                    exePath = arg0;
                    LogDebug($"Method 3 (CommandLine): {exePath ?? "null"}");
                }
            }

            // Method 4: BaseDirectory + exe name (for single-file apps)
            if (string.IsNullOrEmpty(exePath))
            {
                string baseDir = AppContext.BaseDirectory;
                string exeName = Process.GetCurrentProcess().ProcessName + ".exe";
                exePath = Path.Combine(baseDir, exeName);
                LogDebug($"Method 4 (BaseDirectory): {exePath ?? "null"}");
            }

            // Validate
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                throw new InvalidOperationException(
                    $"Cannot determine executable path. Attempted methods:\n" +
                    $"  MainModule: {TryGetMainModule() ?? "null"}\n" +
                    $"  ProcessPath: {Environment.ProcessPath ?? "null"}\n" +
                    $"  CommandLine: {TryGetCommandLine() ?? "null"}\n" +
                    $"  BaseDirectory: {AppContext.BaseDirectory ?? "null"}\n\n" +
                    $"Final path: {exePath ?? "null"}\n" +
                    $"File exists: {(!string.IsNullOrEmpty(exePath) && File.Exists(exePath))}");
            }

            LogDebug($"✅ Executable path resolved: {exePath}");

            var fileInfo = new FileInfo(exePath);
            LogDebug($"File size: {FormatBytes(fileInfo.Length)}");

            // ============================================================
            // STEP 2: VALIDATE FILE SIZE
            // ============================================================
            LogDebug("Step 2: Validating file size...");

            // Try v2.3 first, fall back to v2.2
            int footerSize = FOOTER_LENGTH_V23;
            if (fileInfo.Length < FOOTER_LENGTH_V23)
            {
                if (fileInfo.Length < FOOTER_LENGTH_V22)
                {
                    throw new InvalidOperationException(
                        $"File is too small ({fileInfo.Length} bytes) to contain payload footer.\n" +
                        $"Minimum required: {FOOTER_LENGTH_V22} bytes (v2.2) or {FOOTER_LENGTH_V23} bytes (v2.3).\n" +
                        $"This EXE may not be a packaged installer.\n" +
                        $"Expected: Packaged installer with embedded payload\n" +
                        $"Found: Raw stub executable");
                }
                // File is large enough for v2.2 but not v2.3, will detect version in step 3
                footerSize = -1; // Let step 3 decide
            }

            // ============================================================
            // STEP 3: READ AND DETECT FOOTER VERSION
            // ============================================================
            LogDebug("Step 3: Reading and analyzing footer...");

            byte[] footer;
            int detectedFooterSize;

            using (var fs = File.OpenRead(exePath))
            {
                // Try reading v2.3 footer first (50 bytes)
                fs.Seek(-FOOTER_LENGTH_V23, SeekOrigin.End);
                footer = new byte[FOOTER_LENGTH_V23];

                int totalRead = 0;
                while (totalRead < FOOTER_LENGTH_V23)
                {
                    int bytesRead = fs.Read(footer, totalRead, FOOTER_LENGTH_V23 - totalRead);
                    if (bytesRead <= 0)
                    {
                        throw new InvalidOperationException(
                            $"Failed to read footer. Read {totalRead}/{FOOTER_LENGTH_V23} bytes.");
                    }
                    totalRead += bytesRead;
                }

                LogDebug($"Footer read successfully: {totalRead} bytes");
            }

            // Check marker position to determine version
            string marker23 = Encoding.ASCII.GetString(footer, SIZE_LENGTH + HASH_LENGTH, MARKER_LENGTH);
            string marker22 = Encoding.ASCII.GetString(footer, SIZE_LENGTH, MARKER_LENGTH);

            if (marker23 == PAYLOAD_MARKER)
            {
                detectedFooterSize = FOOTER_LENGTH_V23;
                LogDebug("✅ Detected footer version: v2.3 (with SHA256 hash)");
            }
            else if (marker22 == PAYLOAD_MARKER)
            {
                detectedFooterSize = FOOTER_LENGTH_V22;
                LogDebug("ℹ️  Detected footer version: v2.2 (without hash) — falling back");
                // Trim footer to v2.2 size
                Array.Resize(ref footer, FOOTER_LENGTH_V22);
            }
            else
            {
                throw new InvalidOperationException(
                    $"Invalid payload marker.\n" +
                    $"Expected: '{PAYLOAD_MARKER}'\n" +
                    $"Found (v2.3 pos): '{marker23}'\n" +
                    $"Found (v2.2 pos): '{marker22}'\n\n" +
                    $"This file may not be a packaged installer, or it may be corrupted.");
            }

            // ============================================================
            // STEP 4: PARSE PAYLOAD SIZE
            // ============================================================
            LogDebug("Step 4: Parsing payload size...");

            byte[] sizeBytes = new byte[SIZE_LENGTH];
            Array.Copy(footer, 0, sizeBytes, 0, SIZE_LENGTH);
            long payloadSize = BitConverter.ToInt64(sizeBytes, 0);

            LogDebug($"Raw size bytes: {BitConverter.ToString(sizeBytes)}");
            LogDebug($"Parsed payload size: {FormatBytes(payloadSize)} ({payloadSize} bytes)");

            if (payloadSize <= 0)
            {
                throw new InvalidOperationException(
                    $"Invalid payload size: {payloadSize} bytes.\n" +
                    $"Size must be positive.\n" +
                    $"Raw bytes: {BitConverter.ToString(sizeBytes)}\n\n" +
                    $"This indicates you are running the RAW STUB, not the PACKAGED installer.\n" +
                    $"Current file: {exePath}\n" +
                    $"File size: {FormatBytes(fileInfo.Length)}\n\n" +
                    $"Make sure you are running the packaged EXE created by PackItPro, not StubInstaller.exe directly!");
            }

            if (payloadSize > fileInfo.Length - detectedFooterSize)
            {
                throw new InvalidOperationException(
                    $"Payload size ({FormatBytes(payloadSize)}) is larger than available space.\n" +
                    $"File size: {FormatBytes(fileInfo.Length)}\n" +
                    $"Footer size: {detectedFooterSize} bytes\n" +
                    $"Max payload: {FormatBytes(fileInfo.Length - detectedFooterSize)}");
            }

            // ============================================================
            // STEP 5: EXTRACT PAYLOAD HASH (if v2.3)
            // ============================================================
            byte[]? expectedPayloadHash = null;
            if (detectedFooterSize == FOOTER_LENGTH_V23)
            {
                LogDebug("Step 5: Extracting payload hash from footer...");
                expectedPayloadHash = new byte[HASH_LENGTH];
                Array.Copy(footer, SIZE_LENGTH, expectedPayloadHash, 0, HASH_LENGTH);
                LogDebug($"Expected hash: {Convert.ToBase64String(expectedPayloadHash)}");
            }
            else
            {
                LogDebug("Step 5: Skipped (v2.2 format has no hash)");
            }

            // ============================================================
            // STEP 6: CALCULATE PAYLOAD OFFSET
            // ============================================================
            LogDebug("Step 6: Calculating payload offset...");

            long payloadOffset = fileInfo.Length - detectedFooterSize - payloadSize;

            LogDebug($"File size: {fileInfo.Length}");
            LogDebug($"Footer size: {detectedFooterSize}");
            LogDebug($"Payload size: {payloadSize}");
            LogDebug($"Calculated offset: {payloadOffset}");

            if (payloadOffset < 0)
            {
                throw new InvalidOperationException(
                    $"Invalid payload offset: {payloadOffset}\n" +
                    $"This suggests the payload size in the footer is incorrect.");
            }

            // ============================================================
            // STEP 7: EXTRACT PAYLOAD (and compute hash if needed)
            // ============================================================
            LogDebug("Step 7: Extracting payload...");

            byte[] payload = new byte[payloadSize];
            byte[]? computedPayloadHash = null;

            using (var fs = File.OpenRead(exePath))
            using (var sha = expectedPayloadHash != null ? SHA256.Create() : null)
            {
                fs.Seek(payloadOffset, SeekOrigin.Begin);

                int totalRead = 0;
                while (totalRead < payloadSize)
                {
                    int remaining = (int)(payloadSize - totalRead);
                    int toRead = Math.Min(remaining, 81920); // 80 KB chunks

                    int bytesRead = fs.Read(payload, totalRead, toRead);
                    if (bytesRead <= 0)
                    {
                        throw new InvalidOperationException(
                            $"Unexpected EOF while reading payload. " +
                            $"Read {totalRead}/{payloadSize} bytes.");
                    }

                    // Hash as we read (streaming hash)
                    if (sha != null)
                    {
                        sha.TransformBlock(payload, totalRead, bytesRead, null, 0);
                    }

                    totalRead += bytesRead;

                    if (totalRead % (1024 * 1024) == 0) // Log every MB
                    {
                        LogDebug($"  Read {FormatBytes(totalRead)}/{FormatBytes(payloadSize)}...");
                    }
                }

                // Finalize hash if computing
                if (sha != null)
                {
                    sha.TransformFinalBlock(payload, 0, 0);
                    computedPayloadHash = sha.Hash;
                }

                LogDebug($"✅ Payload extracted: {FormatBytes(totalRead)}");
            }

            // ============================================================
            // STEP 8: VERIFY PAYLOAD INTEGRITY (if v2.3)
            // ============================================================
            if (expectedPayloadHash != null && computedPayloadHash != null)
            {
                LogDebug("Step 8: Verifying payload integrity...");

                string expectedHashStr = Convert.ToBase64String(expectedPayloadHash);
                string computedHashStr = Convert.ToBase64String(computedPayloadHash);

                LogDebug($"Expected: {expectedHashStr}");
                LogDebug($"Computed: {computedHashStr}");

                if (!ByteArraysEqual(expectedPayloadHash, computedPayloadHash))
                {
                    throw new InvalidOperationException(
                        $"⚠️ PAYLOAD INTEGRITY CHECK FAILED!\n\n" +
                        $"The ZIP payload has been modified or corrupted.\n\n" +
                        $"Expected hash: {expectedHashStr}\n" +
                        $"Computed hash: {computedHashStr}\n\n" +
                        $"Possible causes:\n" +
                        $"  • File was tampered with\n" +
                        $"  • Disk corruption during transfer\n" +
                        $"  • Network transmission error\n" +
                        $"  • Antivirus modification\n\n" +
                        $"Installation cannot proceed.");
                }

                LogDebug("✅ Payload integrity verified successfully!");
            }
            else if (detectedFooterSize == FOOTER_LENGTH_V22)
            {
                LogDebug("Step 8: Skipped (v2.2 format has no hash to verify)");
            }

            // ============================================================
            // STEP 9: VERIFY ZIP HEADER
            // ============================================================
            LogDebug("Step 9: Verifying ZIP header...");

            if (payload.Length >= 4)
            {
                // ZIP files start with "PK\x03\x04" (0x50 0x4B 0x03 0x04)
                if (payload[0] == 0x50 && payload[1] == 0x4B &&
                    payload[2] == 0x03 && payload[3] == 0x04)
                {
                    LogDebug("✅ Valid ZIP header detected (PK\\x03\\x04)");
                }
                else
                {
                    LogDebug($"⚠️ WARNING: Unexpected header bytes: " +
                             $"{payload[0]:X2} {payload[1]:X2} {payload[2]:X2} {payload[3]:X2}");
                    LogDebug("Expected ZIP header: 50 4B 03 04");
                    LogDebug("Payload may not be a valid ZIP file!");
                }
            }

            LogDebug("========== PAYLOAD EXTRACTION SUCCESS ==========");
            return payload;
        }

        /// <summary>
        /// Extracts the provided payload bytes (assumed to be a ZIP archive) to a temporary directory.
        /// SECURITY: Validates all extraction paths to prevent Zip Slip (directory traversal) attacks.
        /// </summary>
        public static string ExtractPayloadToTempDirectory(byte[] payloadData)
        {
            LogDebug("========== ZIP EXTRACTION START ==========");
            LogDebug($"Payload size: {FormatBytes(payloadData.Length)}");

            // Create unique temp directory
            var tempPath = Path.Combine(
                Path.GetTempPath(),
                "PackItPro",
                Guid.NewGuid().ToString());

            LogDebug($"Creating temp directory: {tempPath}");
            Directory.CreateDirectory(tempPath);

            try
            {
                // SECURITY: Normalize the extraction root for path validation
                // Add separator to ensure extracted paths are within this directory
                string fullTempPath = Path.GetFullPath(tempPath + Path.DirectorySeparatorChar);
                LogDebug($"Extraction root (normalized): {fullTempPath}");

                // Extract ZIP from memory
                using (var zipStream = new MemoryStream(payloadData))
                {
                    LogDebug("Opening ZIP archive...");

                    using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Read))
                    {
                        LogDebug($"ZIP contains {archive.Entries.Count} entries");

                        int extracted = 0;
                        foreach (var entry in archive.Entries)
                        {
                            // Skip directory entries
                            if (string.IsNullOrEmpty(entry.Name))
                                continue;

                            // SECURITY: Validate entry path to prevent Zip Slip (CWE-22)
                            // This prevents malicious ZIPs with paths like "../../../etc/passwd"
                            string destPath = Path.Combine(tempPath, entry.FullName);
                            string fullDestPath = Path.GetFullPath(destPath);

                            // Ensure the normalized destination path is within the extraction root
                            if (!fullDestPath.StartsWith(fullTempPath, StringComparison.OrdinalIgnoreCase))
                            {
                                throw new InvalidOperationException(
                                    $"SECURITY VIOLATION: ZIP entry path attempts to escape extraction directory.\n" +
                                    $"Entry: {entry.FullName}\n" +
                                    $"Resolves to: {fullDestPath}\n" +
                                    $"Extraction root: {fullTempPath}\n" +
                                    $"This ZIP archive may be malicious or corrupted. Extraction aborted.");
                            }

                            // Create directory if needed
                            var destDir = Path.GetDirectoryName(fullDestPath);
                            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                            {
                                Directory.CreateDirectory(destDir);
                            }

                            LogDebug($"  [{extracted + 1}/{archive.Entries.Count}] Extracting: {entry.FullName} ({FormatBytes(entry.Length)})");

                            entry.ExtractToFile(fullDestPath, overwrite: true);
                            extracted++;
                        }

                        LogDebug($"✅ Extracted {extracted} file(s)");
                    }
                }

                LogDebug($"✅ Extraction complete: {tempPath}");
                LogDebug("========== ZIP EXTRACTION SUCCESS ==========");

                return tempPath;
            }
            catch (Exception ex)
            {
                LogDebug($"❌ ZIP extraction failed: {ex.Message}");
                LogDebug($"Stack trace: {ex.StackTrace}");

                // Clean up on failure
                try
                {
                    if (Directory.Exists(tempPath))
                    {
                        Directory.Delete(tempPath, true);
                    }
                }
                catch
                {
                    // Ignore cleanup errors
                }

                throw;
            }
        }

        #region Helper Methods

        private static string? TryGetMainModule()
        {
            try
            {
                return Process.GetCurrentProcess().MainModule?.FileName;
            }
            catch
            {
                return null;
            }
        }

        private static string? TryGetCommandLine()
        {
            try
            {
                var args = Environment.GetCommandLineArgs();
                return args.Length > 0 ? args[0] : null;
            }
            catch
            {
                return null;
            }
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        private static void LogDebug(string message)
        {
            var logMessage = $"[PayloadExtractor] {message}";
            Debug.WriteLine(logMessage);
            Console.WriteLine(logMessage);

            // Also write to temp log file
            try
            {
                var logPath = Path.Combine(Path.GetTempPath(), "PackItPro_Extraction.log");
                File.AppendAllText(logPath, $"[{DateTime.Now:HH:mm:ss.fff}] {logMessage}\n");
            }
            catch
            {
                // Ignore log write failures
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        #endregion
    }
}
