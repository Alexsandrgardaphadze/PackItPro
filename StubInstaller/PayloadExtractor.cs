// StubInstaller/PayloadExtractor.cs - FINAL CORRECTED VERSION
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace StubInstaller
{
    public static class PayloadExtractor
    {
        // Constants matching the packer format
        private const string PAYLOAD_MARKER = "PACKIT_END"; // 10 bytes ASCII
        private const int MARKER_LENGTH = 10;
        private const int SIZE_LENGTH = sizeof(long); // 8 bytes
        private const int FOOTER_LENGTH = SIZE_LENGTH + MARKER_LENGTH; // 18 bytes total

        /// <summary>
        /// Extracts the payload that was appended to the end of this executable file.
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

            if (fileInfo.Length < FOOTER_LENGTH)
            {
                throw new InvalidOperationException(
                    $"File is too small ({fileInfo.Length} bytes) to contain payload footer ({FOOTER_LENGTH} bytes).\n" +
                    $"This EXE may not be a packaged installer.\n" +
                    $"Expected: Packaged installer with embedded payload\n" +
                    $"Found: Raw stub executable");
            }

            // ============================================================
            // STEP 3: READ FOOTER
            // ============================================================
            LogDebug("Step 3: Reading footer...");

            byte[] footer;
            using (var fs = File.OpenRead(exePath))
            {
                fs.Seek(-FOOTER_LENGTH, SeekOrigin.End);
                footer = new byte[FOOTER_LENGTH];

                int totalRead = 0;
                while (totalRead < FOOTER_LENGTH)
                {
                    int bytesRead = fs.Read(footer, totalRead, FOOTER_LENGTH - totalRead);
                    if (bytesRead <= 0)
                    {
                        throw new InvalidOperationException(
                            $"Failed to read footer. Read {totalRead}/{FOOTER_LENGTH} bytes.");
                    }
                    totalRead += bytesRead;
                }

                LogDebug($"Footer read successfully: {totalRead} bytes");
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

            if (payloadSize > fileInfo.Length - FOOTER_LENGTH)
            {
                throw new InvalidOperationException(
                    $"Payload size ({FormatBytes(payloadSize)}) is larger than available space.\n" +
                    $"File size: {FormatBytes(fileInfo.Length)}\n" +
                    $"Footer size: {FOOTER_LENGTH} bytes\n" +
                    $"Max payload: {FormatBytes(fileInfo.Length - FOOTER_LENGTH)}");
            }

            // ============================================================
            // STEP 5: VERIFY MARKER
            // ============================================================
            LogDebug("Step 5: Verifying marker...");

            byte[] markerBytes = new byte[MARKER_LENGTH];
            Array.Copy(footer, SIZE_LENGTH, markerBytes, 0, MARKER_LENGTH);
            string marker = Encoding.ASCII.GetString(markerBytes);

            LogDebug($"Raw marker bytes: {BitConverter.ToString(markerBytes)}");
            LogDebug($"Parsed marker: '{marker}'");
            LogDebug($"Expected marker: '{PAYLOAD_MARKER}'");

            if (marker != PAYLOAD_MARKER)
            {
                throw new InvalidOperationException(
                    $"Invalid payload marker.\n" +
                    $"Expected: '{PAYLOAD_MARKER}'\n" +
                    $"Found: '{marker}'\n" +
                    $"Raw bytes: {BitConverter.ToString(markerBytes)}\n\n" +
                    $"This file may not be a packaged installer, or it may be corrupted.");
            }

            LogDebug("✅ Marker verified successfully");

            // ============================================================
            // STEP 6: CALCULATE PAYLOAD OFFSET
            // ============================================================
            LogDebug("Step 6: Calculating payload offset...");

            long payloadOffset = fileInfo.Length - FOOTER_LENGTH - payloadSize;

            LogDebug($"File size: {fileInfo.Length}");
            LogDebug($"Footer size: {FOOTER_LENGTH}");
            LogDebug($"Payload size: {payloadSize}");
            LogDebug($"Calculated offset: {payloadOffset}");

            if (payloadOffset < 0)
            {
                throw new InvalidOperationException(
                    $"Invalid payload offset: {payloadOffset}\n" +
                    $"This suggests the payload size in the footer is incorrect.");
            }

            // ============================================================
            // STEP 7: EXTRACT PAYLOAD
            // ============================================================
            LogDebug("Step 7: Extracting payload...");

            byte[] payload = new byte[payloadSize];
            using (var fs = File.OpenRead(exePath))
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

                    totalRead += bytesRead;

                    if (totalRead % (1024 * 1024) == 0) // Log every MB
                    {
                        LogDebug($"  Read {FormatBytes(totalRead)}/{FormatBytes(payloadSize)}...");
                    }
                }

                LogDebug($"✅ Payload extracted: {FormatBytes(totalRead)}");
            }

            // ============================================================
            // STEP 8: VERIFY ZIP HEADER
            // ============================================================
            LogDebug("Step 8: Verifying ZIP header...");

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

                            var destPath = Path.Combine(tempPath, entry.FullName);

                            // Create directory if needed
                            var destDir = Path.GetDirectoryName(destPath);
                            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                            {
                                Directory.CreateDirectory(destDir);
                            }

                            LogDebug($"  [{extracted + 1}/{archive.Entries.Count}] Extracting: {entry.FullName} ({FormatBytes(entry.Length)})");

                            entry.ExtractToFile(destPath, overwrite: true);
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
