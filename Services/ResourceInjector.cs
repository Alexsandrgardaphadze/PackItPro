// PackItPro/Services/ResourceInjector.cs - FINAL COMPLETE VERSION
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace PackItPro.Services
{
    /// <summary>
    /// Injects a ZIP payload into the stub installer executable
    /// Format: [STUB][PAYLOAD][SIZE:8bytes][MARKER:"PACKIT_END"]
    /// </summary>
    public static class ResourceInjector
    {
        private const string PAYLOAD_MARKER = "PACKIT_END";
        private const int MARKER_LENGTH = 10;
        private const int SIZE_LENGTH = sizeof(long);
        private const int FOOTER_LENGTH = SIZE_LENGTH + MARKER_LENGTH; // 18 bytes total

        /// <summary>
        /// Injects the payload ZIP into the stub installer
        /// </summary>
        /// <param name="stubPath">Path to StubInstaller.exe</param>
        /// <param name="payloadZipPath">Path to the ZIP file containing all installers</param>
        /// <param name="outputPath">Path where the final EXE will be created</param>
        public static void InjectPayload(string stubPath, string payloadZipPath, string outputPath)
        {
            LogInfo("========== PAYLOAD INJECTION START ==========");

            // Validation
            if (!File.Exists(stubPath))
                throw new FileNotFoundException("Stub executable not found", stubPath);

            if (!File.Exists(payloadZipPath))
                throw new FileNotFoundException("Payload ZIP not found", payloadZipPath);

            // Validate stub is self-contained
            var stubInfo = new FileInfo(stubPath);
            if (stubInfo.Length < 10 * 1024 * 1024) // < 10 MB
            {
                throw new InvalidOperationException(
                    $"Stub is too small ({FormatBytes(stubInfo.Length)}).\n" +
                    $"This indicates a framework-dependent build.\n" +
                    $"Expected: 25-100 MB (self-contained)");
            }

            // Read payload
            byte[] payloadBytes = File.ReadAllBytes(payloadZipPath);

            if (payloadBytes.Length == 0)
                throw new InvalidOperationException("Payload ZIP is empty!");

            long stubSize = stubInfo.Length;
            long payloadSize = payloadBytes.Length;

            LogInfo($"Stub size: {FormatBytes(stubSize)}");
            LogInfo($"Payload size: {FormatBytes(payloadSize)}");

            // Create output file
            using (FileStream outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
            {
                // 1️⃣ Copy stub executable
                using (FileStream stubStream = File.OpenRead(stubPath))
                {
                    stubStream.CopyTo(outputStream);
                }
                LogInfo($"✅ Stub copied ({FormatBytes(stubSize)})");

                // 2️⃣ Write payload ZIP
                outputStream.Write(payloadBytes, 0, payloadBytes.Length);
                LogInfo($"✅ Payload written ({FormatBytes(payloadSize)})");

                // 3️⃣ Write payload size (8 bytes, little-endian Int64)
                byte[] sizeBytes = BitConverter.GetBytes((long)payloadSize);
                outputStream.Write(sizeBytes, 0, SIZE_LENGTH);
                LogInfo($"✅ Size footer written (8 bytes)");
                LogInfo($"   Size bytes: {BitConverter.ToString(sizeBytes)}");

                // 4️⃣ Write marker ("PACKIT_END" in ASCII)
                byte[] markerBytes = Encoding.ASCII.GetBytes(PAYLOAD_MARKER);
                if (markerBytes.Length != MARKER_LENGTH)
                    throw new InvalidOperationException($"Marker must be exactly {MARKER_LENGTH} bytes!");

                outputStream.Write(markerBytes, 0, MARKER_LENGTH);
                LogInfo($"✅ Marker written ('{PAYLOAD_MARKER}' 10 bytes)");

                outputStream.Flush();
            }

            // Verification
            long finalSize = new FileInfo(outputPath).Length;
            long expectedSize = stubSize + payloadSize + FOOTER_LENGTH;

            LogInfo($"Final EXE size: {FormatBytes(finalSize)}");
            LogInfo($"Expected size: {FormatBytes(expectedSize)}");

            if (finalSize != expectedSize)
            {
                throw new InvalidOperationException(
                    $"SIZE MISMATCH! Final size is {FormatBytes(finalSize)}, " +
                    $"but expected {FormatBytes(expectedSize)}. " +
                    $"Payload may not have been written correctly!");
            }

            if (finalSize <= stubSize + 1024) // Sanity check
            {
                throw new InvalidOperationException(
                    $"CRITICAL ERROR: Final EXE size ({FormatBytes(finalSize)}) is too small! " +
                    $"Payload was NOT appended correctly!");
            }

            LogInfo("========== PAYLOAD INJECTION SUCCESS ==========");
        }

        /// <summary>
        /// Verifies that a packaged EXE has the correct structure
        /// </summary>
        public static bool VerifyPackagedExe(string packagedExePath)
        {
            try
            {
                if (!File.Exists(packagedExePath))
                    return false;

                using var fs = File.OpenRead(packagedExePath);

                if (fs.Length < FOOTER_LENGTH)
                    return false;

                // Read footer
                fs.Seek(-FOOTER_LENGTH, SeekOrigin.End);
                byte[] footer = new byte[FOOTER_LENGTH];
                fs.Read(footer, 0, FOOTER_LENGTH);

                // Extract marker
                byte[] markerBytes = new byte[MARKER_LENGTH];
                Array.Copy(footer, SIZE_LENGTH, markerBytes, 0, MARKER_LENGTH);
                string marker = Encoding.ASCII.GetString(markerBytes);

                if (marker != PAYLOAD_MARKER)
                {
                    LogError($"Invalid marker: '{marker}' (expected '{PAYLOAD_MARKER}')");
                    return false;
                }

                // Extract size
                byte[] sizeBytes = new byte[SIZE_LENGTH];
                Array.Copy(footer, 0, sizeBytes, 0, SIZE_LENGTH);
                long payloadSize = BitConverter.ToInt64(sizeBytes, 0);

                if (payloadSize <= 0 || payloadSize > fs.Length - FOOTER_LENGTH)
                {
                    LogError($"Invalid payload size: {payloadSize}");
                    return false;
                }

                LogInfo($"✅ Package verified: Payload size = {FormatBytes(payloadSize)}");
                return true;
            }
            catch (Exception ex)
            {
                LogError($"Verification failed: {ex.Message}");
                return false;
            }
        }

        private static string FormatBytes(long bytes)
        {
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

        private static void LogInfo(string message)
        {
            var msg = $"[ResourceInjector] {message}";
            Debug.WriteLine(msg);
            Console.WriteLine(msg);
        }

        private static void LogError(string message)
        {
            var msg = $"[ResourceInjector] ERROR: {message}";
            Debug.WriteLine(msg);
            Console.WriteLine(msg);
        }
    }
}