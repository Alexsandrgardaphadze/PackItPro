// PackItPro/Services/ResourceInjector.cs - v2.2
using System;
using System.IO;
using System.Text;
using System.Threading;

namespace PackItPro.Services
{
    /// <summary>
    /// Injects a ZIP payload into the stub installer executable.
    ///
    /// Final binary layout:
    ///   [ STUB EXE ][ ZIP payload ][ payload size: Int64 LE ][ "PACKIT_END": 10 ASCII bytes ]
    ///                                                         |__________ FOOTER: 18 bytes __|
    /// </summary>
    public static class ResourceInjector
    {
        public const string PAYLOAD_MARKER = "PACKIT_END";
        private const int MARKER_LENGTH = 10;
        private const int SIZE_LENGTH = sizeof(long);
        public const int FOOTER_LENGTH = SIZE_LENGTH + MARKER_LENGTH; // 18 bytes

        private const int STREAM_BUFFER = 1024 * 1024; // 1 MB copy buffer
        private const long MIN_STUB_SIZE = 10L * 1024 * 1024; // 10 MB

        /// <summary>
        /// Injects the payload ZIP into the stub and writes the final EXE to outputPath.
        /// Streams all data — safe for 1 GB+ payloads.
        /// Supports cancellation for large files.
        /// </summary>
        public static void InjectPayload(
            string stubPath,
            string payloadZipPath,
            string outputPath,
            CancellationToken ct = default)
        {
            if (!File.Exists(stubPath))
                throw new FileNotFoundException("Stub executable not found.", stubPath);

            if (!File.Exists(payloadZipPath))
                throw new FileNotFoundException("Payload ZIP not found.", payloadZipPath);

            var stubInfo = new FileInfo(stubPath);
            var payloadInfo = new FileInfo(payloadZipPath);

            if (stubInfo.Length < MIN_STUB_SIZE)
                throw new InvalidOperationException(
                    $"Stub is too small ({FormatBytes(stubInfo.Length)}) — this is a framework-dependent build.\n" +
                    "Publish StubInstaller as self-contained (dotnet publish --self-contained) and copy it to PackItPro/Resources.");

            if (payloadInfo.Length == 0)
                throw new InvalidOperationException("Payload ZIP is empty.");

            long stubSize = stubInfo.Length;
            long payloadSize = payloadInfo.Length;
            long expectedSize = stubSize + payloadSize + FOOTER_LENGTH;

            using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, STREAM_BUFFER))
            {
                // 1. Stream stub
                ct.ThrowIfCancellationRequested();
                using (var stub = File.OpenRead(stubPath))
                    CopyWithCancellation(stub, output, ct);

                // 2. Stream payload ZIP
                ct.ThrowIfCancellationRequested();
                using (var payload = File.OpenRead(payloadZipPath))
                    CopyWithCancellation(payload, output, ct);

                // 3. Write payload size (8 bytes, little-endian Int64)
                output.Write(BitConverter.GetBytes(payloadSize), 0, SIZE_LENGTH);

                // 4. Write marker ("PACKIT_END", exactly 10 ASCII bytes)
                var markerBytes = Encoding.ASCII.GetBytes(PAYLOAD_MARKER);
                if (markerBytes.Length != MARKER_LENGTH)
                    throw new InvalidOperationException(
                        $"Marker is {markerBytes.Length} bytes — expected {MARKER_LENGTH}. " +
                        "Do not modify PAYLOAD_MARKER without updating MARKER_LENGTH.");

                output.Write(markerBytes, 0, MARKER_LENGTH);

                // FIX: Flush(true) — forces OS write-through to disk before we
                // read the file back for verification. Without this, the file system
                // cache may serve stale data and verification will fail spuriously.
                output.Flush(flushToDisk: true);
            }

            long actualSize = new FileInfo(outputPath).Length;
            if (actualSize != expectedSize)
                throw new InvalidOperationException(
                    $"Output size mismatch — expected {FormatBytes(expectedSize)}, got {FormatBytes(actualSize)}.");
        }

        /// <summary>
        /// Reads the last 18 bytes of a packaged EXE and confirms the footer is valid.
        /// Does NOT extract or verify payload contents.
        /// </summary>
        public static bool VerifyPackagedExe(string packagedExePath)
        {
            try
            {
                if (!File.Exists(packagedExePath)) return false;

                using var fs = File.OpenRead(packagedExePath);
                if (fs.Length < FOOTER_LENGTH) return false;

                fs.Seek(-FOOTER_LENGTH, SeekOrigin.End);
                var footer = new byte[FOOTER_LENGTH];
                if (fs.Read(footer, 0, FOOTER_LENGTH) != FOOTER_LENGTH) return false;

                long payloadSize = BitConverter.ToInt64(footer, 0);
                if (payloadSize <= 0 || payloadSize > fs.Length - FOOTER_LENGTH) return false;

                string marker = Encoding.ASCII.GetString(footer, SIZE_LENGTH, MARKER_LENGTH);
                return marker == PAYLOAD_MARKER;
            }
            catch
            {
                return false;
            }
        }

        // ──────────────────────────────────────────────────────────────
        // Helpers
        // ──────────────────────────────────────────────────────────────

        private static void CopyWithCancellation(Stream source, Stream dest, CancellationToken ct)
        {
            var buffer = new byte[STREAM_BUFFER];
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                dest.Write(buffer, 0, read);
            }
        }

        private static string FormatBytes(long bytes)
        {
            string[] s = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes; int o = 0;
            while (v >= 1024 && o < s.Length - 1) { o++; v /= 1024; }
            return $"{v:0.##} {s[o]}";
        }
    }
}