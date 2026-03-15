// PackItPro/Services/ResourceInjector.cs - v2.3
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace PackItPro.Services
{
    /// <summary>
    /// Injects a ZIP payload into the stub installer executable.
    ///
    /// Final binary layout (v2.3 with payload hash):
    ///   [ STUB EXE ][ ZIP payload ][ payload size: Int64 LE ][ payload hash: 32 bytes ][ "PACKIT_END": 10 ASCII bytes ]
    ///                                                         |___________________ FOOTER: 50 bytes __________________|
    /// 
    /// Footer format guarantees byte-level integrity independent of ZIP internals.
    /// The hash is computed over the exact ZIP bytes without re-serialization.
    /// </summary>
    public static class ResourceInjector
    {
        public const string PAYLOAD_MARKER = "PACKIT_END";
        private const int MARKER_LENGTH = 10;
        private const int SIZE_LENGTH = sizeof(long);
        private const int HASH_LENGTH = 32; // SHA256 output is 32 bytes
        public const int FOOTER_LENGTH = SIZE_LENGTH + HASH_LENGTH + MARKER_LENGTH; // 50 bytes

        private const int STREAM_BUFFER = 1024 * 1024; // 1 MB copy buffer
        private const long MIN_STUB_SIZE = 10L * 1024 * 1024; // 10 MB

        /// <summary>
        /// Injects the payload ZIP into the stub and writes the final EXE to outputPath.
        /// Streams all data — safe for 1 GB+ payloads.
        /// Computes SHA256 hash of payload on-the-fly during injection.
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

                // 2. Stream payload ZIP and compute hash simultaneously
                ct.ThrowIfCancellationRequested();
                byte[] payloadHash;
                using (var payload = File.OpenRead(payloadZipPath))
                    payloadHash = CopyAndHashPayload(payload, output, payloadSize, ct);

                // 3. Write payload size (8 bytes, little-endian Int64)
                output.Write(BitConverter.GetBytes(payloadSize), 0, SIZE_LENGTH);

                // 4. Write payload hash (32 bytes, raw SHA256 digest)
                if (payloadHash.Length != HASH_LENGTH)
                    throw new InvalidOperationException(
                        $"Payload hash is {payloadHash.Length} bytes — expected {HASH_LENGTH}. " +
                        "SHA256 output must be exactly 32 bytes.");
                output.Write(payloadHash, 0, HASH_LENGTH);

                // 5. Write marker ("PACKIT_END", exactly 10 ASCII bytes)
                var markerBytes = Encoding.ASCII.GetBytes(PAYLOAD_MARKER);
                if (markerBytes.Length != MARKER_LENGTH)
                    throw new InvalidOperationException(
                        $"Marker is {markerBytes.Length} bytes — expected {MARKER_LENGTH}. " +
                        "Do not modify PAYLOAD_MARKER without updating MARKER_LENGTH.");

                output.Write(markerBytes, 0, MARKER_LENGTH);

                // Flush to the OS buffer. The FileStream.Dispose() that follows will
                // ensure data is written before we do the size check.
                // flushToDisk:true (FlushFileBuffers) is NOT used here — on VMs backed
                // by a VHD/VMDK it forces a full write-through to the physical disk and
                // can make a 500 MB package take 10-20x longer than necessary.
                output.Flush(flushToDisk: false);
            }

            long actualSize = new FileInfo(outputPath).Length;
            if (actualSize != expectedSize)
                throw new InvalidOperationException(
                    $"Output size mismatch — expected {FormatBytes(expectedSize)}, got {FormatBytes(actualSize)}.");
        }

        /// <summary>
        /// Reads the footer of a packaged EXE and confirms it is valid.
        /// Returns the footer structure (size, hash, marker) for verification.
        /// Does NOT verify the payload hash against actual ZIP bytes — that's done in StubInstaller.
        /// </summary>
        public static (long payloadSize, byte[] payloadHash, string marker) ReadPackageFooter(string packagedExePath)
        {
            if (!File.Exists(packagedExePath))
                throw new FileNotFoundException("Packaged EXE not found.", packagedExePath);

            using var fs = File.OpenRead(packagedExePath);
            if (fs.Length < FOOTER_LENGTH)
                throw new InvalidOperationException(
                    $"File is too small ({fs.Length} bytes) to contain a valid footer ({FOOTER_LENGTH} bytes).");

            fs.Seek(-FOOTER_LENGTH, SeekOrigin.End);
            var footer = new byte[FOOTER_LENGTH];
            int read = fs.Read(footer, 0, FOOTER_LENGTH);
            if (read != FOOTER_LENGTH)
                throw new InvalidOperationException($"Failed to read footer: expected {FOOTER_LENGTH} bytes, got {read}.");

            long payloadSize = BitConverter.ToInt64(footer, 0);
            byte[] payloadHash = new byte[HASH_LENGTH];
            Array.Copy(footer, SIZE_LENGTH, payloadHash, 0, HASH_LENGTH);
            string marker = Encoding.ASCII.GetString(footer, SIZE_LENGTH + HASH_LENGTH, MARKER_LENGTH);

            return (payloadSize, payloadHash, marker);
        }

        /// <summary>
        /// Reads the last 18 bytes of a packaged EXE and confirms the footer is valid (legacy v2.2 format).
        /// Does NOT extract or verify payload contents.
        /// </summary>
        public static bool VerifyPackagedExe(string packagedExePath)
        {
            try
            {
                if (!File.Exists(packagedExePath)) return false;

                using var fs = File.OpenRead(packagedExePath);
                // Accept both old (18 bytes) and new (50 bytes) footer formats
                if (fs.Length < MARKER_LENGTH + SIZE_LENGTH) return false;

                fs.Seek(-MARKER_LENGTH, SeekOrigin.End);
                var markerBytes = new byte[MARKER_LENGTH];
                if (fs.Read(markerBytes, 0, MARKER_LENGTH) != MARKER_LENGTH) return false;

                string marker = Encoding.ASCII.GetString(markerBytes);
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

        /// <summary>
        /// Copies payload from source to dest while computing SHA256 hash.
        /// Returns the computed hash digest.
        /// </summary>
        private static byte[] CopyAndHashPayload(Stream source, Stream dest, long expectedSize, CancellationToken ct)
        {
            using var sha = SHA256.Create();
            var buffer = new byte[STREAM_BUFFER];
            long totalCopied = 0;
            int bytesRead;

            while ((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                ct.ThrowIfCancellationRequested();

                // Hash the bytes
                sha.TransformBlock(buffer, 0, bytesRead, null, 0);

                // Copy to output
                dest.Write(buffer, 0, bytesRead);

                totalCopied += bytesRead;
            }

            if (totalCopied != expectedSize)
                throw new InvalidOperationException(
                    $"Payload size mismatch during copy: expected {expectedSize} bytes, copied {totalCopied} bytes.");

            // Finalize hash
            sha.TransformFinalBlock(buffer, 0, 0);

            return sha.Hash ?? throw new InvalidOperationException("SHA256 hash computation failed.");
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