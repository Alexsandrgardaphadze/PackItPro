// StubInstaller/PayloadExtractor.cs
using StubInstaller.Infrastrucure;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace StubInstaller.Core
{
    public static class PayloadExtractor
    {
        private const string PayloadMarker = "PACKIT_END";
        private const int MarkerLength = 10;
        private const int SizeLength = sizeof(long);
        private const int HashLength = 32;
        private const int FooterLengthV23 = SizeLength + HashLength + MarkerLength; // 50
        private const int FooterLengthV22 = SizeLength + MarkerLength;              // 18

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Extracts the ZIP payload appended to this executable directly to a
        /// temp directory without loading it into RAM.
        ///
        /// Returns the path of the temp directory containing the extracted files.
        /// Throws <see cref="InvalidOperationException"/> on any validation failure.
        /// </summary>
        public static string ExtractAndDecompressPayload()
        {
            string exePath = ResolveExePath();
            Log($"Executable: {exePath}");
            Log($"File size:  {Util.FormatBytes(new FileInfo(exePath).Length)}");

            // Read footer to get payload offset, size, and optional hash
            var (payloadOffset, payloadSize, expectedHash, footerVersion) =
                ReadFooter(exePath);

            Log($"Footer:     v{footerVersion} ({(footerVersion == 23 ? FooterLengthV23 : FooterLengthV22)} bytes)");
            Log($"Payload:    {Util.FormatBytes(payloadSize)} at offset {payloadOffset}");

            // Create temp directory
            string tempPath = Path.Combine(Path.GetTempPath(), "PackItPro", Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempPath);
            Log($"Temp dir:   {tempPath}");

            try
            {
                // Stream directly from the exe file — no payload byte[] allocation
                using var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, bufferSize: 81920);

                fs.Seek(payloadOffset, SeekOrigin.Begin);

                // ── STEP A: Verify hash with a sequential read BEFORE extraction ────────
                // ResourceInjector hashes the ZIP bytes sequentially (offset 0 → end).
                // ZipArchive does NOT read sequentially — it seeks to the Central Directory
                // at the end of the ZIP first, then jumps to individual entries.
                // Hashing inside a HashingReadStream during extraction therefore produces
                // a different byte order than ResourceInjector, causing guaranteed mismatch.
                // Fix: do one sequential read pass over the raw payload bytes first,
                // then seek back to offset 0 and let ZipArchive read however it wants.
                if (expectedHash != null)
                {
                    Log("Verifying payload hash (sequential pass)...");
                    fs.Seek(payloadOffset, SeekOrigin.Begin);

                    using var sha = SHA256.Create();
                    var hashBuffer = new byte[81920];
                    long remaining = payloadSize;
                    int bytesRead;

                    while (remaining > 0 &&
                           (bytesRead = fs.Read(hashBuffer, 0, (int)Math.Min(hashBuffer.Length, remaining))) > 0)
                    {
                        sha.TransformBlock(hashBuffer, 0, bytesRead, null, 0);
                        remaining -= bytesRead;
                    }
                    sha.TransformFinalBlock(hashBuffer, 0, 0);
                    byte[] actualHash = sha.Hash!;

                    if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
                    {
                        throw new InvalidOperationException(
                            "PAYLOAD INTEGRITY CHECK FAILED!\n\n" +
                            "The ZIP payload has been modified or corrupted.\n\n" +
                            $"Expected: {Convert.ToBase64String(expectedHash)}\n" +
                            $"Actual:   {Convert.ToBase64String(actualHash)}\n\n" +
                            "Possible causes: file tampered, disk corruption, antivirus modification.\n" +
                            "Installation cannot proceed.");
                    }
                    Log("Payload hash verified.");
                }

                // ── STEP B: Extract — seek back to payload start ──────────────────────
                // ZipArchive is free to seek in any order now that hash is confirmed.
                fs.Seek(payloadOffset, SeekOrigin.Begin);
                using var payloadStream = new SubStream(fs, payloadSize);

                string safeTempDir = Path.GetFullPath(tempPath + Path.DirectorySeparatorChar);
                int extracted = 0;

                using (var archive = new ZipArchive(payloadStream, ZipArchiveMode.Read, leaveOpen: true))
                {
                    Log($"ZIP entries: {archive.Entries.Count}");
                    foreach (var entry in archive.Entries)
                    {
                        if (string.IsNullOrEmpty(entry.Name)) continue; // directory entry

                        // Zip Slip guard
                        string destPath = Path.GetFullPath(Path.Combine(tempPath, entry.FullName));
                        if (!destPath.StartsWith(safeTempDir, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException(
                                $"SECURITY: ZIP entry '{entry.FullName}' resolves outside extraction root. " +
                                "This archive may be malicious. Extraction aborted.");

                        var destDir = Path.GetDirectoryName(destPath);
                        if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                            Directory.CreateDirectory(destDir);

                        entry.ExtractToFile(destPath, overwrite: true);
                        extracted++;
                        Log($"  [{extracted}/{archive.Entries.Count}] {entry.FullName} ({Util.FormatBytes(entry.Length)})");
                    }
                }
                Log($"Extracted {extracted} file(s) to: {tempPath}");
                return tempPath;
            }
            catch
            {
                // Clean up on failure — don't leave partial extractions
                try { if (Directory.Exists(tempPath)) Directory.Delete(tempPath, true); } catch { }
                throw;
            }
        }

        /// <summary>
        /// Backward-compatible shim for callers that used the old two-step API.
        /// Prefer <see cref="ExtractAndDecompressPayload"/> for new code.
        /// </summary>
        [Obsolete("Use ExtractAndDecompressPayload() — streams directly without RAM allocation.")]
        public static byte[] ExtractPayloadFromEndOfFile()
        {
            // For compatibility: read the raw payload bytes.
            // This still allocates — migrate callers to ExtractAndDecompressPayload.
            string exePath = ResolveExePath();
            var (payloadOffset, payloadSize, _, _) = ReadFooter(exePath);

            var payload = new byte[payloadSize];
            using var fs = File.OpenRead(exePath);
            fs.Seek(payloadOffset, SeekOrigin.Begin);
            int totalRead = 0;
            while (totalRead < payloadSize)
            {
                int read = fs.Read(payload, totalRead, (int)(payloadSize - totalRead));
                if (read == 0) throw new InvalidOperationException("Unexpected EOF reading payload.");
                totalRead += read;
            }
            return payload;
        }

        /// <summary>
        /// Backward-compatible shim — wraps ExtractAndDecompressPayload.
        /// <paramref name="payloadData"/> is ignored; extraction reads from the exe.
        /// </summary>
        [Obsolete("Use ExtractAndDecompressPayload() instead.")]
        public static string ExtractPayloadToTempDirectory(byte[] payloadData)
            => ExtractAndDecompressPayload();

        // ── Footer parsing ────────────────────────────────────────────────────

        private static (long offset, long size, byte[]? hash, int version)
            ReadFooter(string exePath)
        {
            var fi = new FileInfo(exePath);

            if (fi.Length < FooterLengthV22)
                throw new InvalidOperationException(
                    $"File too small ({fi.Length} bytes) to contain a payload footer. " +
                    "This may not be a packaged installer, or it may be the raw stub.");

            using var fs = File.OpenRead(exePath);

            // Try v2.3 first (50-byte footer)
            if (fi.Length >= FooterLengthV23)
            {
                fs.Seek(-FooterLengthV23, SeekOrigin.End);
                var footer = ReadExact(fs, FooterLengthV23);
                string marker = Encoding.ASCII.GetString(footer, SizeLength + HashLength, MarkerLength);
                if (marker == PayloadMarker)
                {
                    long size = BitConverter.ToInt64(footer, 0);
                    var hash = new byte[HashLength];
                    Array.Copy(footer, SizeLength, hash, 0, HashLength);
                    ValidatePayloadSize(size, fi.Length, FooterLengthV23);
                    long offset = fi.Length - FooterLengthV23 - size;
                    return (offset, size, hash, 23);
                }
            }

            // Fall back to v2.2 (18-byte footer)
            fs.Seek(-FooterLengthV22, SeekOrigin.End);
            var footer22 = ReadExact(fs, FooterLengthV22);
            string marker22 = Encoding.ASCII.GetString(footer22, SizeLength, MarkerLength);
            if (marker22 != PayloadMarker)
                throw new InvalidOperationException(
                    $"Invalid payload marker. Expected '{PayloadMarker}'. " +
                    "This file is not a packaged installer, or it is corrupted.");

            long size22 = BitConverter.ToInt64(footer22, 0);
            ValidatePayloadSize(size22, fi.Length, FooterLengthV22);
            long offset22 = fi.Length - FooterLengthV22 - size22;
            Log("Footer version: v2.2 (no hash — integrity check skipped)");
            return (offset22, size22, null, 22);
        }

        private static void ValidatePayloadSize(long size, long fileSize, int footerSize)
        {
            if (size <= 0)
                throw new InvalidOperationException(
                    $"Invalid payload size: {size}. " +
                    "You may be running the raw stub instead of a packaged installer.");
            if (size > fileSize - footerSize)
                throw new InvalidOperationException(
                    $"Payload size ({Util.FormatBytes(size)}) exceeds available space in file.");
        }

        private static byte[] ReadExact(Stream stream, int count)
        {
            var buf = new byte[count];
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = stream.Read(buf, totalRead, count - totalRead);
                if (read == 0) throw new InvalidOperationException(
                    $"Unexpected EOF reading footer (read {totalRead}/{count} bytes).");
                totalRead += read;
            }
            return buf;
        }

        // ── Exe path resolution ───────────────────────────────────────────────

        private static string ResolveExePath()
        {
            // Environment.ProcessPath is the correct API for .NET 6+ single-file apps
            string? path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
                return path;

            // Fallback: MainModule (may be null in some sandbox environments)
            try
            {
                path = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(path) && File.Exists(path)) return path;
            }
            catch { }

            throw new InvalidOperationException(
                "Cannot determine the executable path.\n" +
                $"ProcessPath: {Environment.ProcessPath ?? "null"}\n" +
                $"BaseDirectory: {AppContext.BaseDirectory}");
        }

        // ── Logging ───────────────────────────────────────────────────────────

        private static void Log(string message) => StubLogger.Log($"[PayloadExtractor] {message}");
    }

    // ── Helper streams ────────────────────────────────────────────────────────

    /// <summary>
    /// Limits reads to a fixed-length window of an underlying stream.
    /// Used to prevent ZipArchive from reading past the payload into the footer.
    /// </summary>
    internal sealed class SubStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _startOffset;  // absolute position in _inner at construction
        private readonly long _length;       // fixed total length of this window
        private long _position;     // current logical position within the window

        internal SubStream(Stream inner, long length)
        {
            _inner = inner;
            _startOffset = inner.Position;     // remember where the payload begins
            _length = length;
            _position = 0;
        }

        public override bool CanRead => true;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position
        {
            get => _position;
            set => Seek(value, SeekOrigin.Begin);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            long remaining = _length - _position;
            if (remaining <= 0) return 0;
            int toRead = (int)Math.Min(count, remaining);
            int read = _inner.Read(buffer, offset, toRead);
            _position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!_inner.CanSeek) throw new NotSupportedException();

            // Resolve the new logical position within our window
            long newLogical = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => _position + offset,
                SeekOrigin.End => _length + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };

            newLogical = Math.Clamp(newLogical, 0, _length);

            // Translate to absolute position in the underlying stream
            _inner.Seek(_startOffset + newLogical, SeekOrigin.Begin);
            _position = newLogical;
            return _position;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
