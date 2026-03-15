// StubInstaller/PayloadExtractor.cs - v3.0
// Changes vs v2.0:
//   [1] Streaming extraction — payload is never loaded into RAM as byte[].
//       v2.0 allocated new byte[payloadSize] (up to 2 GB on the LOH) then wrapped
//       it in a MemoryStream for ZIP extraction. On machines with 4 GB RAM and a
//       large package this caused an OutOfMemoryException before a single file was
//       extracted. v3.0 seeks the FileStream to the payload offset and passes it
//       directly to ZipArchive — zero payload allocation.
//   [2] LogDebug now delegates to StubLogger.Log instead of writing to a separate
//       PackItPro_Extraction.log in %TEMP%. All output goes to the single install
//       log so diagnosis is not split across two files.
//   [3] Console.WriteLine removed — produces no output in the WinForms stub and
//       cluttered console mode with duplicate lines already in StubLogger.
//   [4] ExtractPayloadToTempDirectory(byte[]) kept as an internal compatibility
//       shim (calls the streaming overload) but marked Obsolete.
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

                // Wrap the payload region in a length-limited stream so ZipArchive
                // cannot read past the end of the payload into the footer
                using var payloadStream = new SubStream(fs, payloadSize);

                // Verify hash while streaming if v2.3 footer
                Stream hashingStream = payloadStream;
                SHA256? sha = null;
                if (expectedHash != null)
                {
                    sha = SHA256.Create();
                    hashingStream = new HashingReadStream(payloadStream, sha);
                }

                // Validate ZIP header before opening the archive
                var headerBuf = new byte[4];
                int headerRead = hashingStream.Read(headerBuf, 0, 4);
                if (headerRead == 4 &&
                    !(headerBuf[0] == 0x50 && headerBuf[1] == 0x4B &&
                      headerBuf[2] == 0x03 && headerBuf[3] == 0x04))
                {
                    Log($"WARNING: Unexpected ZIP header: {headerBuf[0]:X2} {headerBuf[1]:X2} {headerBuf[2]:X2} {headerBuf[3]:X2}");
                }

                // Rewind so ZipArchive sees the complete ZIP including its header
                hashingStream.Seek(0, SeekOrigin.Begin);

                string safeTempDir = Path.GetFullPath(tempPath + Path.DirectorySeparatorChar);
                int extracted = 0;

                using (var archive = new ZipArchive(hashingStream, ZipArchiveMode.Read, leaveOpen: true))
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

                // Verify hash after extraction if v2.3
                if (sha != null && expectedHash != null)
                {
                    sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
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
                    Log("Payload integrity verified.");
                }

                sha?.Dispose();
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
    /// Limits reads to <see cref="_remaining"/> bytes of an underlying stream.
    /// Used to prevent ZipArchive from reading past the payload into the footer.
    /// </summary>
    internal sealed class SubStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        internal SubStream(Stream inner, long length)
        {
            _inner = inner;
            _remaining = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _remaining;
        public override long Position
        {
            get => _inner.CanSeek ? _inner.Position : 0;
            set => Seek(value, SeekOrigin.Begin);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0) return 0;
            int toRead = (int)Math.Min(count, _remaining);
            int read = _inner.Read(buffer, offset, toRead);
            _remaining -= read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!_inner.CanSeek) throw new NotSupportedException();
            // Translate to absolute position in the inner stream
            long newPos = origin switch
            {
                SeekOrigin.Begin => _inner.Position - (Length - _remaining) + offset,
                SeekOrigin.Current => _inner.Position + offset,
                SeekOrigin.End => _inner.Position + (_remaining) + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            _inner.Seek(newPos, SeekOrigin.Begin);
            return newPos;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// Wraps a readable stream and feeds all bytes through a <see cref="SHA256"/>
    /// transform as they are read, allowing hash-while-extract without buffering.
    /// </summary>
    internal sealed class HashingReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly SHA256 _sha;
        private readonly long _length;
        private long _position;

        internal HashingReadStream(Stream inner, SHA256 sha)
        {
            _inner = inner;
            _sha = sha;
            _length = inner.CanSeek ? inner.Length : -1;
        }

        public override bool CanRead => true;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _length >= 0 ? _length : throw new NotSupportedException();
        public override long Position
        {
            get => _position;
            set => Seek(value, SeekOrigin.Begin);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = _inner.Read(buffer, offset, count);
            if (read > 0)
            {
                _sha.TransformBlock(buffer, offset, read, null, 0);
                _position += read;
            }
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (!_inner.CanSeek) throw new NotSupportedException();
            long newPos = _inner.Seek(offset, origin);
            _position = newPos;
            return newPos;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}