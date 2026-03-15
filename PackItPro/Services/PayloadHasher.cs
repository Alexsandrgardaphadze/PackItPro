// PackItPro/Services/PayloadHasher.cs
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    /// <summary>
    /// Computes SHA-256 hash of a file stream using configurable buffer sizes.
    /// Supports cancellation tokens for interruptible long-running hashes.
    /// </summary>
    public static class PayloadHasher
    {
        private const int DEFAULT_BUFFER_SIZE = 1024 * 1024; // 1 MB buffer

        /// <summary>
        /// Computes the SHA-256 hash of a file stream asynchronously.
        /// </summary>
        public static async Task<byte[]> ComputePayloadHashAsync(
            Stream stream,
            long bytesToHash = -1,
            int bufferSize = DEFAULT_BUFFER_SIZE,
            IProgress<(long processed, long total)>? progress = null,
            CancellationToken ct = default)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (!stream.CanRead)
                throw new InvalidOperationException("Stream must be readable.");

            if (bufferSize <= 0)
                throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            // Determine total bytes to hash
            long totalBytes = bytesToHash >= 0 ? bytesToHash : (stream.CanSeek ? stream.Length - stream.Position : -1);

            using var sha = SHA256.Create();
            var buffer = new byte[bufferSize];
            long processedBytes = 0;

            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, ct)) > 0)
            {
                ct.ThrowIfCancellationRequested();

                sha.TransformBlock(buffer, 0, bytesRead, null, 0);
                processedBytes += bytesRead;

                if (totalBytes >= 0)
                {
                    progress?.Report((Math.Min(processedBytes, totalBytes), totalBytes));
                }
            }

            sha.TransformFinalBlock(buffer, 0, 0);
            progress?.Report((processedBytes, totalBytes >= 0 ? totalBytes : processedBytes));

            return sha.Hash ?? throw new InvalidOperationException("SHA256 hash computation failed.");
        }

        /// <summary>
        /// Computes the SHA-256 hash of a file synchronously using streaming.
        /// </summary>
        public static byte[] ComputePayloadHash(
            string filePath,
            long bytesToHash = -1,
            int bufferSize = DEFAULT_BUFFER_SIZE,
            IProgress<(long processed, long total)>? progress = null)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found.", filePath);

            using var fs = File.OpenRead(filePath);
            return ComputePayloadHashSync(fs, bytesToHash, bufferSize, progress);
        }

        /// <summary>
        /// Computes SHA-256 hash of a file stream synchronously.
        /// </summary>
        private static byte[] ComputePayloadHashSync(
            Stream stream,
            long bytesToHash = -1,
            int bufferSize = DEFAULT_BUFFER_SIZE,
            IProgress<(long processed, long total)>? progress = null)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (!stream.CanRead)
                throw new InvalidOperationException("Stream must be readable.");

            long totalBytes = bytesToHash >= 0 ? bytesToHash : (stream.CanSeek ? stream.Length - stream.Position : -1);

            using var sha = SHA256.Create();
            var buffer = new byte[bufferSize];
            long processedBytes = 0;

            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha.TransformBlock(buffer, 0, bytesRead, null, 0);
                processedBytes += bytesRead;

                if (totalBytes >= 0 && bytesToHash >= 0)
                {
                    progress?.Report((Math.Min(processedBytes, totalBytes), totalBytes));
                }
            }

            sha.TransformFinalBlock(buffer, 0, 0);
            if (totalBytes >= 0)
            {
                progress?.Report((processedBytes, totalBytes));
            }

            return sha.Hash ?? throw new InvalidOperationException("SHA256 hash computation failed.");
        }
    }
}
