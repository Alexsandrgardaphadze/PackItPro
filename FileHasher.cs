// FileHasher.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PackItPro
{
    /// <summary>
    /// Provides utility methods for calculating file and directory hashes.
    /// </summary>
    public static class FileHasher
    {
        /// <summary>
        /// Computes the SHA256 hash of a single file as a byte array.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <returns>The SHA256 hash as a byte array.</returns>
        public static byte[] ComputeFileHash(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return sha.ComputeHash(stream);
        }

        /// <summary>
        /// Computes the SHA256 hash of a single file as a lowercase hexadecimal string.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        /// <returns>The SHA256 hash as a lowercase hexadecimal string.</returns>
        public static string ComputeFileHashString(string filePath)
        {
            var hashBytes = ComputeFileHash(filePath);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// Computes a deterministic SHA256 hash representing the contents of a directory.
        /// The hash is calculated based on the relative file paths (lowercase) and the content hash of each file.
        /// </summary>
        /// <param name="directoryPath">The path to the directory.</param>
        /// <returns>The SHA256 hash of the directory structure and content as a byte array.</returns>
        public static byte[] ComputeDirectoryHash(string directoryPath)
        {
            using var sha256 = SHA256.Create();
            var fileHashes = new List<byte[]>();

            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.OrdinalIgnoreCase); // Sort filenames to ensure consistent order

            foreach (var filePath in files)
            {
                // NEW: Use the byte array version of ComputeFileHash
                var fileContentHash = ComputeFileHash(filePath);
                var relativePath = Path.GetRelativePath(directoryPath, filePath).ToLowerInvariant();
                var pathBytes = Encoding.UTF8.GetBytes(relativePath);

                using var tempStream = new MemoryStream();
                tempStream.Write(pathBytes, 0, pathBytes.Length);
                tempStream.Write(fileContentHash, 0, fileContentHash.Length);
                tempStream.Position = 0;

                var combinedHash = sha256.ComputeHash(tempStream);
                fileHashes.Add(combinedHash);
            }

            fileHashes.Sort((x, y) => Comparer<byte[]>.Default.Compare(x, y));

            using var finalStream = new MemoryStream();
            foreach (var hash in fileHashes)
            {
                finalStream.Write(hash, 0, hash.Length);
            }
            finalStream.Position = 0;

            return sha256.ComputeHash(finalStream);
        }
    }
}