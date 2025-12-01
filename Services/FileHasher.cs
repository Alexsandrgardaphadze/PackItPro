using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PackItPro.Services
{
    /// <summary>
    /// Utility class for computing SHA256 file and directory hashes in a
    /// deterministic and reproducible way.
    /// </summary>
    public static class FileHasher
    {
        /// <summary>
        /// Computes the SHA256 hash of a file and returns its raw byte array.
        /// </summary>
        public static byte[] ComputeFileHash(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return sha.ComputeHash(stream);
        }

        /// <summary>
        /// Computes the SHA256 hash of a file and returns it as a lowercase hex string.
        /// </summary>
        public static string ComputeFileHashString(string filePath)
        {
            var hashBytes = ComputeFileHash(filePath);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// Computes a deterministic SHA256 hash representing the entire directory contents.
        /// Includes lowercase relative paths and file content hashes.
        /// </summary>
        public static byte[] ComputeDirectoryHash(string directoryPath)
        {
            if (string.IsNullOrWhiteSpace(directoryPath))
                throw new ArgumentException("Directory path cannot be null or empty.", nameof(directoryPath));

            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");

            using var sha256 = SHA256.Create();
            var perFileHashes = new List<byte[]>();

            // Get files and sort by their relative path for consistency
            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);

            foreach (var filePath in files)
            {
                try
                {
                    var fileContentHash = ComputeFileHash(filePath);

                    // Always use relative path to avoid machine-dependent hashing
                    var relativePath = Path.GetRelativePath(directoryPath, filePath)
                        .Replace('\\', '/') // Normalize path separators
                        .ToLowerInvariant(); // Ensure case-insensitive consistency

                    var pathBytes = Encoding.UTF8.GetBytes(relativePath);

                    // Combine path + content hash into a temporary stream
                    using var combinedStream = new MemoryStream();
                    combinedStream.Write(pathBytes, 0, pathBytes.Length);
                    combinedStream.Write(fileContentHash, 0, fileContentHash.Length);
                    combinedStream.Position = 0; // Reset position for reading

                    // Hash the combined data (path + content hash)
                    perFileHashes.Add(sha256.ComputeHash(combinedStream));
                }
                catch (Exception)
                {
                    // Skip files that cannot be read (locked, permissions, etc.)
                    // This ensures the hash calculation is deterministic: the same set of readable files
                    // will always produce the same hash, regardless of other unreadable files in the directory.
                }
            }

            // NEW: Sort the list of byte arrays using the StructuralComparer adapted via a lambda.
            // This ensures the final hash is order-independent of the *hashes* themselves,
            // only depending on the *set* of hashes and their content.
            perFileHashes.Sort((x, y) => StructuralComparisons.StructuralComparer.Compare(x, y));

            // Combine all sorted hashes into a final stream and hash it
            using var finalStream = new MemoryStream();
            foreach (var hash in perFileHashes)
            {
                finalStream.Write(hash, 0, hash.Length);
            }
            finalStream.Position = 0;

            return sha256.ComputeHash(finalStream);
        }
    }
}