// PackItPro/Services/FileHasher.cs
using System;
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
        public static byte[] ComputeFileHash(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return sha.ComputeHash(stream);
        }

        public static string ComputeFileHashString(string filePath)
        {
            var hashBytes = ComputeFileHash(filePath);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        public static byte[] ComputeDirectoryHash(string directoryPath)
        {
            if (string.IsNullOrWhiteSpace(directoryPath))
                throw new ArgumentException("Directory path cannot be null or empty.", nameof(directoryPath));

            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");

            using var sha256 = SHA256.Create();
            var perFileHashes = new List<byte[]>();

            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);

            foreach (var filePath in files)
            {
                try
                {
                    var fileContentHash = ComputeFileHash(filePath);
                    var relativePath = Path.GetRelativePath(directoryPath, filePath)
                        .Replace('\\', '/')
                        .ToLowerInvariant();

                    var pathBytes = Encoding.UTF8.GetBytes(relativePath);
                    using var combinedStream = new MemoryStream();
                    combinedStream.Write(pathBytes, 0, pathBytes.Length);
                    combinedStream.Write(fileContentHash, 0, fileContentHash.Length);
                    combinedStream.Position = 0;
                    perFileHashes.Add(sha256.ComputeHash(combinedStream));
                }
                catch (Exception)
                {
                    // Skip unreadable files deterministically
                }
            }

            // FIXED: Safe lexicographical sort for byte[]
            perFileHashes.Sort((a, b) =>
            {
                for (int i = 0; i < Math.Min(a.Length, b.Length); i++)
                {
                    int diff = a[i].CompareTo(b[i]);
                    if (diff != 0) return diff;
                }
                return a.Length.CompareTo(b.Length);
            });

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