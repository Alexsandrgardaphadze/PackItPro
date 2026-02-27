// StubInstaller/IntegrityChecker.cs
// Deterministic SHA-256 hash over a directory's contents.
// Algorithm is identical to PackItPro/Services/FileHasher.cs — they must stay in sync:
//   per-file entry = SHA256( UTF8(relPath_with_forward_slashes) ++ rawFileHash )
//   final hash     = SHA256( all per-file entries sorted and concatenated )
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace StubInstaller
{
    internal static class IntegrityChecker
    {
        /// <summary>
        /// Computes the directory hash, always excluding the manifest and log files
        /// (the manifest contains the expected hash; the log is written after hashing).
        /// </summary>
        internal static byte[] ComputeDirectoryHash(
            string directoryPath,
            IEnumerable<string>? extraExcludes = null)
        {
            var exclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Constants.ManifestFileName,
                Constants.LogFileName,
            };
            if (extraExcludes != null)
                foreach (var e in extraExcludes) exclusions.Add(e);

            using var sha = SHA256.Create();

            var perFileHashes = Directory
                .GetFiles(directoryPath, "*", SearchOption.AllDirectories)
                .Where(f => !exclusions.Contains(Path.GetFileName(f)))
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .Select(f => ComputeFileEntry(sha, directoryPath, f))
                .ToList();

            if (perFileHashes.Count == 0)
                throw new InvalidOperationException($"No hashable files found in '{directoryPath}'.");

            // Sort the per-file hashes so filesystem traversal order never matters
            perFileHashes.Sort(CompareHashes);

            // Final hash = SHA256 of all per-file hashes concatenated
            using var buffer = new MemoryStream(perFileHashes.Count * 32);
            foreach (var h in perFileHashes) buffer.Write(h);
            buffer.Position = 0;
            return sha.ComputeHash(buffer);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static byte[] ComputeFileEntry(SHA256 sha, string root, string filePath)
        {
            // Hash the file bytes
            byte[] fileHash;
            using (var fs = File.OpenRead(filePath))
                fileHash = sha.ComputeHash(fs);
            sha.Initialize();

            // Combine relative path + file hash into one entry
            // (renamed file ≠ same entry even if content is identical)
            string relPath = Path.GetRelativePath(root, filePath).Replace('\\', '/');
            byte[] pathBytes = Encoding.UTF8.GetBytes(relPath);

            using var ms = new MemoryStream(pathBytes.Length + fileHash.Length);
            ms.Write(pathBytes);
            ms.Write(fileHash);
            ms.Position = 0;

            var entry = sha.ComputeHash(ms);
            sha.Initialize();
            return entry;
        }

        private static int CompareHashes(byte[] a, byte[] b)
        {
            int len = Math.Min(a.Length, b.Length);
            for (int i = 0; i < len; i++)
            {
                int d = a[i].CompareTo(b[i]);
                if (d != 0) return d;
            }
            return a.Length.CompareTo(b.Length);
        }
    }
}