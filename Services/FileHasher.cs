// PackItPro/Services/FileHasher.cs - v2.2
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PackItPro.Services
{
    public static class FileHasher
    {
        private static readonly HashSet<string> DefaultExclusions = new(StringComparer.OrdinalIgnoreCase)
        {
            "packitmeta.json",
            "install.log",
        };

        public static byte[] ComputeFileHash(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return sha.ComputeHash(stream);
        }

        public static string ComputeFileHashString(string filePath)
        {
            var bytes = ComputeFileHash(filePath);
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// Computes a deterministic SHA256 over all installer files in a directory,
        /// excluding manifest and log files (which cannot be part of their own hash).
        ///
        /// THROWS on any unreadable file — partial hashing silently destroys
        /// integrity guarantees, so we fail hard instead of skipping.
        /// </summary>
        public static byte[] ComputeDirectoryHash(string directoryPath, params string[] additionalExclusions)
        {
            if (string.IsNullOrWhiteSpace(directoryPath))
                throw new ArgumentException("Directory path cannot be null or empty.", nameof(directoryPath));

            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");

            var exclusions = new HashSet<string>(DefaultExclusions, StringComparer.OrdinalIgnoreCase);
            foreach (var exc in additionalExclusions)
                exclusions.Add(exc);

            using var sha256 = SHA256.Create();
            var perFile = new List<byte[]>();
            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            int hashed = 0, skipped = 0;

            Array.Sort(files, StringComparer.OrdinalIgnoreCase);

            foreach (var filePath in files)
            {
                if (exclusions.Contains(Path.GetFileName(filePath)))
                {
                    skipped++;
                    continue;
                }

                // FIX #1: Never swallow — partial hashing breaks integrity guarantees entirely.
                byte[] fileHash;
                try
                {
                    fileHash = ComputeFileHash(filePath);
                }
                catch (Exception ex)
                {
                    throw new IOException(
                        $"Cannot hash '{filePath}' — package cannot be built with an unreadable file. " +
                        $"Ensure the file is not locked and you have read permissions.", ex);
                }

                // FIX #2: Preserve original path casing in hash input.
                // We normalise the separator for cross-platform determinism, but do NOT
                // lower-case — a future Linux stub verifying hashes would compute a
                // different hash if casing was changed here.
                var relPath = Path.GetRelativePath(directoryPath, filePath).Replace('\\', '/');
                var pathBytes = Encoding.UTF8.GetBytes(relPath);

                using var ms = new MemoryStream(pathBytes.Length + fileHash.Length);
                ms.Write(pathBytes, 0, pathBytes.Length);
                ms.Write(fileHash, 0, fileHash.Length);
                ms.Position = 0;
                perFile.Add(sha256.ComputeHash(ms));
                hashed++;
            }

            System.Diagnostics.Debug.WriteLine(
                $"[FileHasher] Hashed {hashed} file(s), skipped {skipped} excluded.");

            if (perFile.Count == 0)
                throw new InvalidOperationException(
                    $"No hashable files found in '{directoryPath}' " +
                    $"(hashed: {hashed}, skipped: {skipped}).");

            // Byte-level lexicographic sort — deterministic regardless of OS file ordering
            perFile.Sort((a, b) =>
            {
                int len = Math.Min(a.Length, b.Length);
                for (int i = 0; i < len; i++)
                {
                    int d = a[i].CompareTo(b[i]);
                    if (d != 0) return d;
                }
                return a.Length.CompareTo(b.Length);
            });

            using var final = new MemoryStream(perFile.Count * 32);
            foreach (var h in perFile)
                final.Write(h, 0, h.Length);

            final.Position = 0;
            return sha256.ComputeHash(final);
        }

        public static HashVerificationResult VerifyDirectoryHash(string directoryPath, string expectedBase64)
        {
            try
            {
                var actual = Convert.ToBase64String(ComputeDirectoryHash(directoryPath));
                bool passed = actual == expectedBase64;
                return new HashVerificationResult
                {
                    Passed = passed,
                    ActualHash = actual,
                    ExpectedHash = expectedBase64,
                    ErrorMessage = passed ? null : "Hash mismatch — files may have been modified or corrupted.",
                };
            }
            catch (Exception ex)
            {
                return new HashVerificationResult
                {
                    Passed = false,
                    ActualHash = null,
                    ExpectedHash = expectedBase64,
                    ErrorMessage = $"Hash computation failed: {ex.Message}",
                };
            }
        }
    }

    public class HashVerificationResult
    {
        public bool Passed { get; set; }
        public string? ActualHash { get; set; }
        public string? ExpectedHash { get; set; }
        public string? ErrorMessage { get; set; }
    }
}