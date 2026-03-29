// PackItPro/Services/FileHasher.cs
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

        /// <summary>
        /// Computes a deterministic SHA256 over an explicit list of source file paths.
        /// Used by Packager when source files are not copied to a temp directory —
        /// we hash by explicit list rather than directory scan.
        ///
        /// Algorithm matches ComputeDirectoryHash exactly: per-file entry =
        /// SHA256(UTF8(filename) ++ rawFileHash), final = SHA256(sorted entries).
        ///
        /// The manifest file is always excluded — it cannot be part of its own hash.
        /// </summary>
        public static byte[] ComputeFileListHash(
            IEnumerable<string> sourceFilePaths,
            string manifestPath)
        {
            if (sourceFilePaths == null) throw new ArgumentNullException(nameof(sourceFilePaths));

            using var sha256 = SHA256.Create();
            var perFile = new List<byte[]>();

            foreach (var filePath in sourceFilePaths)
            {
                string fileName = Path.GetFileName(filePath);

                // Exclude manifest and log — matches ComputeDirectoryHash exclusions
                if (fileName.Equals("packitmeta.json", StringComparison.OrdinalIgnoreCase)) continue;
                if (fileName.Equals("install.log", StringComparison.OrdinalIgnoreCase)) continue;
                if (filePath.Equals(manifestPath, StringComparison.OrdinalIgnoreCase)) continue;

                byte[] fileHash;
                try { fileHash = ComputeFileHash(filePath); }
                catch (Exception ex)
                {
                    throw new IOException(
                        $"Cannot hash '{filePath}' — package cannot be built with an unreadable file. " +
                        "Ensure the file is not locked and you have read permissions.", ex);
                }

                // Key = bare filename — matches the ZIP entry name and post-extraction layout
                var pathBytes = System.Text.Encoding.UTF8.GetBytes(fileName);
                using var ms = new MemoryStream(pathBytes.Length + fileHash.Length);
                ms.Write(pathBytes, 0, pathBytes.Length);
                ms.Write(fileHash, 0, fileHash.Length);
                ms.Position = 0;
                perFile.Add(sha256.ComputeHash(ms));
            }

            if (perFile.Count == 0)
                throw new InvalidOperationException(
                    "No hashable files in list. Cannot compute integrity hash.");

            // Byte-level lexicographic sort — deterministic regardless of input order
            perFile.Sort((a, b) =>
            {
                int len = Math.Min(a.Length, b.Length);
                for (int i = 0; i < len; i++) { int d = a[i].CompareTo(b[i]); if (d != 0) return d; }
                return a.Length.CompareTo(b.Length);
            });

            using var final = new MemoryStream(perFile.Count * 32);
            foreach (var h in perFile) final.Write(h, 0, h.Length);
            final.Position = 0;
            return sha256.ComputeHash(final);
        }

        public class HashVerificationResult
        {
            public bool Passed { get; set; }
            public string? ActualHash { get; set; }
            public string? ExpectedHash { get; set; }
            public string? ErrorMessage { get; set; }
        }
    }
}