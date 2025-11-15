// Packager.cs
// NEW: Add SharpZipLib namespace
using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
// NEW: Add Diagnostics namespace for Debug.WriteLine
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text; // For Encoding
using System.Text.Json;
using System.Threading.Tasks;

namespace PackItPro
{
    public static class Packager
    {
        // NEW: Accept settings object or relevant settings values as parameters
        public static async Task<string> CreatePackageAsync(
            List<string> filePaths,
            string outputDirectory,
            string packageName,
            bool requiresAdmin,
            bool useLZMACompression) // NEW: Pass compression setting
        {
            var tempDir = Path.Combine(Path.GetTempPath(), $"PackItPro_{Guid.NewGuid()}");
            string? payloadZipPath = null;
            string? tempFinalPath = null;

            try
            {
                Directory.CreateDirectory(tempDir);

                // Copy files
                foreach (var file in filePaths)
                {
                    File.Copy(file, Path.Combine(tempDir, Path.GetFileName(file)));
                }

                // Generate manifest using ManifestGenerator
                var includeWingetScript = false; // Could be passed as a parameter or fetched from settings
                var manifestJson = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin, includeWingetScript);

                // Calculate checksum of the *initial* payload contents (before manifest contains the final hash)
                // We calculate the hash of the temp directory *as it stands now* (with files and initial manifest).
                // Then we put this hash INTO the manifest, and re-create the zip.
                var initialManifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(initialManifestPath, manifestJson);
                // NEW: Use the ComputeDirectoryHash from VirusTotalClient or a shared utility
                // Assuming VirusTotalClient.ComputeDirectoryHash is static and public, or moved to a util class
                // If it's not static, you'd need an instance or pass it in.
                // For now, assuming static public.
                var initialDirHash = Convert.ToBase64String(ComputeDirectoryHash(tempDir)); // Reuse the hash function from VirusTotalClient or move to Utils
                LogInfo($"Calculated initial directory hash for integrity check: {initialDirHash}"); // Log the initial hash

                // Deserialize manifest, update with hash, serialize again
                var manifestObj = JsonSerializer.Deserialize<PackageManifest>(manifestJson) ?? throw new InvalidDataException("Invalid manifest generated");
                manifestObj.SHA256Checksum = initialDirHash; // Set the calculated hash
                manifestJson = JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(initialManifestPath, manifestJson); // Overwrite the initial manifest with the one containing the hash


                // Create the final payload.zip containing the updated manifest
                payloadZipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");
                using (var fs = new FileStream(payloadZipPath, FileMode.Create))
                using (var zipStream = new ZipOutputStream(fs))
                {
                    // NEW: Clarify compression setting - SharpZipLib uses SetLevel for Deflate
                    // LZMA is not natively supported by ZipOutputStream. You'd need SevenZipSharp or SharpCompress for true LZMA within a zip.
                    // For now, using Deflate.
                    if (useLZMACompression) // NEW: Use the passed-in setting
                    {
                        zipStream.SetLevel(9); // Highest Deflate compression
                        LogInfo("Using Deflate (level 9) as LZMA placeholder in payload zip. Consider SevenZipSharp for true LZMA.");
                    }
                    else
                    {
                        zipStream.SetLevel(0); // No compression
                    }

                    int totalFiles = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).Length + 1; // Approximate count (+1 for manifest)
                    int processed = 0;

                    // Add updated manifest first
                    var manifestFileInfo = new FileInfo(initialManifestPath);
                    var manifestEntry = new ZipEntry("packitmeta.json")
                    {
                        DateTime = DateTime.Now,
                        Size = manifestFileInfo.Length
                    };
                    zipStream.PutNextEntry(manifestEntry);
                    using var manifestStream = File.OpenRead(manifestFileInfo.FullName);
                    await manifestStream.CopyToAsync(zipStream);
                    zipStream.CloseEntry();
                    processed++;

                    // Add user files
                    foreach (var filePath in Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories))
                    {
                        if (Path.GetFileName(filePath) == "packitmeta.json") continue; // Skip the initial manifest file, we added the updated one

                        var fileInfo = new FileInfo(filePath);
                        var entry = new ZipEntry(Path.GetRelativePath(tempDir, filePath)) // Use relative path for zip
                        {
                            DateTime = DateTime.Now,
                            Size = fileInfo.Length
                        };
                        zipStream.PutNextEntry(entry);
                        using var fileStream = File.OpenRead(filePath);
                        await fileStream.CopyToAsync(zipStream);
                        zipStream.CloseEntry();

                        processed++;
                        // Could update progress here if needed within this function
                    }
                }

                // Find and embed payload into stub using ResourceInjector
                var stubPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe"); // Or look in AppData
                if (!File.Exists(stubPath))
                {
                    // Fallback to AppData or error
                    var appDataStubPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "PackItPro", "StubInstaller.exe"
                    );
                    if (!File.Exists(appDataStubPath))
                    {
                        throw new FileNotFoundException("StubInstaller.exe not found in application directory or AppData.");
                    }
                    stubPath = appDataStubPath;
                }

                tempFinalPath = Path.GetTempFileName();
                ResourceInjector.InjectPayload(stubPath, payloadZipPath, tempFinalPath);

                // Move temp file to final location
                var outputPath = Path.Combine(outputDirectory, $"{packageName}.packitexe");
                File.Move(tempFinalPath, outputPath, overwrite: true);

                return outputPath;
            }
            finally
            {
                // Ensure temporary files are deleted even if an exception occurs
                if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, true); } catch { /* Ignore errors during cleanup */ }
                }
                if (!string.IsNullOrEmpty(payloadZipPath) && File.Exists(payloadZipPath))
                {
                    try { File.Delete(payloadZipPath); } catch { /* Ignore errors during cleanup */ }
                }
                if (!string.IsNullOrEmpty(tempFinalPath) && File.Exists(tempFinalPath))
                {
                    try { File.Delete(tempFinalPath); } catch { /* Ignore errors during cleanup */ }
                }
            }
        }

        // NEW: Log helper specific to this class (optional, could use global one)
        private static void LogInfo(string message)
        {
            // Could use the global LogInfo from MainWindow or a dedicated logger
            Debug.WriteLine($"[Packager] INFO: {message}");
        }

        // NEW: Helper function to compute directory hash (moved from VirusTotalClient or made static here)
        // This function calculates a deterministic hash based on file content AND relative path.
        private static byte[] ComputeDirectoryHash(string directoryPath)
        {
            using var sha256 = SHA256.Create();
            var fileHashes = new List<byte[]>();

            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.OrdinalIgnoreCase); // Sort filenames to ensure consistent order

            foreach (var filePath in files)
            {
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

        // NEW: Helper function to compute file hash
        private static byte[] ComputeFileHash(string filePath)
        {
            using var fileStream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(fileStream);
        }
    }
}