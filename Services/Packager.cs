// PackItPro/Services/Packager.cs
using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public static class Packager
    {
        public static async Task<string> CreatePackageAsync(
            List<string> filePaths,
            string outputDirectory,
            string packageName,
            bool requiresAdmin,
            bool useLZMACompression)
        {
            var tempDir = Path.Combine(Path.GetTempPath(), $"PackItPro_{Guid.NewGuid()}");
            string? payloadZipPath = null;
            string? tempFinalPath = null;

            try
            {
                Directory.CreateDirectory(tempDir);

                // Copy files (use overwrite to avoid "already exists" error)
                foreach (var file in filePaths)
                {
                    File.Copy(file, Path.Combine(tempDir, Path.GetFileName(file)), overwrite: true);
                }

                var manifestJson = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin, includeWingetUpdateScript: false);
                var initialManifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(initialManifestPath, manifestJson);

                var initialDirHash = Convert.ToBase64String(FileHasher.ComputeDirectoryHash(tempDir));
                LogInfo($"Calculated initial directory hash: {initialDirHash}");

                var manifestObj = JsonSerializer.Deserialize<PackageManifest>(manifestJson) ??
                    throw new InvalidDataException("Invalid manifest generated");
                manifestObj.SHA256Checksum = initialDirHash;
                manifestJson = JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(initialManifestPath, manifestJson);

                payloadZipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");
                using (var fs = new FileStream(payloadZipPath, FileMode.Create))
                using (var zipStream = new ZipOutputStream(fs))
                {
                    zipStream.SetLevel(useLZMACompression ? 9 : 0);

                    // Add manifest
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

                    // Add user files
                    foreach (var filePath in Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories))
                    {
                        if (Path.GetFileName(filePath) == "packitmeta.json") continue;

                        var fileInfo = new FileInfo(filePath);
                        var entry = new ZipEntry(Path.GetRelativePath(tempDir, filePath))
                        {
                            DateTime = DateTime.Now,
                            Size = fileInfo.Length
                        };
                        zipStream.PutNextEntry(entry);
                        using var fileStream = File.OpenRead(filePath);
                        await fileStream.CopyToAsync(zipStream);
                        zipStream.CloseEntry();
                    }
                }

                // FIXED: Find StubInstaller.exe correctly
                var stubPath = FindStubInstaller();
                tempFinalPath = Path.GetTempFileName();
                ResourceInjector.InjectPayload(stubPath, payloadZipPath, tempFinalPath);

                var outputPath = Path.Combine(outputDirectory, $"{packageName}.exe");
                File.Move(tempFinalPath, outputPath, overwrite: true);
                return outputPath;
            }
            finally
            {
                // Clean up temp files
                if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir))
                    try { Directory.Delete(tempDir, true); } catch { }
                if (!string.IsNullOrEmpty(payloadZipPath) && File.Exists(payloadZipPath))
                    try { File.Delete(payloadZipPath); } catch { }
                if (!string.IsNullOrEmpty(tempFinalPath) && File.Exists(tempFinalPath))
                    try { File.Delete(tempFinalPath); } catch { }
            }
        }

        private static string FindStubInstaller()
        {
            // Check output directory first
            var localPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
            if (File.Exists(localPath)) return localPath;

            // Check AppData fallback
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PackItPro", "StubInstaller.exe");
            if (File.Exists(appDataPath)) return appDataPath;

            throw new FileNotFoundException("StubInstaller.exe not found in application directory or AppData.");
        }

        private static void LogInfo(string message) =>
            Debug.WriteLine($"[Packager] INFO: {message}");
    }
}