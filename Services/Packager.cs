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
    /// <summary>
    /// Delegate for reporting progress during packing operations
    /// </summary>
    public delegate void ProgressReportHandler(int percentage, string message);

    public static class Packager
    {
        // ✅ NEW: Progress event for UI updates
        public static event ProgressReportHandler? ProgressChanged;

        public static async Task<string> CreatePackageAsync(
            List<string> filePaths,
            string outputDirectory,
            string packageName,
            bool requiresAdmin,
            bool useLZMACompression,
            IProgress<(int percentage, string message)>? progress = null)
        {
            var tempDir = Path.Combine(Path.GetTempPath(), $"PackItPro_{Guid.NewGuid()}");
            string? payloadZipPath = null;
            string? tempFinalPath = null;

            try
            {
                Directory.CreateDirectory(tempDir);
                ReportProgress(progress, 5, "Preparing files...");
                LogInfo("Creating temporary directory for packing");

                // Copy files (use overwrite to avoid "already exists" error)
                var totalFiles = filePaths.Count;
                for (int i = 0; i < filePaths.Count; i++)
                {
                    var file = filePaths[i];
                    try
                    {
                        // Verify file is accessible before copying
                        using (var fs = File.Open(file, FileMode.Open, FileAccess.Read))
                        {
                            // File is accessible
                        }
                        
                        File.Copy(file, Path.Combine(tempDir, Path.GetFileName(file)), overwrite: true);
                        var copyProgress = (int)(5 + (i / (double)totalFiles) * 15);
                        ReportProgress(progress, copyProgress, $"Copying files ({i + 1}/{totalFiles})...");
                        LogInfo($"Copied: {Path.GetFileName(file)}");
                    }
                    catch (IOException ex) when (ex.Message.Contains("in use"))
                    {
                        throw new IOException($"File is locked (open in another application): {Path.GetFileName(file)}", ex);
                    }
                }

                ReportProgress(progress, 20, "Generating manifest...");
                var manifestJson = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin, includeWingetUpdateScript: false);
                var initialManifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(initialManifestPath, manifestJson);
                LogInfo("Manifest generated");

                ReportProgress(progress, 25, "Computing checksums...");
                var initialDirHash = Convert.ToBase64String(FileHasher.ComputeDirectoryHash(tempDir));
                LogInfo($"Calculated initial directory hash: {initialDirHash}");

                var manifestObj = JsonSerializer.Deserialize<PackageManifest>(manifestJson) ??
                    throw new InvalidDataException("Invalid manifest generated");
                manifestObj.SHA256Checksum = initialDirHash;
                manifestJson = JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(initialManifestPath, manifestJson);

                ReportProgress(progress, 30, "Creating ZIP archive...");
                payloadZipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");
                var allFilesInTemp = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).ToList();
                long totalBytes = 0;
                long processedBytes = 0;

                // Calculate total size for progress reporting
                foreach (var file in allFilesInTemp)
                {
                    totalBytes += new FileInfo(file).Length;
                }

                using (var fs = new FileStream(payloadZipPath, FileMode.Create))
                using (var zipStream = new ZipOutputStream(fs))
                {
                    zipStream.SetLevel(useLZMACompression ? 9 : 0);
                    var compressionLevel = useLZMACompression ? "Maximum (LZMA)" : "None";
                    LogInfo($"ZIP compression level: {compressionLevel}");

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
                    processedBytes += manifestFileInfo.Length;
                    ReportProgress(progress, 35, "Added manifest to archive");

                    // Add user files
                    var fileIndex = 0;
                    foreach (var filePath in allFilesInTemp)
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
                        processedBytes += fileInfo.Length;
                        fileIndex++;

                        // Progress: 35% (archive start) to 60% (archive complete)
                        var zipProgress = (int)(35 + (processedBytes / (double)totalBytes) * 25);
                        ReportProgress(progress, Math.Min(zipProgress, 60), $"Compressing {Path.GetFileName(filePath)} ({fileIndex}/{allFilesInTemp.Count})...");
                        LogInfo($"Added to ZIP: {Path.GetFileName(filePath)}");
                    }
                }

                ReportProgress(progress, 65, "Injecting payload into stub...");
                var zipFileSize = new FileInfo(payloadZipPath).Length;
                LogInfo($"ZIP file created: {zipFileSize} bytes");

                // FIXED: Find StubInstaller.exe correctly
                var stubPath = FindStubInstaller();
                tempFinalPath = Path.GetTempFileName();
                ResourceInjector.InjectPayload(stubPath, payloadZipPath, tempFinalPath);
                LogInfo("Payload injected into stub");

                ReportProgress(progress, 80, "Finalizing executable...");
                var outputPath = Path.Combine(outputDirectory, $"{packageName}.exe");
                File.Move(tempFinalPath, outputPath, overwrite: true);
                var finalSize = new FileInfo(outputPath).Length;
                LogInfo($"Output file created: {outputPath} ({finalSize} bytes)");

                ReportProgress(progress, 100, $"Package created successfully! ({FormatBytes(finalSize)})");
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

        // ✅ Helper method to format bytes
        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        // ✅ Helper to report progress
        private static void ReportProgress(IProgress<(int, string)>? progress, int percentage, string message)
        {
            progress?.Report((percentage, message));
            ProgressChanged?.Invoke(percentage, message);
            LogInfo($"Progress: {percentage}% - {message}");
        }

        private static void LogInfo(string message) =>
            Debug.WriteLine($"[Packager] INFO: {message}");
    }
}