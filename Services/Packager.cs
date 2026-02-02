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
    public delegate void ProgressReportHandler(int percentage, string message);

    public static class Packager
    {
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

                // COPY FILES
                int totalFiles = filePaths.Count;
                for (int i = 0; i < totalFiles; i++)
                {
                    string file = filePaths[i];
                    try
                    {
                        using (var fs = File.Open(file, FileMode.Open, FileAccess.Read)) { }

                        File.Copy(file, Path.Combine(tempDir, Path.GetFileName(file)), overwrite: true);
                        var copyProgress = (int)(5 + (i / (double)totalFiles) * 15);
                        ReportProgress(progress, copyProgress, $"Copying files ({i + 1}/{totalFiles})...");
                        LogInfo($"Copied: {Path.GetFileName(file)}");
                    }
                    catch (IOException ex) when (ex.Message.Contains("in use"))
                    {
                        throw new IOException($"File is locked: {Path.GetFileName(file)}", ex);
                    }
                }

                // MANIFEST
                ReportProgress(progress, 20, "Generating manifest...");
                var manifestJson = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin, false);
                var manifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(manifestPath, manifestJson);
                LogInfo("Manifest generated");

                // HASH CHECKSUM
                ReportProgress(progress, 25, "Computing checksums...");
                string dirHash = Convert.ToBase64String(FileHasher.ComputeDirectoryHash(tempDir));
                LogInfo($"Directory hash: {dirHash}");

                var manifestObj = JsonSerializer.Deserialize<PackageManifest>(manifestJson) ??
                    throw new InvalidDataException("Invalid manifest generated");
                manifestObj.SHA256Checksum = dirHash;
                manifestJson = JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(manifestPath, manifestJson);

                // CREATE ZIP
                ReportProgress(progress, 30, "Creating ZIP archive...");
                payloadZipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");
                var allFilesInTemp = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).ToList();
                long totalBytes = allFilesInTemp.Sum(f => new FileInfo(f).Length);
                long processedBytes = 0;

                using (var fs = new FileStream(payloadZipPath, FileMode.Create))
                using (var zipStream = new ZipOutputStream(fs))
                {
                    zipStream.SetLevel(useLZMACompression ? 9 : 0);

                    // ADD MANIFEST
                    var manifestFileInfo = new FileInfo(manifestPath);
                    var manifestEntry = new ZipEntry("packitmeta.json")
                    {
                        DateTime = DateTime.Now,
                        Size = manifestFileInfo.Length
                    };
                    zipStream.PutNextEntry(manifestEntry);
                    using var manifestStream = File.OpenRead(manifestPath);
                    await manifestStream.CopyToAsync(zipStream);
                    zipStream.CloseEntry();
                    processedBytes += manifestFileInfo.Length;
                    ReportProgress(progress, 35, "Added manifest to archive");

                    // ADD USER FILES
                    int fileIndex = 0;
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
                        byte[] buffer = new byte[81920];
                        int bytesRead;
                        long copiedBytes = 0;
                        while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            zipStream.Write(buffer, 0, bytesRead);
                            copiedBytes += bytesRead;
                        }
                        zipStream.CloseEntry();
                        processedBytes += fileInfo.Length;
                        fileIndex++;

                        var zipProgress = (int)(35 + (processedBytes / (double)totalBytes) * 25);
                        ReportProgress(progress, Math.Min(zipProgress, 60), $"Compressing {Path.GetFileName(filePath)} ({fileIndex}/{allFilesInTemp.Count})...");
                        LogInfo($"Added to ZIP: {Path.GetFileName(filePath)} ({copiedBytes} bytes)");
                    }

                    zipStream.Finish();
                }

                // INJECT PAYLOAD INTO STUB
                ReportProgress(progress, 65, "Injecting payload into stub...");
                var stubPath = FindStubInstaller();
                tempFinalPath = Path.GetTempFileName();
                ResourceInjector.InjectPayload(stubPath, payloadZipPath, tempFinalPath);

                // MOVE FINAL EXECUTABLE
                ReportProgress(progress, 80, "Finalizing executable...");
                string outputPath = Path.Combine(outputDirectory, $"{packageName}.exe");
                File.Move(tempFinalPath, outputPath, overwrite: true);
                LogInfo($"Output created: {outputPath}");

                ReportProgress(progress, 100, $"Package created successfully!");
                return outputPath;
            }
            finally
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
                try { if (File.Exists(payloadZipPath)) File.Delete(payloadZipPath); } catch { }
                try { if (File.Exists(tempFinalPath)) File.Delete(tempFinalPath); } catch { }
            }
        }

        private static string FindStubInstaller()
        {
            var local = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
            if (File.Exists(local)) return local;

            var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PackItPro", "StubInstaller.exe");
            if (File.Exists(appData)) return appData;

            throw new FileNotFoundException("StubInstaller.exe not found.");
        }

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1) { order++; len /= 1024; }
            return $"{len:0.##} {sizes[order]}";
        }

        private static void ReportProgress(IProgress<(int, string)>? progress, int percentage, string message)
        {
            progress?.Report((percentage, message));
            ProgressChanged?.Invoke(percentage, message);
            LogInfo($"Progress: {percentage}% - {message}");
        }

        private static void LogInfo(string message) => Debug.WriteLine($"[Packager] {message}");
    }
}
