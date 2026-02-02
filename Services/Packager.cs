// PackItPro/Services/Packager.cs - COMPLETE PRODUCTION VERSION
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

        /// <summary>
        /// Creates a packaged installer containing multiple files
        /// </summary>
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
                LogInfo("========== PACKAGE CREATION START ==========");
                LogInfo($"Creating temporary directory: {tempDir}");

                // ============================================================
                // STEP 1: COPY FILES TO TEMP DIRECTORY
                // ============================================================
                int totalFiles = filePaths.Count;
                LogInfo($"Copying {totalFiles} file(s) to temp directory...");

                for (int i = 0; i < totalFiles; i++)
                {
                    string file = filePaths[i];
                    try
                    {
                        // Verify file is accessible
                        using (var fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read)) { }

                        string destPath = Path.Combine(tempDir, Path.GetFileName(file));
                        File.Copy(file, destPath, overwrite: true);

                        var copyProgress = (int)(5 + (i / (double)totalFiles) * 15);
                        ReportProgress(progress, copyProgress, $"Copying files ({i + 1}/{totalFiles})...");
                        LogInfo($"  ✓ Copied: {Path.GetFileName(file)} ({FormatBytes(new FileInfo(file).Length)})");
                    }
                    catch (IOException ex) when (ex.Message.Contains("in use") || ex.Message.Contains("being used"))
                    {
                        throw new IOException($"File is locked or in use: {Path.GetFileName(file)}\n\nPlease close any programs using this file and try again.", ex);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        throw new UnauthorizedAccessException($"Cannot access file: {Path.GetFileName(file)}\n\nCheck file permissions.", ex);
                    }
                }

                // ============================================================
                // STEP 2: GENERATE MANIFEST
                // ============================================================
                ReportProgress(progress, 20, "Generating manifest...");
                LogInfo("Generating package manifest...");

                var manifestJson = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin, false);
                var manifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(manifestPath, manifestJson);
                LogInfo("  ✓ Manifest generated");

                // ============================================================
                // STEP 3: COMPUTE DIRECTORY HASH
                // ============================================================
                ReportProgress(progress, 25, "Computing checksums...");
                LogInfo("Computing directory hash for integrity verification...");

                string dirHash = Convert.ToBase64String(FileHasher.ComputeDirectoryHash(tempDir));
                LogInfo($"  ✓ Directory hash: {dirHash.Substring(0, 16)}...");

                // Update manifest with hash
                var manifestObj = JsonSerializer.Deserialize<PackageManifest>(manifestJson) ??
                    throw new InvalidDataException("Failed to deserialize manifest");
                manifestObj.SHA256Checksum = dirHash;
                manifestJson = JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(manifestPath, manifestJson);
                LogInfo("  ✓ Manifest updated with checksum");

                // ============================================================
                // STEP 4: CREATE ZIP ARCHIVE
                // ============================================================
                ReportProgress(progress, 30, "Creating ZIP archive...");
                LogInfo("Creating ZIP payload...");

                payloadZipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");
                var allFilesInTemp = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).ToList();
                long totalBytes = allFilesInTemp.Sum(f => new FileInfo(f).Length);
                long processedBytes = 0;

                LogInfo($"  Compressing {allFilesInTemp.Count} file(s) ({FormatBytes(totalBytes)})...");

                using (var fs = new FileStream(payloadZipPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var zipStream = new ZipOutputStream(fs))
                {
                    // Set compression level (0=none, 9=max)
                    zipStream.SetLevel(useLZMACompression ? 9 : 6);
                    LogInfo($"  Compression level: {(useLZMACompression ? "Maximum (9)" : "Standard (6)")}");

                    // Add manifest first
                    var manifestFileInfo = new FileInfo(manifestPath);
                    var manifestEntry = new ZipEntry("packitmeta.json")
                    {
                        DateTime = DateTime.Now,
                        Size = manifestFileInfo.Length
                    };

                    zipStream.PutNextEntry(manifestEntry);
                    using (var manifestStream = File.OpenRead(manifestPath))
                    {
                        await manifestStream.CopyToAsync(zipStream);
                    }
                    zipStream.CloseEntry();
                    processedBytes += manifestFileInfo.Length;
                    ReportProgress(progress, 35, "Added manifest to archive");

                    // Add all user files
                    int fileIndex = 0;
                    foreach (var filePath in allFilesInTemp)
                    {
                        if (Path.GetFileName(filePath) == "packitmeta.json")
                            continue; // Already added

                        var fileInfo = new FileInfo(filePath);
                        var relativePath = Path.GetRelativePath(tempDir, filePath);

                        var entry = new ZipEntry(relativePath)
                        {
                            DateTime = DateTime.Now,
                            Size = fileInfo.Length
                        };

                        zipStream.PutNextEntry(entry);

                        using (var fileStream = File.OpenRead(filePath))
                        {
                            byte[] buffer = new byte[81920]; // 80 KB buffer
                            int bytesRead;
                            long fileBytesWritten = 0;

                            while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                zipStream.Write(buffer, 0, bytesRead);
                                fileBytesWritten += bytesRead;
                            }

                            if (fileBytesWritten != fileInfo.Length)
                            {
                                LogWarning($"Size mismatch for {Path.GetFileName(filePath)}: wrote {fileBytesWritten}, expected {fileInfo.Length}");
                            }
                        }

                        zipStream.CloseEntry();
                        processedBytes += fileInfo.Length;
                        fileIndex++;

                        var zipProgress = (int)(35 + (processedBytes / (double)totalBytes) * 25);
                        ReportProgress(progress, Math.Min(zipProgress, 60),
                            $"Compressing {Path.GetFileName(filePath)} ({fileIndex}/{allFilesInTemp.Count})...");

                        LogInfo($"    [{fileIndex}/{allFilesInTemp.Count}] {Path.GetFileName(filePath)} ({FormatBytes(fileInfo.Length)})");
                    }

                    zipStream.Finish();
                    zipStream.Flush();
                }

                // Verify ZIP was created correctly
                var zipFileInfo = new FileInfo(payloadZipPath);
                if (!zipFileInfo.Exists || zipFileInfo.Length == 0)
                {
                    throw new InvalidOperationException("ZIP payload creation failed - file is empty or missing!");
                }

                LogInfo($"  ✓ ZIP created: {FormatBytes(zipFileInfo.Length)}");
                LogInfo($"  Compression ratio: {(totalBytes > 0 ? (zipFileInfo.Length * 100.0 / totalBytes) : 0):F1}%");

                // ============================================================
                // STEP 5: INJECT PAYLOAD INTO STUB
                // ============================================================
                ReportProgress(progress, 65, "Injecting payload into stub...");
                LogInfo("Injecting payload into stub installer...");

                var stubPath = FindStubInstaller();
                LogInfo($"  Using stub: {stubPath}");

                tempFinalPath = Path.GetTempFileName();

                // Use the FIXED ResourceInjector
                ResourceInjector.InjectPayload(stubPath, payloadZipPath, tempFinalPath);

                // Verify the injection worked
                if (!ResourceInjector.VerifyPackagedExe(tempFinalPath))
                {
                    throw new InvalidOperationException("Package verification failed! The payload may not have been injected correctly.");
                }

                LogInfo("  ✓ Payload injection verified");

                // ============================================================
                // STEP 6: MOVE TO FINAL LOCATION
                // ============================================================
                ReportProgress(progress, 80, "Finalizing executable...");
                LogInfo("Moving to final location...");

                string outputPath = Path.Combine(outputDirectory, $"{packageName}.exe");

                // Delete existing file if it exists
                if (File.Exists(outputPath))
                {
                    try
                    {
                        File.Delete(outputPath);
                        LogInfo($"  Deleted existing file: {outputPath}");
                    }
                    catch (IOException ex)
                    {
                        throw new IOException($"Cannot overwrite existing file (it may be in use): {outputPath}\n\nClose any programs using this file.", ex);
                    }
                }

                File.Move(tempFinalPath, outputPath, overwrite: true);

                var finalFileInfo = new FileInfo(outputPath);
                LogInfo($"  ✓ Package created: {outputPath}");
                LogInfo($"  Final size: {FormatBytes(finalFileInfo.Length)}");

                ReportProgress(progress, 100, "Package created successfully!");
                LogInfo("========== PACKAGE CREATION SUCCESS ==========");

                return outputPath;
            }
            catch (Exception ex)
            {
                LogError($"Package creation failed: {ex.Message}");
                LogError($"Stack trace: {ex.StackTrace}");
                throw; // Re-throw to let caller handle
            }
            finally
            {
                // Cleanup temporary files
                try
                {
                    if (Directory.Exists(tempDir))
                    {
                        Directory.Delete(tempDir, true);
                        LogInfo($"Cleaned up temp directory: {tempDir}");
                    }
                }
                catch (Exception ex)
                {
                    LogWarning($"Failed to delete temp directory: {ex.Message}");
                }

                try
                {
                    if (File.Exists(payloadZipPath))
                    {
                        File.Delete(payloadZipPath);
                        LogInfo($"Cleaned up payload ZIP: {payloadZipPath}");
                    }
                }
                catch (Exception ex)
                {
                    LogWarning($"Failed to delete payload ZIP: {ex.Message}");
                }

                try
                {
                    if (File.Exists(tempFinalPath))
                    {
                        File.Delete(tempFinalPath);
                        LogInfo($"Cleaned up temp final file: {tempFinalPath}");
                    }
                }
                catch (Exception ex)
                {
                    LogWarning($"Failed to delete temp final file: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Finds the StubInstaller.exe in known locations
        /// </summary>
        private static string FindStubInstaller()
        {
            // Check local directory (development)
            var local = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
            if (File.Exists(local))
            {
                LogInfo($"Found stub in local directory: {local}");
                return local;
            }

            // Check AppData (installed)
            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PackItPro",
                "StubInstaller.exe");

            if (File.Exists(appData))
            {
                LogInfo($"Found stub in AppData: {appData}");
                return appData;
            }

            // Check one level up (bin/Debug vs project root)
            var parentDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "StubInstaller.exe");
            if (File.Exists(parentDir))
            {
                LogInfo($"Found stub in parent directory: {parentDir}");
                return Path.GetFullPath(parentDir);
            }

            throw new FileNotFoundException(
                "StubInstaller.exe not found!\n\n" +
                "Searched in:\n" +
                $"  1. {local}\n" +
                $"  2. {appData}\n" +
                $"  3. {parentDir}\n\n" +
                "Please ensure StubInstaller.exe is in your project output directory and set to 'Copy always'.");
        }

        /// <summary>
        /// Formats bytes into human-readable format
        /// </summary>
        private static string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        /// <summary>
        /// Reports progress to both IProgress and event subscribers
        /// </summary>
        private static void ReportProgress(IProgress<(int, string)>? progress, int percentage, string message)
        {
            progress?.Report((percentage, message));
            ProgressChanged?.Invoke(percentage, message);
            LogInfo($"[{percentage}%] {message}");
        }

        private static void LogInfo(string message)
        {
            Debug.WriteLine($"[Packager] {message}");
            Console.WriteLine($"[Packager] {message}");
        }

        private static void LogWarning(string message)
        {
            Debug.WriteLine($"[Packager] WARNING: {message}");
            Console.WriteLine($"[Packager] WARNING: {message}");
        }

        private static void LogError(string message)
        {
            Debug.WriteLine($"[Packager] ERROR: {message}");
            Console.WriteLine($"[Packager] ERROR: {message}");
        }
    }
}
