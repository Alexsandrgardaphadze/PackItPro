using ICSharpCode.SharpZipLib.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PackItPro.Services
{
    public static class Packager
    {
        // Deterministic ZIP timestamp so identical content always produces identical bytes.
        private static readonly DateTime ZipEpoch = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Maps the UI ComboBox index to a SharpZipLib compression level:
        ///   0 = None     → store only (level 0)
        ///   1 = Fast     → deflate default (level 6)
        ///   2 = Maximum  → maximum deflate (level 9)
        /// </summary>
        private static int MapCompressionLevel(int uiIndex) => uiIndex switch
        {
            0 => 0,
            1 => 6,
            2 => 9,
            _ => 6,
        };

        public static async Task<string> CreatePackageAsync(
            List<string> filePaths,
            string outputDirectory,
            string packageName,
            bool requiresAdmin,
            int compressionLevel,
            bool includeWingetUpdateScript,
            IProgress<(int percentage, string message)>? progress = null,
            ILogService? log = null,
            CancellationToken ct = default)
        {
            log ??= NullLogService.Instance;

            var tempDir = Path.Combine(Path.GetTempPath(), $"PackItPro_{Guid.NewGuid()}");
            string? zipPath = null;
            string? finalTemp = null;

            try
            {
                Directory.CreateDirectory(tempDir);
                Report(progress, 5, "Step 1 of 6 — Preparing files...");
                log.Info("========== PACKAGE CREATION START ==========");
                log.Info($"Package: '{packageName}' | Files: {filePaths.Count} | Admin: {requiresAdmin} | Compression: {compressionLevel} | Winget: {includeWingetUpdateScript}");

                // STEP 1: Copy source files to temp directory
                Report(progress, 8, "Step 1 of 6 — Copying files...");
                log.Info($"STEP 1: Copying {filePaths.Count} file(s)...");

                for (int i = 0; i < filePaths.Count; i++)
                {
                    ct.ThrowIfCancellationRequested();

                    string src = filePaths[i];
                    string dest = Path.Combine(tempDir, Path.GetFileName(src));

                    try
                    {
                        using (File.Open(src, FileMode.Open, FileAccess.Read, FileShare.Read)) { }
                        File.Copy(src, dest, overwrite: true);
                        log.Info($"  [{i + 1}/{filePaths.Count}] {Path.GetFileName(src)} ({FormatBytes(new FileInfo(src).Length)})");
                        Report(progress, 8 + (int)((i + 1.0) / filePaths.Count * 12),
                            $"Step 1 of 6 — Copying files ({i + 1}/{filePaths.Count})...");
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        throw new UnauthorizedAccessException(
                            $"Access denied to '{Path.GetFileName(src)}'. " +
                            "Check file permissions or run PackItPro as Administrator.", ex);
                    }
                    catch (IOException ex)
                    {
                        throw new IOException(
                            $"Cannot read '{Path.GetFileName(src)}': {ex.Message}\n" +
                            "Ensure the file is not locked by another program.", ex);
                    }
                }

                // STEP 1b: Write update_all.bat when Winget Updater is enabled.
                // The manifest references this filename — the file must exist in the ZIP.
                if (includeWingetUpdateScript)
                {
                    var batPath = Path.Combine(tempDir, "update_all.bat");
                    await File.WriteAllTextAsync(batPath, WingetUpdaterScript(), ct);
                    log.Info("  Winget updater script added: update_all.bat");
                }

                // STEP 2: Generate manifest
                Report(progress, 20, "Step 2 of 6 — Generating manifest...");
                log.Info("STEP 2: Generating manifest...");

                var manifestJson = ManifestGenerator.Generate(
                    filePaths,
                    packageName,
                    requiresAdmin,
                    includeWingetUpdateScript);

                var manifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(manifestPath, manifestJson, ct);
                log.Info("  Manifest written (checksum pending).");

                // STEP 3: Hash all files and embed the checksum in the manifest
                Report(progress, 25, "Step 3 of 6 — Computing integrity hash...");
                log.Info("STEP 3: Hashing installer files...");

                string dirHash = await Task.Run(
                    () => Convert.ToBase64String(FileHasher.ComputeDirectoryHash(tempDir)), ct);
                log.Info($"  Hash: {dirHash[..16]}...");

                var manifestObj = JsonSerializer.Deserialize<PackageManifest>(manifestJson)
                    ?? throw new InvalidDataException("Failed to deserialize manifest for checksum update.");
                manifestObj.SHA256Checksum = dirHash;
                manifestJson = JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(manifestPath, manifestJson, ct);
                log.Info("  Manifest updated with checksum.");

                // STEP 4: Create ZIP archive
                Report(progress, 30, "Step 4 of 6 — Compressing payload (will take a moment)...");
                log.Info("STEP 4: Compressing payload...");

                zipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");

                var allFiles = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).ToList();
                long totalBytes = allFiles.Sum(f => new FileInfo(f).Length);
                int zipLevel = MapCompressionLevel(compressionLevel);
                string compressionDesc = compressionLevel switch
                {
                    0 => "Store (no compression)",
                    1 => "Fast (level 6)",
                    2 => "Maximum (level 9)",
                    _ => "Default"
                };

                log.Info($"  {allFiles.Count} file(s) | {FormatBytes(totalBytes)} | ZIP level {zipLevel} ({compressionDesc})");

                long processedBytes = 0;

                await Task.Run(() =>
                {
                    using var fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
                    using var zip = new ZipOutputStream(fs);
                    zip.SetLevel(zipLevel);

                    // Manifest goes first — stub reads it before extracting anything else
                    AddFileToZipSync(zip, manifestPath, "packitmeta.json", ZipEpoch);

                    var installers = allFiles
                        .Where(f => !Path.GetFileName(f).Equals("packitmeta.json", StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    for (int i = 0; i < installers.Count; i++)
                    {
                        ct.ThrowIfCancellationRequested();

                        var filePath = installers[i];
                        var entryName = Path.GetRelativePath(tempDir, filePath);
                        var fileSize = new FileInfo(filePath).Length;

                        AddFileToZipSync(zip, filePath, entryName, ZipEpoch);

                        processedBytes += fileSize;
                        int pct = 30 + (int)(processedBytes / (double)totalBytes * 35);
                        Report(progress, Math.Min(pct, 65),
                            $"Step 4 of 6 — Compressing {Path.GetFileName(filePath)} ({i + 1}/{installers.Count})...");
                    }

                    zip.Finish();
                }, ct);

                var zipInfo = new FileInfo(zipPath);
                if (!zipInfo.Exists || zipInfo.Length == 0)
                    throw new InvalidOperationException("ZIP creation failed — output file is empty.");

                log.Info($"  ZIP: {FormatBytes(zipInfo.Length)} ({zipInfo.Length * 100.0 / Math.Max(totalBytes, 1):F1}% of original)");

                // STEP 5: Inject payload into the stub executable
                Report(progress, 68, "Step 5 of 6 — Injecting payload into stub...");
                log.Info("STEP 5: Injecting payload...");

                string stubPath = StubLocator.FindStubInstaller(log);
                log.Info($"  Stub: {stubPath} ({FormatBytes(new FileInfo(stubPath).Length)})");

                finalTemp = Path.GetTempFileName();

                await Task.Run(() => ResourceInjector.InjectPayload(stubPath, zipPath, finalTemp, ct), ct);

                if (!ResourceInjector.VerifyPackagedExe(finalTemp))
                    throw new InvalidOperationException("Package verification failed after injection.");

                log.Info("  Injection verified ✓");

                // STEP 6: Move to final output path
                Report(progress, 92, "Step 6 of 6 — Finalizing...");
                log.Info("STEP 6: Writing output...");

                string outputPath = Path.Combine(outputDirectory, $"{packageName}.exe");

                if (File.Exists(outputPath))
                {
                    try { File.Delete(outputPath); }
                    catch (IOException ex)
                    {
                        throw new IOException(
                            $"Cannot overwrite '{outputPath}' — it may be open in another program.", ex);
                    }
                }

                File.Move(finalTemp, outputPath, overwrite: true);
                finalTemp = null;

                log.Info($"  Output: {outputPath} ({FormatBytes(new FileInfo(outputPath).Length)})");
                Report(progress, 100, "✅ Package created successfully!");
                log.Info("========== PACKAGE CREATION SUCCESS ==========");

                return outputPath;
            }
            catch (OperationCanceledException)
            {
                log.Warning("Package creation cancelled by user.");
                throw;
            }
            catch (Exception ex)
            {
                log.Error("Package creation failed", ex);
                throw;
            }
            finally
            {
                TryDelete(tempDir, isDir: true, log);
                TryDelete(zipPath, isDir: false, log);
                TryDelete(finalTemp, isDir: false, log);
            }
        }

        // Embedded winget updater script. No external file dependency.
        private static string WingetUpdaterScript() =>
            """
            @echo off
            echo ============================================
            echo  PackItPro - Winget Updater
            echo  Updating all installed applications...
            echo ============================================
            echo.
            where winget >nul 2>&1
            if %ERRORLEVEL% NEQ 0 (
                echo ERROR: winget is not installed or not in PATH.
                echo Please install the App Installer from the Microsoft Store.
                pause
                exit /b 1
            )
            echo Running: winget upgrade --all --silent --accept-source-agreements
            echo.
            winget upgrade --all --silent --accept-source-agreements --accept-package-agreements
            echo.
            echo ============================================
            echo  Update complete.
            echo ============================================
            pause
            """;

        private static void AddFileToZipSync(
            ZipOutputStream zip, string filePath, string entryName, DateTime timestamp)
        {
            var entry = new ZipEntry(entryName)
            {
                DateTime = timestamp,
                Size = new FileInfo(filePath).Length,
            };
            zip.PutNextEntry(entry);

            using var src = File.OpenRead(filePath);
            var buffer = new byte[81920];
            int read;
            while ((read = src.Read(buffer, 0, buffer.Length)) > 0)
                zip.Write(buffer, 0, read);

            zip.CloseEntry();
        }

        private static void TryDelete(string? path, bool isDir, ILogService log)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                if (isDir && Directory.Exists(path)) Directory.Delete(path, recursive: true);
                if (!isDir && File.Exists(path)) File.Delete(path);
            }
            catch (Exception ex) { log.Warning($"Cleanup failed for '{path}': {ex.Message}"); }
        }

        private static void Report(IProgress<(int, string)>? p, int pct, string msg)
            => p?.Report((pct, msg));

        private static string FormatBytes(long b)
        {
            if (b == 0) return "0 B";
            string[] s = { "B", "KB", "MB", "GB", "TB" };
            double v = b; int o = 0;
            while (v >= 1024 && o < s.Length - 1) { o++; v /= 1024; }
            return $"{v:0.##} {s[o]}";
        }
    }
}