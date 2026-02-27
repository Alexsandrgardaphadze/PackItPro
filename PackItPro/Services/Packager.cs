// PackItPro/Services/Packager.cs - v2.2
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
    // FIX: Static event removed entirely — it accumulates handlers across packaging
    // operations, leaking memory. Callers use IProgress<> instead.
    // public static event ProgressReportHandler? ProgressChanged;  ← DELETED

    public static class Packager
    {
        // Deterministic ZIP timestamp — same content always produces same bytes.
        // Professional packagers (NuGet, npm, Debian) do this.
        private static readonly DateTime ZipEpoch = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static async Task<string> CreatePackageAsync(
            List<string> filePaths,
            string outputDirectory,
            string packageName,
            bool requiresAdmin,
            bool useLZMACompression,
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
                Report(progress, 5, "Preparing files...");
                log.Info("========== PACKAGE CREATION START ==========");
                log.Info($"Package: '{packageName}' | Files: {filePaths.Count} | Admin: {requiresAdmin}");

                // ============================================================
                // STEP 1: COPY FILES TO TEMP
                // ============================================================
                Report(progress, 8, "Copying files...");
                log.Info($"STEP 1: Copying {filePaths.Count} file(s)...");

                for (int i = 0; i < filePaths.Count; i++)
                {
                    ct.ThrowIfCancellationRequested();

                    string src = filePaths[i];
                    string dest = Path.Combine(tempDir, Path.GetFileName(src));

                    try
                    {
                        // Verify accessible before committing to copy
                        using (File.Open(src, FileMode.Open, FileAccess.Read, FileShare.Read)) { }
                        File.Copy(src, dest, overwrite: true);
                        log.Info($"  [{i + 1}/{filePaths.Count}] {Path.GetFileName(src)} ({FormatBytes(new FileInfo(src).Length)})");
                        Report(progress, 8 + (int)((i + 1.0) / filePaths.Count * 12),
                            $"Copying files ({i + 1}/{filePaths.Count})...");
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        throw new UnauthorizedAccessException(
                            $"Access denied to '{Path.GetFileName(src)}'. " +
                            "Check file permissions or run PackItPro as Administrator.", ex);
                    }
                    catch (IOException ex)
                    {
                        // FIX: Catch all IOExceptions (not just sharing violations) and
                        // give an actionable message for whichever error occurred.
                        throw new IOException(
                            $"Cannot read '{Path.GetFileName(src)}': {ex.Message}\n" +
                            "Ensure the file is not locked by another program.", ex);
                    }
                }

                // ============================================================
                // STEP 2: GENERATE MANIFEST (no checksum yet)
                // ============================================================
                Report(progress, 20, "Generating manifest...");
                log.Info("STEP 2: Generating manifest...");

                var manifestJson = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin);
                var manifestPath = Path.Combine(tempDir, "packitmeta.json");
                await File.WriteAllTextAsync(manifestPath, manifestJson, ct);
                log.Info("  Manifest written (checksum pending).");

                // ============================================================
                // STEP 3: HASH INSTALLER FILES ONLY
                // FileHasher.DefaultExclusions permanently skips packitmeta.json
                // and install.log — no extra args needed.
                // SHA256 over hundreds of MB is CPU-bound, run on thread pool.
                // ============================================================
                Report(progress, 25, "Computing integrity hash...");
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

                // ============================================================
                // STEP 4: CREATE ZIP ARCHIVE
                // SharpZipLib is synchronous — mixing async reads with sync ZIP
                // writes creates fake async that blocks the thread pool.
                // We push the ENTIRE compression work onto a background thread.
                // ============================================================
                Report(progress, 30, "Creating ZIP archive...");
                log.Info("STEP 4: Compressing payload...");

                zipPath = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");

                var allFiles = Directory.GetFiles(tempDir, "*", SearchOption.AllDirectories).ToList();
                long totalBytes = allFiles.Sum(f => new FileInfo(f).Length);
                int level = useLZMACompression ? 9 : 6;

                log.Info($"  {allFiles.Count} file(s) | {FormatBytes(totalBytes)} | level {level}");

                long processedBytes = 0;

                await Task.Run(() =>
                {
                    using var fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
                    using var zip = new ZipOutputStream(fs);
                    zip.SetLevel(level);

                    // Manifest first — stub needs it before anything else
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
                            $"Compressing {Path.GetFileName(filePath)} ({i + 1}/{installers.Count})...");
                    }

                    zip.Finish();
                }, ct);

                var zipInfo = new FileInfo(zipPath);
                if (!zipInfo.Exists || zipInfo.Length == 0)
                    throw new InvalidOperationException("ZIP creation failed — output file is empty.");

                log.Info($"  ZIP: {FormatBytes(zipInfo.Length)} ({zipInfo.Length * 100.0 / Math.Max(totalBytes, 1):F1}% of original)");

                // ============================================================
                // STEP 5: INJECT PAYLOAD INTO STUB
                // ============================================================
                Report(progress, 68, "Injecting payload into stub...");
                log.Info("STEP 5: Injecting payload...");

                string stubPath = StubLocator.FindStubInstaller(log);
                log.Info($"  Stub: {stubPath} ({FormatBytes(new FileInfo(stubPath).Length)})");

                finalTemp = Path.GetTempFileName();

                await Task.Run(() => ResourceInjector.InjectPayload(stubPath, zipPath, finalTemp, ct), ct);

                if (!ResourceInjector.VerifyPackagedExe(finalTemp))
                    throw new InvalidOperationException("Package verification failed after injection.");

                log.Info("  Injection verified ✓");

                // ============================================================
                // STEP 6: MOVE TO FINAL LOCATION
                // ============================================================
                Report(progress, 92, "Finalizing...");
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
                finalTemp = null; // consumed — don't delete in finally

                log.Info($"  Output: {outputPath} ({FormatBytes(new FileInfo(outputPath).Length)})");
                Report(progress, 100, "Package created successfully!");
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

        // ──────────────────────────────────────────────────────────────
        // Sync ZIP helper — must be called from inside Task.Run
        // ──────────────────────────────────────────────────────────────

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

        // ──────────────────────────────────────────────────────────────
        // Helpers
        // ──────────────────────────────────────────────────────────────

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
        {
            p?.Report((pct, msg));
        }

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