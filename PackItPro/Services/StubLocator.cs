// PackItPro/Services/StubLocator.cs
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace PackItPro.Services
{
    public static class StubLocator
    {
        // Logical resource name assigned by MSBuild for:
        //   PackItPro\Resources\StubInstaller.exe  declared as EmbeddedResource
        private const string ResourceName = "PackItPro.Resources.StubInstaller.exe";

        private static readonly string CacheDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PackItPro", "Cache");

        private static readonly string CachedStubPath =
            Path.Combine(CacheDir, "StubInstaller.exe");

        /// <summary>
        /// Returns the path to a ready-to-use StubInstaller.exe.
        /// Strategy (in order):
        ///   1. Embedded resource — extract to Cache\ if missing or hash changed.
        ///   2. File-system probe — Resources\ next to the exe (dev / Content layout).
        /// Throws InvalidOperationException if the stub cannot be located.
        /// </summary>
        public static string FindStubInstaller(ILogService? log)
        {
            // 1. Embedded resource
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(ResourceName);

            if (stream != null)
            {
                Directory.CreateDirectory(CacheDir);

                // Stream directly to disk instead of loading into RAM first.
                // The self-contained stub is ~90 MB — a ReadFully() allocation
                // would put 90 MB on the LOH every pack operation.
                if (!File.Exists(CachedStubPath) || !StubHashMatches(stream, CachedStubPath, log))
                {
                    stream.Position = 0; // reset after hash check
                    log?.Info($"[StubLocator] Extracting stub to cache: {CachedStubPath}");
                    string tmpPath = CachedStubPath + ".tmp";
                    try
                    {
                        using (var fs = new FileStream(
                            tmpPath, FileMode.Create, FileAccess.Write,
                            FileShare.None, bufferSize: 81920))
                        {
                            stream.CopyTo(fs);
                        }
                        File.Move(tmpPath, CachedStubPath, overwrite: true);
                    }
                    catch
                    {
                        try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                        throw;
                    }
                }
                else
                {
                    log?.Debug("[StubLocator] Using cached stub (hash match)");
                }

                return CachedStubPath;
            }

            // 2. Legacy file-system probe (dev builds)
            string? exeDir = Path.GetDirectoryName(Environment.ProcessPath);
            if (exeDir != null)
            {
                string legacy = Path.Combine(exeDir, "Resources", "StubInstaller.exe");
                if (File.Exists(legacy))
                {
                    log?.Info($"[StubLocator] Using file-system stub: {legacy}");
                    return legacy;
                }
            }

            throw new InvalidOperationException(
                "StubInstaller.exe not found.\n\n" +
                "Developers: run .\\build.ps1 to publish and copy StubInstaller to Resources\\\n" +
                "Release builds: ensure StubInstaller.exe is an EmbeddedResource in PackItPro.csproj");
        }

        /// <summary>
        /// Returns true if the embedded stream hash matches the cached file on disk.
        /// Reads both streams without loading either fully into memory.
        /// </summary>
        private static bool StubHashMatches(Stream embedded, string cachedPath, ILogService? log)
        {
            try
            {
                string embeddedHash = ComputeStreamHash(embedded);
                string cachedHash = ComputeFileHash(cachedPath);
                return embeddedHash == cachedHash;
            }
            catch (Exception ex)
            {
                log?.Warning($"[StubLocator] Hash check failed: {ex.Message} — will re-extract");
                return false;
            }
        }

        private static string ComputeStreamHash(Stream stream)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(stream));
        }

        private static string ComputeFileHash(string path)
        {
            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                return Convert.ToHexString(sha.ComputeHash(fs));
            }
            catch { return string.Empty; }
        }
    }
}