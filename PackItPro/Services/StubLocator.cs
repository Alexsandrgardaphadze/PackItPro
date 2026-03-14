// PackItPro/Services/StubLocator.cs - v2.2
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
                byte[] embedded = ReadFully(stream);
                string embeddedHash = ComputeHash(embedded);

                if (!File.Exists(CachedStubPath) ||
                    ComputeFileHash(CachedStubPath) != embeddedHash)
                {
                    log?.Info($"[StubLocator] Extracting stub ({embedded.Length / 1024} KB) to cache");
                    File.WriteAllBytes(CachedStubPath, embedded);
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

        private static byte[] ReadFully(Stream stream)
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ms.ToArray();
        }

        private static string ComputeHash(byte[] data)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(data));
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