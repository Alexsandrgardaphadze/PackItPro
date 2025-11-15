using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace PackItPro
{
    public static class Packager
    {
        public static async Task<string> CreatePackageAsync(
            List<string> filePaths,
            string outputDirectory,
            string packageName,
            bool requiresAdmin)
        {
            var tempDir = Path.Combine(Path.GetTempPath(), $"PackItPro_{Guid.NewGuid()}");
            string? payloadZip = null;

            try
            {
                Directory.CreateDirectory(tempDir);

                // Copy files
                foreach (var file in filePaths)
                {
                    File.Copy(file, Path.Combine(tempDir, Path.GetFileName(file)));
                }

                // Generate manifest
                var manifest = ManifestGenerator.Generate(filePaths, packageName, requiresAdmin);
                await File.WriteAllTextAsync(Path.Combine(tempDir, "packitmeta.json"), manifest);

                // Create payload.zip
                payloadZip = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid()}.zip");
                ZipFile.CreateFromDirectory(tempDir, payloadZip);

                // Calculate checksum
                var checksum = ComputeSHA256(payloadZip);

                // Update manifest with checksum
                var manifestObj = JsonSerializer.Deserialize<Dictionary<string, object>>(manifest);
                manifestObj["sha256Checksum"] = checksum;
                await File.WriteAllTextAsync(
                    Path.Combine(tempDir, "packitmeta.json"),
                    JsonSerializer.Serialize(manifestObj, new JsonSerializerOptions { WriteIndented = true })
                );

                // Recreate zip with updated manifest
                File.Delete(payloadZip);
                ZipFile.CreateFromDirectory(tempDir, payloadZip);

                // Inject into stub
                var stubPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubInstaller.exe");
                if (!File.Exists(stubPath))
                    throw new FileNotFoundException("StubInstaller.exe not found in application directory");

                var outputPath = Path.Combine(outputDirectory, $"{packageName}.packitexe");
                ResourceInjector.InjectPayload(stubPath, payloadZip, outputPath);

                return outputPath;
            }
            finally
            {
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
                if (payloadZip != null && File.Exists(payloadZip)) File.Delete(payloadZip);
            }
        }

        private static string ComputeSHA256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return Convert.ToBase64String(sha.ComputeHash(stream));
        }
    }
}