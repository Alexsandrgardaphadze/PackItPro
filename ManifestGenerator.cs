using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace PackItPro
{
    public static class ManifestGenerator
    {
        public static string Generate(List<string> filePaths, string packageName, bool requiresAdmin)
        {
            var files = filePaths.Select((path, index) => new
            {
                name = Path.GetFileName(path),
                installType = DetectType(path),
                silentArgs = (string[]?)null,
                requiresAdmin = false,
                installOrder = index + 1,
                timeoutMinutes = 10
            }).ToList();

            var manifest = new
            {
                version = "1.0",
                packageName,
                sha256Checksum = "",
                files,
                autoUpdateScript = (string?)null,
                requiresAdmin,
                cleanup = true
            };

            return JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        }

        private static string DetectType(string filePath)
        {
            var ext = Path.GetExtension(filePath).ToLower();
            if (ext == ".msi") return "msi";
            if (ext == ".exe")
            {
                try
                {
                    var bytes = File.ReadAllBytes(filePath).Take(8192).ToArray();
                    var text = System.Text.Encoding.ASCII.GetString(bytes);
                    if (text.Contains("Inno Setup")) return "innosetup";
                    if (text.Contains("Nullsoft Install")) return "nsis";
                }
                catch { }
            }
            return "exe";
        }
    }
}