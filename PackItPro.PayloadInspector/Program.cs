using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;

namespace PackItPro
{
    public class Packager
    {
        private const string MARKER = "PACKIT_END";

        public async Task<bool> PackAsync(string stubPath, string outputPath, List<string> payloadFiles, IProgress<string> progress = null)
        {
            try
            {
                progress?.Report("Step 1: Reading stub EXE...");
                byte[] stubBytes = await File.ReadAllBytesAsync(stubPath);
                progress?.Report($"Stub EXE size: {stubBytes.Length} bytes");

                progress?.Report("Step 2: Creating ZIP archive in memory for payload files...");
                byte[] payloadBytes;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (ZipArchive zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
                    {
                        int count = 0;
                        foreach (var file in payloadFiles)
                        {
                            count++;
                            progress?.Report($"Adding file to ZIP ({count}/{payloadFiles.Count}): {file}");
                            var entry = zip.CreateEntry(Path.GetFileName(file), CompressionLevel.Optimal);
                            using (var entryStream = entry.Open())
                            using (var fileStream = File.OpenRead(file))
                            {
                                await fileStream.CopyToAsync(entryStream);
                            }
                        }
                    }
                    payloadBytes = ms.ToArray();
                }

                byte[] markerBytes = Encoding.ASCII.GetBytes(MARKER);
                progress?.Report($"ZIP payload size: {payloadBytes.Length} bytes");
                progress?.Report($"Marker: {MARKER} ({markerBytes.Length} bytes)");

                progress?.Report("Step 3: Writing final packed EXE...");
                using (FileStream fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                {
                    // 1️⃣ write stub
                    await fs.WriteAsync(stubBytes, 0, stubBytes.Length);

                    // 2️⃣ write payload
                    await fs.WriteAsync(payloadBytes, 0, payloadBytes.Length);

                    // 3️⃣ write marker
                    await fs.WriteAsync(markerBytes, 0, markerBytes.Length);

                    await fs.FlushAsync();
                }

                progress?.Report("Packing completed successfully!");
                progress?.Report($"Stub size: {stubBytes.Length} bytes");
                progress?.Report($"Payload size: {payloadBytes.Length} bytes");
                progress?.Report($"Marker size: {markerBytes.Length} bytes");
                progress?.Report($"Total output size: {new FileInfo(outputPath).Length} bytes");

                // Optional: verify marker
                if (!VerifyMarker(outputPath))
                    throw new InvalidOperationException("Marker verification failed!");

                return true;
            }
            catch (Exception ex)
            {
                progress?.Report("Error during packing: " + ex.Message);
                return false;
            }
        }

        private bool VerifyMarker(string outputPath)
        {
            byte[] markerBytes = Encoding.ASCII.GetBytes(MARKER);
            using (FileStream fs = new FileStream(outputPath, FileMode.Open, FileAccess.Read))
            {
                if (fs.Length < markerBytes.Length) return false;
                fs.Seek(-markerBytes.Length, SeekOrigin.End);
                byte[] check = new byte[markerBytes.Length];
                fs.Read(check, 0, check.Length);
                for (int i = 0; i < markerBytes.Length; i++)
                {
                    if (check[i] != markerBytes[i]) return false;
                }
                return true;
            }
        }
    }
}
