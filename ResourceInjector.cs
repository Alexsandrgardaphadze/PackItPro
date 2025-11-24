// ResourceInjector.cs
using System;
using System.IO;

namespace PackItPro
{
    public static class ResourceInjector
    {
        // Appends the payload zip to the stub executable
        public static void InjectPayload(string stubPath, string payloadZipPath, string outputPath)
        {
            // Step 1: Copy the stub to the output path
            File.Copy(stubPath, outputPath, overwrite: true);

            // Step 2: Read the payload zip data
            var payloadBytes = File.ReadAllBytes(payloadZipPath);

            // Step 3: Append payload, size, and marker to the output file
            var payloadSize = payloadBytes.Length;
            var payloadSizeBytes = BitConverter.GetBytes(payloadSize);
            var magicMarker = System.Text.Encoding.UTF8.GetBytes("PACKIT_END"); // 10-byte marker

            using (var fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write))
            {
                fs.Write(payloadBytes, 0, payloadBytes.Length);      // payload data
                fs.Write(payloadSizeBytes, 0, payloadSizeBytes.Length); // payload size
                fs.Write(magicMarker, 0, magicMarker.Length);       // marker
            }
        }
    }
}
