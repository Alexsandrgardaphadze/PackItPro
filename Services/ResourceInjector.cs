// PackItPro/Services/ResourceInjector.cs
using System;
using System.IO;
using System.Text;

namespace PackItPro.Services
{
    public static class ResourceInjector
    {
        private const string PAYLOAD_MARKER = "PACKIT_END";
        private const int MARKER_LENGTH = 10;
        private const int SIZE_LENGTH = 8; // sizeof(long)

        public static void InjectPayload(string stubPath, string payloadZipPath, string outputPath)
        {
            // Copy stub to output
            File.Copy(stubPath, outputPath, overwrite: true);

            // Read payload
            var payloadBytes = File.ReadAllBytes(payloadZipPath);
            var payloadSize = payloadBytes.Length;

            // Write footer: [payload][size (8 bytes)][marker (10 bytes)]
            using var fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write);

            // Write payload size as little-endian long
            var sizeBytes = BitConverter.GetBytes(payloadSize);
            fs.Write(sizeBytes, 0, SIZE_LENGTH);

            // Write marker as ASCII bytes
            var markerBytes = Encoding.ASCII.GetBytes(PAYLOAD_MARKER);
            fs.Write(markerBytes, 0, MARKER_LENGTH);
        }
    }
}