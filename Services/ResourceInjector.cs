using System;
using System.IO;
using System.Text;

namespace PackItPro.Services
{
    public static class ResourceInjector
    {
        private const string PAYLOAD_MARKER = "PACKIT_END";
        private const int SIZE_LENGTH = sizeof(long);

        public static void InjectPayload(string stubPath, string payloadZipPath, string outputPath)
        {
            File.Copy(stubPath, outputPath, overwrite: true);

            var payloadBytes = File.ReadAllBytes(payloadZipPath);
            var payloadSize = payloadBytes.Length;

            using var fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write);

            // Write payload size (Int64)
            var sizeBytes = BitConverter.GetBytes((long)payloadSize);
            fs.Write(sizeBytes, 0, sizeBytes.Length);

            // Write marker
            var markerBytes = Encoding.ASCII.GetBytes(PAYLOAD_MARKER);
            fs.Write(markerBytes, 0, markerBytes.Length);
        }
    }
}
