using System;
using System.IO;
using System.Text;

public class PackagerService
{
    private const string PayloadMarker = "###PACKITPRO_PAYLOAD###";

    public void InjectPayloadIntoStub(
        string stubExePath,
        byte[] zipPayload,
        string outputExePath,
        Action<string> log)
    {
        log("========== PAYLOAD INJECTION START ==========");

        if (!File.Exists(stubExePath))
            throw new FileNotFoundException("Stub executable not found", stubExePath);

        if (zipPayload == null || zipPayload.Length == 0)
            throw new InvalidOperationException("ZIP payload is EMPTY");

        log($"ZIP payload size: {zipPayload.Length:N0} bytes");

        // DEBUG: dump payload to disk
        string debugZipPath = Path.Combine(
            Path.GetDirectoryName(outputExePath)!,
            "DEBUG_payload.zip"
        );

        File.WriteAllBytes(debugZipPath, zipPayload);
        log($"DEBUG ZIP written: {debugZipPath}");

        long stubSize = new FileInfo(stubExePath).Length;
        log($"Stub EXE size: {stubSize:N0} bytes");

        using FileStream stubStream = new FileStream(
            stubExePath,
            FileMode.Open,
            FileAccess.Read
        );

        using FileStream outputStream = new FileStream(
            outputExePath,
            FileMode.Create,
            FileAccess.Write
        );

        // 1️⃣ Copy stub EXE
        stubStream.CopyTo(outputStream);
        log("Stub copied to output");

        // 2️⃣ Write payload marker
        byte[] markerBytes = Encoding.UTF8.GetBytes(PayloadMarker);
        outputStream.Write(markerBytes, 0, markerBytes.Length);
        log($"Marker written ({markerBytes.Length} bytes)");

        // 3️⃣ Write payload size (Int64)
        byte[] sizeBytes = BitConverter.GetBytes((long)zipPayload.Length);
        outputStream.Write(sizeBytes, 0, sizeBytes.Length);
        log("Payload size written (Int64)");

        // 4️⃣ Write payload itself
        outputStream.Write(zipPayload, 0, zipPayload.Length);
        log("ZIP payload appended");

        outputStream.Flush();
        outputStream.Close();

        long finalSize = new FileInfo(outputExePath).Length;
        log($"Final EXE size: {finalSize:N0} bytes");

        if (finalSize <= stubSize + 1024)
            throw new InvalidOperationException(
                "FINAL EXE SIZE INVALID — PAYLOAD WAS NOT APPENDED"
            );

        log("========== PAYLOAD INJECTION SUCCESS ==========");
    }
}
