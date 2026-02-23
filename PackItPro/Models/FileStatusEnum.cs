// PackItPro/Models/Models.cs - v2.3 UPDATED
namespace PackItPro.Models
{
    /// <summary>
    /// Status of a file in the package list
    /// </summary>
    public enum FileStatusEnum
    {
        Pending,      // Not yet scanned
        Clean,        // Scanned, no threats
        Infected,     // Detected threats
        ScanFailed,   // Scan error
        Skipped       // Skipped (e.g., non-executable when OnlyScanExecutables=true)
    }

    /// <summary>
    /// Compression method for ZIP archive
    /// Maps to SharpZipLib compression levels:
    /// - None: 0 (store only, no compression)
    /// - Fast: 6 (good balance)
    /// - Normal: 7 (better compression)
    /// - Maximum: 9 (best compression, slowest)
    /// </summary>
    public enum CompressionMethodEnum
    {
        None = 0,      // No compression
        Fast = 1,      // Fast compression (level 6)
        Normal = 2,    // Normal compression (level 7)
        Maximum = 3    // Maximum compression (level 9)
    }
}