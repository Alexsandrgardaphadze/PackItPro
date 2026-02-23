// PackItPro/Models/AppSettings.cs - v2.3 IMPROVED
using System;

namespace PackItPro.Models
{
    public class AppSettings
    {
        public string OutputLocation { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public string OutputFileName { get; set; } = "MyPackage";
        public string VirusTotalApiKey { get; set; } = "";
        public bool OnlyScanExecutables { get; set; } = true;
        public bool AutoRemoveInfectedFiles { get; set; } = true;
        public int MinimumDetectionsToFlag { get; set; } = 1;
        public bool IncludeWingetUpdateScript { get; set; } = false;

        // FIX: Use enum instead of magic numbers (0, 1, 2)
        // Old: public int CompressionLevel { get; set; } = 1;
        public CompressionMethodEnum CompressionMethod { get; set; } = CompressionMethodEnum.Fast;

        // Kept for backward compatibility if settings are already saved with old field
        // Maps old int value to new enum
        public int CompressionLevel
        {
            get => CompressionMethod switch
            {
                CompressionMethodEnum.None => 0,
                CompressionMethodEnum.Fast => 1,
                CompressionMethodEnum.Normal => 2,
                CompressionMethodEnum.Maximum => 3,
                _ => 1
            };
            set => CompressionMethod = value switch
            {
                0 => CompressionMethodEnum.None,
                1 => CompressionMethodEnum.Fast,
                2 => CompressionMethodEnum.Normal,
                3 => CompressionMethodEnum.Maximum,
                _ => CompressionMethodEnum.Fast
            };
        }

        public bool RequiresAdmin { get; set; } = false;
        public bool VerifyIntegrity { get; set; } = true;
        public bool ScanWithVirusTotal { get; set; } = true;
        public int MaxFilesInList { get; set; } = 20;

        // DEPRECATED: UseLZMACompression — use CompressionMethod instead
        // Kept for backward compatibility
        public bool UseLZMACompression
        {
            get => CompressionMethod == CompressionMethodEnum.Maximum;
            set => CompressionMethod = value ? CompressionMethodEnum.Maximum : CompressionMethodEnum.Fast;
        }
    }
}