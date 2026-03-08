using System;
using System.Collections.Generic;

namespace PackItPro.Models
{
    public class AppSettings
    {
        public string OutputLocation { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public string OutputFileName { get; set; } = "MyPackage";
        public bool OnlyScanExecutables { get; set; } = true;
        public bool AutoRemoveInfectedFiles { get; set; } = true;

        // Raised from 1 → 3. A single obscure engine (Zillya, etc.) flagging
        // a well-known NSIS installer is noise, not a threat. Three independent
        // engines agreeing is a much stronger signal.
        public int MinimumDetectionsToFlag { get; set; } = 3;

        public bool IncludeWingetUpdateScript { get; set; } = false;

        public CompressionMethodEnum CompressionMethod { get; set; } = CompressionMethodEnum.Fast;

        // Kept for backward compatibility — maps old int value to new enum.
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

        // Kept for backward compatibility
        public bool UseLZMACompression
        {
            get => CompressionMethod == CompressionMethodEnum.Maximum;
            set => CompressionMethod = value ? CompressionMethodEnum.Maximum : CompressionMethodEnum.Fast;
        }

        // Engines considered authoritative — a single detection from any of these
        // overrides MinimumDetectionsToFlag and flags the file as infected regardless.
        // User-editable so they can add or remove engines via settings UI.
        public List<string> TrustedEngines { get; set; } = new()
        {
            "Microsoft",
            "Google",
            "Kaspersky",
            "DrWeb",
            "BitDefender",
            "ESET-NOD32",
            "Sophos",
            "Symantec",
            "CrowdStrike Falcon",
            "Malwarebytes",
            "Avast",
            "AVG",
            "F-Secure",
            "Trend Micro",
        };
    }
}
