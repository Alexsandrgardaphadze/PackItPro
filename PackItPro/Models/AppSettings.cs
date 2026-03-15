// PackItPro/Models/AppSettings.cs
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

        /// <summary>
        /// When true, a VirusTotal scan is triggered automatically as soon as files
        /// are added (via browse dialog or drag-and-drop). Requires ScanWithVirusTotal
        /// to be true and a valid API key to be stored — both are checked at call-time.
        /// Default false: users who add many files at once shouldn't be surprised by
        /// an immediate scan eating their API quota.
        /// </summary>
        public bool ScanOnAdd { get; set; } = false;

        /// <summary>
        /// True after the user has accepted the packaging disclaimer.
        /// Once set, the disclaimer dialog is suppressed on subsequent packs.
        /// Reset to false on major version upgrades if the disclaimer text changes.
        /// NOTE: Set to true here so VM testing is not blocked by the dialog.
        ///       Change back to false before shipping to end users.
        /// </summary>
        public bool DisclaimerAccepted { get; set; } = false;

        // Kept for backward compatibility
        public bool UseLZMACompression
        {
            get => CompressionMethod == CompressionMethodEnum.Maximum;
            set => CompressionMethod = value ? CompressionMethodEnum.Maximum : CompressionMethodEnum.Fast;
        }

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