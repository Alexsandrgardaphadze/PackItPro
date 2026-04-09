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
        public bool DisclaimerAccepted { get; set; } = false;
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

        /// <summary>When true the light theme is active; false = dark (default).</summary>
        public bool UseLightTheme { get; set; } = false;

        /// <summary>
        /// Display name of the last used theme ("Dark", "Light", or a custom pack name).
        /// Persisted to settings.json and restored on startup.
        /// </summary>
        public string ThemeName { get; set; } = "Dark";

        /// <summary>
        /// List of recently created package paths, up to 5 most recent.
        /// Used in the File menu for quick access to recent packages.
        /// </summary>
        public List<string> RecentPackages { get; set; } = new();

        /// <summary>
        /// Adds a package path to the recent list, removing duplicates and keeping only 5 most recent.
        /// </summary>
        public void AddRecentPackage(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            RecentPackages.Remove(path); // remove duplicate
            RecentPackages.Insert(0, path);
            if (RecentPackages.Count > 5)
                RecentPackages.RemoveRange(5, RecentPackages.Count - 5);
        }
    }
}