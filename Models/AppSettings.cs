// AppSettings.cs
using System;

namespace PackItPro.Models
{
    public class AppSettings
    {
        public string OutputLocation { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public string VirusTotalApiKey { get; set; } = "";
        public bool OnlyScanExecutables { get; set; } = true;
        public bool AutoRemoveInfectedFiles { get; set; } = true;
        public int MinimumDetectionsToFlag { get; set; } = 1;
        public bool IncludeWingetUpdateScript { get; set; } = false; // New setting
        public bool UseLZMACompression { get; set; } = true; // New setting
        public bool RequiresAdmin { get; set; } = false; // NEW: Add setting for overall package admin requirement
        public bool VerifyIntegrity { get; set; } = true;

    }
}