// PackItPro/Models/AppSettings.cs
using System;

namespace PackItPro.Models
{
    public class AppSettings
    {
        public string OutputLocation { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        public string OutputFileName { get; set; } = "MyPackage"; //  NEW
        public string VirusTotalApiKey { get; set; } = "";
        public bool OnlyScanExecutables { get; set; } = true;
        public bool AutoRemoveInfectedFiles { get; set; } = true;
        public int MinimumDetectionsToFlag { get; set; } = 1;
        public bool IncludeWingetUpdateScript { get; set; } = false;
        public bool UseLZMACompression { get; set; } = true;
        public bool RequiresAdmin { get; set; } = false;
        public bool VerifyIntegrity { get; set; } = true;
        public bool ScanWithVirusTotal { get; set; } = true; // NEW
    }
}