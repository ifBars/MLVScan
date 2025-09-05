namespace MLVScan.Models
{
    public class ScanConfig
    {
        // Enable/disable automatic scanning at startup
        public bool EnableAutoScan { get; set; } = true;

        // Enable/disable automatic disabling of suspicious mods
        public bool EnableAutoDisable { get; set; } = true;

        // Minimum severity level to trigger disabling
        public string MinSeverityForDisable { get; set; } = "Medium";

        // Where to scan for mods
        public string[] ScanDirectories { get; set; } = ["Mods", "Plugins"];

        // How many suspicious findings before disabling a mod
        public int SuspiciousThreshold { get; set; } = 1;

        // Mods to whitelist (will be skipped during scanning)
        public string[] WhitelistedMods { get; set; } = [];
    }
}