using System;
using System.Linq;
using MelonLoader;
using MLVScan.Abstractions;
using MLVScan.Models;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader implementation of IConfigManager using MelonPreferences.
    /// </summary>
    public class MelonConfigManager : IConfigManager
    {
        private readonly MelonLogger.Instance _logger;
        private readonly MelonPreferences_Category _category;

        private readonly MelonPreferences_Entry<bool> _enableAutoScan;
        private readonly MelonPreferences_Entry<bool> _enableAutoDisable;
        private readonly MelonPreferences_Entry<string> _minSeverityForDisable;
        private readonly MelonPreferences_Entry<string[]> _scanDirectories;
        private readonly MelonPreferences_Entry<int> _suspiciousThreshold;
        private readonly MelonPreferences_Entry<string[]> _whitelistedHashes;
        private readonly MelonPreferences_Entry<bool> _dumpFullIlReports;
        private readonly MelonPreferences_Entry<bool> _developerMode;
        private readonly MelonPreferences_Entry<bool> _enableReportUpload;
        private readonly MelonPreferences_Entry<bool> _reportUploadConsentAsked;
        private readonly MelonPreferences_Entry<string> _reportUploadApiBaseUrl;

        public MelonConfigManager(MelonLogger.Instance logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            try
            {
                _category = MelonPreferences.CreateCategory("MLVScan");

                _enableAutoScan = _category.CreateEntry("EnableAutoScan", true,
                    description: "Whether to scan mods at startup");

                _enableAutoDisable = _category.CreateEntry("EnableAutoDisable", true,
                    description: "Whether to disable suspicious mods");

                _minSeverityForDisable = _category.CreateEntry("MinSeverityForDisable", "Medium",
                    description: "Minimum severity level to trigger disabling (Low, Medium, High, Critical)");

                _scanDirectories = _category.CreateEntry("ScanDirectories", new[] { "Mods", "Plugins" },
                    description: "Directories to scan for mods");

                _suspiciousThreshold = _category.CreateEntry("SuspiciousThreshold", 1,
                    description: "How many suspicious findings required before disabling a mod");

                _whitelistedHashes = _category.CreateEntry("WhitelistedHashes", Array.Empty<string>(),
                    description: "List of mod SHA256 hashes to skip when scanning");

                _dumpFullIlReports = _category.CreateEntry("DumpFullIlReports", false,
                    description: "When enabled, saves full IL dumps for scanned mods next to reports");

                _developerMode = _category.CreateEntry("DeveloperMode", false,
                    description: "Developer mode: Shows remediation guidance to help mod developers fix false positives");

                _enableReportUpload = _category.CreateEntry("EnableReportUpload", false,
                    description: "When enabled (and consent given), send reports to MLVScan API for false positive analysis");

                _reportUploadConsentAsked = _category.CreateEntry("ReportUploadConsentAsked", false,
                    description: "Whether the first-run consent prompt has been shown (internal)");

                _reportUploadApiBaseUrl = _category.CreateEntry("ReportUploadApiBaseUrl", "https://api.mlvscan.com",
                    description: "API base URL for report uploads");

                _enableAutoScan.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableAutoDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _minSeverityForDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _scanDirectories.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _suspiciousThreshold.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _whitelistedHashes.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _dumpFullIlReports.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _developerMode.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableReportUpload.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _reportUploadConsentAsked.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _reportUploadApiBaseUrl.OnEntryValueChanged.Subscribe(OnConfigChanged);

                UpdateConfigFromPreferences();

                _logger.Msg("Configuration loaded successfully");
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to initialize config system: {ex.Message}");
                _logger.Msg("Using fallback in-memory configuration");
                Config = new MLVScanConfig();
            }
        }

        public MLVScanConfig Config { get; private set; }

        public MLVScanConfig LoadConfig()
        {
            UpdateConfigFromPreferences();
            return Config;
        }

        private void OnConfigChanged<T>(T oldValue, T newValue)
        {
            UpdateConfigFromPreferences();
            _logger.Msg("Configuration updated");
        }

        private void UpdateConfigFromPreferences()
        {
            Config = new MLVScanConfig
            {
                EnableAutoScan = _enableAutoScan.Value,
                EnableAutoDisable = _enableAutoDisable.Value,
                MinSeverityForDisable = ParseSeverity(_minSeverityForDisable.Value),
                ScanDirectories = _scanDirectories.Value,
                SuspiciousThreshold = _suspiciousThreshold.Value,
                WhitelistedHashes = _whitelistedHashes.Value,
                DumpFullIlReports = _dumpFullIlReports.Value,
                Scan = new ScanConfig
                {
                    DeveloperMode = _developerMode.Value
                },
                EnableReportUpload = _enableReportUpload.Value,
                ReportUploadConsentAsked = _reportUploadConsentAsked.Value,
                ReportUploadApiBaseUrl = _reportUploadApiBaseUrl.Value
            };
        }

        public void SaveConfig(MLVScanConfig newConfig)
        {
            try
            {
                _enableAutoScan.Value = newConfig.EnableAutoScan;
                _enableAutoDisable.Value = newConfig.EnableAutoDisable;
                _minSeverityForDisable.Value = FormatSeverity(newConfig.MinSeverityForDisable);
                _scanDirectories.Value = newConfig.ScanDirectories;
                _suspiciousThreshold.Value = newConfig.SuspiciousThreshold;
                _whitelistedHashes.Value = newConfig.WhitelistedHashes;
                _dumpFullIlReports.Value = newConfig.DumpFullIlReports;
                _developerMode.Value = newConfig.Scan?.DeveloperMode ?? false;
                _enableReportUpload.Value = newConfig.EnableReportUpload;
                _reportUploadConsentAsked.Value = newConfig.ReportUploadConsentAsked;
                _reportUploadApiBaseUrl.Value = newConfig.ReportUploadApiBaseUrl;

                MelonPreferences.Save();

                _logger.Msg("Configuration saved successfully");
            }
            catch (Exception ex)
            {
                _logger.Error($"Error saving configuration: {ex.Message}");
                Config = newConfig;
            }
        }

        public string[] GetWhitelistedHashes()
        {
            return _whitelistedHashes.Value;
        }

        public void SetWhitelistedHashes(string[] hashes)
        {
            if (hashes == null)
                return;

            var normalizedHashes = hashes
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            _whitelistedHashes.Value = normalizedHashes;
            MelonPreferences.Save();

            UpdateConfigFromPreferences();
            _logger.Msg($"Updated whitelist with {normalizedHashes.Length} hash(es)");
        }

        public bool IsHashWhitelisted(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return false;

            return Config.WhitelistedHashes.Contains(hash.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase);
        }

        public string GetReportUploadApiBaseUrl() => _reportUploadApiBaseUrl.Value;

        private static Severity ParseSeverity(string severity)
        {
            if (string.IsNullOrWhiteSpace(severity))
                return Severity.Medium;

            return severity.ToLower() switch
            {
                "critical" => Severity.Critical,
                "high" => Severity.High,
                "medium" => Severity.Medium,
                "low" => Severity.Low,
                _ => Severity.Medium
            };
        }

        private static string FormatSeverity(Severity severity)
        {
            return severity switch
            {
                Severity.Critical => "Critical",
                Severity.High => "High",
                Severity.Medium => "Medium",
                Severity.Low => "Low",
                _ => "Medium"
            };
        }
    }
}
