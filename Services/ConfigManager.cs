using MelonLoader;
using MLVScan.Models;

namespace MLVScan.Services
{
    public class ConfigManager
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

        public ConfigManager(MelonLogger.Instance logger)
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

                _enableAutoScan.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableAutoDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _minSeverityForDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _scanDirectories.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _suspiciousThreshold.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _whitelistedHashes.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _dumpFullIlReports.OnEntryValueChanged.Subscribe(OnConfigChanged);

                UpdateConfigFromPreferences();

                _logger.Msg("Configuration loaded successfully");
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to initialize config system: {ex.Message}");
                _logger.Msg("Using fallback in-memory configuration");
                Config = new ScanConfig();
            }
        }

        public ScanConfig Config { get; private set; }

        private void OnConfigChanged<T>(T oldValue, T newValue)
        {
            UpdateConfigFromPreferences();
            _logger.Msg("Configuration updated");
        }

        private void UpdateConfigFromPreferences()
        {
            Config = new ScanConfig
            {
                EnableAutoScan = _enableAutoScan.Value,
                EnableAutoDisable = _enableAutoDisable.Value,
                MinSeverityForDisable = ParseSeverity(_minSeverityForDisable.Value),
                ScanDirectories = _scanDirectories.Value,
                SuspiciousThreshold = _suspiciousThreshold.Value,
                WhitelistedHashes = _whitelistedHashes.Value,
                DumpFullIlReports = _dumpFullIlReports.Value
            };
        }

        public void SaveConfig(ScanConfig newConfig)
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
