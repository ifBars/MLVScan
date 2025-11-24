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
        private readonly MelonPreferences_Entry<string[]> _whitelistedMods;
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

                _whitelistedMods = _category.CreateEntry("WhitelistedMods", Array.Empty<string>(),
                    description: "List of mod filenames to skip when scanning (e.g., 'MLVScan.dll')");

                _dumpFullIlReports = _category.CreateEntry("DumpFullIlReports", false,
                    description: "When enabled, saves full IL dumps for scanned mods next to reports");

                _enableAutoScan.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableAutoDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _minSeverityForDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _scanDirectories.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _suspiciousThreshold.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _whitelistedMods.OnEntryValueChanged.Subscribe(OnConfigChanged);
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
                MinSeverityForDisable = _minSeverityForDisable.Value,
                ScanDirectories = _scanDirectories.Value,
                SuspiciousThreshold = _suspiciousThreshold.Value,
                WhitelistedMods = _whitelistedMods.Value,
                DumpFullIlReports = _dumpFullIlReports.Value
            };
        }

        public void SaveConfig(ScanConfig newConfig)
        {
            try
            {
                _enableAutoScan.Value = newConfig.EnableAutoScan;
                _enableAutoDisable.Value = newConfig.EnableAutoDisable;
                _minSeverityForDisable.Value = newConfig.MinSeverityForDisable;
                _scanDirectories.Value = newConfig.ScanDirectories;
                _suspiciousThreshold.Value = newConfig.SuspiciousThreshold;
                _whitelistedMods.Value = newConfig.WhitelistedMods;
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

        public string[] GetWhitelistedMods()
        {
            return _whitelistedMods.Value;
        }

        public void SetWhitelistedMods(string[] mods)
        {
            if (mods == null)
                return;

            var normalizedMods = mods
                .Where(m => !string.IsNullOrWhiteSpace(m))
                .Select(m => m.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? m : m + ".dll")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            _whitelistedMods.Value = normalizedMods;
            MelonPreferences.Save();

            UpdateConfigFromPreferences();
            _logger.Msg($"Updated whitelist with {normalizedMods.Length} mod(s)");
        }

        public bool IsModWhitelisted(string modFileName)
        {
            if (string.IsNullOrWhiteSpace(modFileName))
                return false;

            if (!modFileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                modFileName += ".dll";

            return Config.WhitelistedMods.Contains(modFileName, StringComparer.OrdinalIgnoreCase);
        }
    }
}
