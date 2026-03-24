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
        private readonly MelonPreferences_Entry<bool> _enableScanCache;
        private readonly MelonPreferences_Entry<bool> _blockKnownThreats;
        private readonly MelonPreferences_Entry<bool> _blockSuspicious;
        private readonly MelonPreferences_Entry<bool> _blockIncompleteScans;
        private readonly MelonPreferences_Entry<string> _minSeverityForDisable;
        private readonly MelonPreferences_Entry<string[]> _scanDirectories;
        private readonly MelonPreferences_Entry<int> _suspiciousThreshold;
        private readonly MelonPreferences_Entry<string[]> _whitelistedHashes;
        private readonly MelonPreferences_Entry<bool> _dumpFullIlReports;
        private readonly MelonPreferences_Entry<bool> _developerMode;
        private readonly MelonPreferences_Entry<bool> _enableReportUpload;
        private readonly MelonPreferences_Entry<bool> _reportUploadConsentAsked;
        private readonly MelonPreferences_Entry<bool> _reportUploadConsentPending;
        private readonly MelonPreferences_Entry<string> _pendingReportUploadPath;
        private readonly MelonPreferences_Entry<string> _pendingReportUploadVerdictKind;
        private readonly MelonPreferences_Entry<string> _reportUploadApiBaseUrl;
        private readonly MelonPreferences_Entry<string[]> _uploadedReportHashes;
        private readonly MelonPreferences_Entry<bool> _includeMods;
        private readonly MelonPreferences_Entry<bool> _includePlugins;
        private readonly MelonPreferences_Entry<bool> _includeUserLibs;
        private readonly MelonPreferences_Entry<bool> _includeThunderstoreProfiles;
        private readonly MelonPreferences_Entry<string[]> _additionalTargetRoots;
        private readonly MelonPreferences_Entry<string[]> _excludedTargetRoots;

        public MelonConfigManager(MelonLogger.Instance logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            try
            {
                _category = MelonPreferences.CreateCategory("MLVScan");

                _enableAutoScan = _category.CreateEntry("EnableAutoScan", true,
                    description: "Whether to scan mods at startup");

                _enableAutoDisable = _category.CreateEntry("EnableAutoDisable", true,
                    description: "Whether to automatically disable mods that meet the active blocking policy");

                _enableScanCache = _category.CreateEntry("EnableScanCache", true,
                    description: "Whether to reuse scan results for unchanged files using a local authenticated cache");

                _blockKnownThreats = _category.CreateEntry("BlockKnownThreats", true,
                    description: "Whether to block mods that match a known threat family or exact malicious sample");

                _blockSuspicious = _category.CreateEntry("BlockSuspicious", true,
                    description: "Whether to block suspicious unknown behavior that may still be a false positive");

                _blockIncompleteScans = _category.CreateEntry("BlockIncompleteScans", false,
                    description: "Whether to block mods that could not be fully analyzed and require manual review");

                _minSeverityForDisable = _category.CreateEntry("MinSeverityForDisable", "Medium",
                    description: "Legacy setting from the old severity-based blocking model (no longer used for blocking)");

                _scanDirectories = _category.CreateEntry("ScanDirectories", new[] { "Mods", "Plugins" },
                    description: "Directories to scan for mods");

                _suspiciousThreshold = _category.CreateEntry("SuspiciousThreshold", 1,
                    description: "Legacy setting from the old threshold-based blocking model (no longer used for blocking)");

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

                _reportUploadConsentPending = _category.CreateEntry("ReportUploadConsentPending", false,
                    description: "Whether an upload consent popup is pending (internal)");

                _pendingReportUploadPath = _category.CreateEntry("PendingReportUploadPath", string.Empty,
                    description: "Suspicious mod path waiting for upload consent (internal)");

                _pendingReportUploadVerdictKind = _category.CreateEntry("PendingReportUploadVerdictKind", string.Empty,
                    description: "Threat verdict kind for the pending upload consent item (internal)");

                _reportUploadApiBaseUrl = _category.CreateEntry("ReportUploadApiBaseUrl", "https://api.mlvscan.com",
                    description: "API base URL for report uploads");

                _uploadedReportHashes = _category.CreateEntry("UploadedReportHashes", Array.Empty<string>(),
                    description: "List of assembly SHA256 hashes already uploaded to the MLVScan API (internal)");

                _includeMods = _category.CreateEntry("IncludeMods", true,
                    description: "Whether to include Mods folders in the target scan scope");

                _includePlugins = _category.CreateEntry("IncludePlugins", true,
                    description: "Whether to include Plugins folders in the target scan scope");

                _includeUserLibs = _category.CreateEntry("IncludeUserLibs", true,
                    description: "Whether to include UserLibs folders in the target scan scope");

                _includeThunderstoreProfiles = _category.CreateEntry("IncludeThunderstoreProfiles", true,
                    description: "Whether to include Thunderstore profile folders in the target scan scope");

                _additionalTargetRoots = _category.CreateEntry("AdditionalTargetRoots", Array.Empty<string>(),
                    description: "Additional absolute paths to include in the target scan scope");

                _excludedTargetRoots = _category.CreateEntry("ExcludedTargetRoots", Array.Empty<string>(),
                    description: "Absolute paths to exclude from the target scan scope");

                _enableAutoScan.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableAutoDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableScanCache.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _blockKnownThreats.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _blockSuspicious.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _blockIncompleteScans.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _minSeverityForDisable.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _scanDirectories.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _suspiciousThreshold.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _whitelistedHashes.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _dumpFullIlReports.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _developerMode.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _enableReportUpload.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _reportUploadConsentAsked.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _reportUploadConsentPending.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _pendingReportUploadPath.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _pendingReportUploadVerdictKind.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _reportUploadApiBaseUrl.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _uploadedReportHashes.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _includeMods.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _includePlugins.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _includeUserLibs.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _includeThunderstoreProfiles.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _additionalTargetRoots.OnEntryValueChanged.Subscribe(OnConfigChanged);
                _excludedTargetRoots.OnEntryValueChanged.Subscribe(OnConfigChanged);

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
                EnableScanCache = _enableScanCache.Value,
                BlockKnownThreats = _blockKnownThreats.Value,
                BlockSuspicious = _blockSuspicious.Value,
                BlockIncompleteScans = _blockIncompleteScans.Value,
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
                ReportUploadConsentPending = _reportUploadConsentPending.Value,
                PendingReportUploadPath = _pendingReportUploadPath.Value,
                PendingReportUploadVerdictKind = _pendingReportUploadVerdictKind.Value,
                ReportUploadApiBaseUrl = _reportUploadApiBaseUrl.Value,
                UploadedReportHashes = NormalizeHashes(_uploadedReportHashes.Value),
                IncludeMods = _includeMods.Value,
                IncludePlugins = _includePlugins.Value,
                IncludeUserLibs = _includeUserLibs.Value,
                IncludePatchers = false,
                IncludeThunderstoreProfiles = _includeThunderstoreProfiles.Value,
                AdditionalTargetRoots = _additionalTargetRoots.Value ?? Array.Empty<string>(),
                ExcludedTargetRoots = _excludedTargetRoots.Value ?? Array.Empty<string>()
            };
        }

        public void SaveConfig(MLVScanConfig newConfig)
        {
            try
            {
                _enableAutoScan.Value = newConfig.EnableAutoScan;
                _enableAutoDisable.Value = newConfig.EnableAutoDisable;
                _enableScanCache.Value = newConfig.EnableScanCache;
                _blockKnownThreats.Value = newConfig.BlockKnownThreats;
                _blockSuspicious.Value = newConfig.BlockSuspicious;
                _blockIncompleteScans.Value = newConfig.BlockIncompleteScans;
                _minSeverityForDisable.Value = FormatSeverity(newConfig.MinSeverityForDisable);
                _scanDirectories.Value = newConfig.ScanDirectories;
                _suspiciousThreshold.Value = newConfig.SuspiciousThreshold;
                _whitelistedHashes.Value = newConfig.WhitelistedHashes;
                _dumpFullIlReports.Value = newConfig.DumpFullIlReports;
                _developerMode.Value = newConfig.Scan?.DeveloperMode ?? false;
                _enableReportUpload.Value = newConfig.EnableReportUpload;
                _reportUploadConsentAsked.Value = newConfig.ReportUploadConsentAsked;
                _reportUploadConsentPending.Value = newConfig.ReportUploadConsentPending;
                _pendingReportUploadPath.Value = newConfig.PendingReportUploadPath ?? string.Empty;
                _pendingReportUploadVerdictKind.Value = newConfig.PendingReportUploadVerdictKind ?? string.Empty;
                _reportUploadApiBaseUrl.Value = newConfig.ReportUploadApiBaseUrl;
                _uploadedReportHashes.Value = NormalizeHashes(newConfig.UploadedReportHashes);
                _includeMods.Value = newConfig.IncludeMods;
                _includePlugins.Value = newConfig.IncludePlugins;
                _includeUserLibs.Value = newConfig.IncludeUserLibs;
                _includeThunderstoreProfiles.Value = newConfig.IncludeThunderstoreProfiles;
                _additionalTargetRoots.Value = newConfig.AdditionalTargetRoots ?? Array.Empty<string>();
                _excludedTargetRoots.Value = newConfig.ExcludedTargetRoots ?? Array.Empty<string>();

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

        public bool IsReportHashUploaded(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return false;

            return NormalizeHashes(_uploadedReportHashes.Value)
                .Contains(hash.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase);
        }

        public void MarkReportHashUploaded(string hash)
        {
            if (!Services.HashUtility.IsValidHash(hash))
                return;

            var updatedHashes = NormalizeHashes((_uploadedReportHashes.Value ?? Array.Empty<string>()).Append(hash));
            if (updatedHashes.Length == (_uploadedReportHashes.Value?.Length ?? 0) && IsReportHashUploaded(hash))
                return;

            _uploadedReportHashes.Value = updatedHashes;
            MelonPreferences.Save();

            UpdateConfigFromPreferences();
            _logger.Msg($"Recorded uploaded report hash: {hash}");
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

        private static string[] NormalizeHashes(System.Collections.Generic.IEnumerable<string> hashes)
        {
            return (hashes ?? Array.Empty<string>())
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }
}
