using System;
using System.IO;
using System.Linq;
using BepInEx;
using BepInEx.Configuration;
using BepInEx.Logging;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of IConfigManager.
    /// </summary>
    public class BepInExConfigManager : IConfigManager
    {
        private const string DefaultReportUploadApiBaseUrl = "https://api.mlvscan.com";

        private readonly ManualLogSource _logger;
        private readonly ConfigFile _configFile;
        private MLVScanConfig _config;
        private string _reportUploadApiBaseUrl = DefaultReportUploadApiBaseUrl;

        public BepInExConfigManager(ManualLogSource logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _configFile = new ConfigFile(Path.Combine(Paths.ConfigPath, "MLVScan.cfg"), true);
            _config = new MLVScanConfig();
        }

        public MLVScanConfig Config => _config;

        public MLVScanConfig LoadConfig()
        {
            try
            {
                _config = ReadBepInExConfig();
                _logger.LogInfo("Configuration loaded from MLVScan.cfg");
                return _config;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to load config, using defaults: {ex.Message}");
                _config = CreateDefaultConfig();
                SaveConfig(_config);
                return _config;
            }
        }

        private MLVScanConfig CreateDefaultConfig()
        {
            return new MLVScanConfig
            {
                EnableAutoScan = true,
                EnableAutoDisable = true,
                EnableScanCache = true,
                BlockKnownThreats = true,
                BlockSuspicious = true,
                BlockIncompleteScans = false,
                ScanDirectories = new[] { "plugins" },
                WhitelistedHashes = Array.Empty<string>(),
                DumpFullIlReports = false,
                Scan = new ScanConfig
                {
                    DeveloperMode = false
                },
                EnableReportUpload = false,
                ReportUploadConsentAsked = false,
                ReportUploadConsentPending = false,
                PendingReportUploadPath = string.Empty,
                PendingReportUploadVerdictKind = string.Empty,
                ReportUploadApiBaseUrl = DefaultReportUploadApiBaseUrl,
                UploadedReportHashes = Array.Empty<string>(),
                IncludeMods = true,
                IncludePlugins = true,
                IncludeUserLibs = true,
                IncludePatchers = true,
                IncludeThunderstoreProfiles = true,
                AdditionalTargetRoots = Array.Empty<string>(),
                ExcludedTargetRoots = Array.Empty<string>()
            };
        }

        public void SaveConfig(MLVScanConfig config)
        {
            try
            {
                WriteBepInExConfig(config);
                _configFile.Save();
                _config = config;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to save config: {ex.Message}");
            }
        }

        public bool IsHashWhitelisted(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return false;

            return _config.WhitelistedHashes.Contains(
                hash.ToLowerInvariant(),
                StringComparer.OrdinalIgnoreCase);
        }

        public string[] GetWhitelistedHashes()
        {
            return _config.WhitelistedHashes;
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

            _config.WhitelistedHashes = normalizedHashes;
            SaveConfig(_config);
            _logger.LogInfo($"Updated whitelist with {normalizedHashes.Length} hash(es)");
        }

        public string GetReportUploadApiBaseUrl() => _reportUploadApiBaseUrl;

        public bool IsReportHashUploaded(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return false;

            return NormalizeHashes(_config.UploadedReportHashes)
                .Contains(hash.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase);
        }

        public void MarkReportHashUploaded(string hash)
        {
            if (!HashUtility.IsValidHash(hash))
                return;

            var normalizedHashes = NormalizeHashes((_config.UploadedReportHashes ?? Array.Empty<string>()).Append(hash));
            if (normalizedHashes.Length == (_config.UploadedReportHashes?.Length ?? 0) && IsReportHashUploaded(hash))
                return;

            _config.UploadedReportHashes = normalizedHashes;
            SaveConfig(_config);
            _logger.LogInfo($"Recorded uploaded report hash: {hash}");
        }

        private static string[] NormalizeHashes(System.Collections.Generic.IEnumerable<string> hashes)
        {
            return (hashes ?? Array.Empty<string>())
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private MLVScanConfig ReadBepInExConfig()
        {
            var defaults = CreateDefaultConfig();
            var config = new MLVScanConfig
            {
                EnableAutoScan = GetEntryValue("General", nameof(MLVScanConfig.EnableAutoScan), defaults.EnableAutoScan, "Enable automatic scanning before BepInEx loads plugins."),
                EnableAutoDisable = GetEntryValue("General", nameof(MLVScanConfig.EnableAutoDisable), defaults.EnableAutoDisable, "Disable blocked plugins before they execute."),
                EnableScanCache = GetEntryValue("General", nameof(MLVScanConfig.EnableScanCache), defaults.EnableScanCache, "Reuse signed scan results for unchanged files."),
                BlockKnownThreats = GetEntryValue("Blocking", nameof(MLVScanConfig.BlockKnownThreats), defaults.BlockKnownThreats, "Block exact known-malicious samples and known malware-family matches."),
                BlockSuspicious = GetEntryValue("Blocking", nameof(MLVScanConfig.BlockSuspicious), defaults.BlockSuspicious, "Block suspicious unknown behavior."),
                BlockIncompleteScans = GetEntryValue("Blocking", nameof(MLVScanConfig.BlockIncompleteScans), defaults.BlockIncompleteScans, "Block files that could not be fully analyzed."),
                ScanDirectories = BindList("Scope", nameof(MLVScanConfig.ScanDirectories), defaults.ScanDirectories, "Comma-separated BepInEx-relative directories to scan."),
                WhitelistedHashes = NormalizeHashes(BindList("Allowlist", nameof(MLVScanConfig.WhitelistedHashes), defaults.WhitelistedHashes, "Comma-separated SHA256 hashes to skip.")),
                DumpFullIlReports = GetEntryValue("Reports", nameof(MLVScanConfig.DumpFullIlReports), defaults.DumpFullIlReports, "Write full IL reports for scanned files."),
                EnableReportUpload = GetEntryValue("Reports", nameof(MLVScanConfig.EnableReportUpload), defaults.EnableReportUpload, "Allow uploading reports to the configured MLVScan API."),
                ReportUploadConsentAsked = GetEntryValue("Reports", nameof(MLVScanConfig.ReportUploadConsentAsked), defaults.ReportUploadConsentAsked, "Whether report-upload consent has already been handled."),
                ReportUploadConsentPending = GetEntryValue("Reports", nameof(MLVScanConfig.ReportUploadConsentPending), defaults.ReportUploadConsentPending, "Whether report-upload consent is pending."),
                PendingReportUploadPath = GetEntryValue("Reports", nameof(MLVScanConfig.PendingReportUploadPath), defaults.PendingReportUploadPath, "Pending report-upload file path."),
                PendingReportUploadVerdictKind = GetEntryValue("Reports", nameof(MLVScanConfig.PendingReportUploadVerdictKind), defaults.PendingReportUploadVerdictKind, "Pending report-upload verdict kind."),
                ReportUploadApiBaseUrl = GetEntryValue("Reports", nameof(MLVScanConfig.ReportUploadApiBaseUrl), defaults.ReportUploadApiBaseUrl, "MLVScan API base URL for report uploads."),
                UploadedReportHashes = NormalizeHashes(BindList("Reports", nameof(MLVScanConfig.UploadedReportHashes), defaults.UploadedReportHashes, "Comma-separated SHA256 hashes already uploaded.")),
                IncludeMods = GetEntryValue("Scope", nameof(MLVScanConfig.IncludeMods), defaults.IncludeMods, "Include game Mods folders in target scope."),
                IncludePlugins = GetEntryValue("Scope", nameof(MLVScanConfig.IncludePlugins), defaults.IncludePlugins, "Include BepInEx plugins folders in target scope."),
                IncludeUserLibs = GetEntryValue("Scope", nameof(MLVScanConfig.IncludeUserLibs), defaults.IncludeUserLibs, "Include user library folders in target scope."),
                IncludePatchers = GetEntryValue("Scope", nameof(MLVScanConfig.IncludePatchers), defaults.IncludePatchers, "Include BepInEx patchers folders in target scope."),
                IncludeThunderstoreProfiles = GetEntryValue("Scope", nameof(MLVScanConfig.IncludeThunderstoreProfiles), defaults.IncludeThunderstoreProfiles, "Include Thunderstore profile folders in target scope."),
                AdditionalTargetRoots = BindList("Scope", nameof(MLVScanConfig.AdditionalTargetRoots), defaults.AdditionalTargetRoots, "Comma-separated additional absolute roots to scan."),
                ExcludedTargetRoots = BindList("Scope", nameof(MLVScanConfig.ExcludedTargetRoots), defaults.ExcludedTargetRoots, "Comma-separated absolute roots to exclude."),
                Scan = new ScanConfig
                {
                    DeveloperMode = GetEntryValue("Scan", nameof(ScanConfig.DeveloperMode), defaults.Scan.DeveloperMode, "Enable developer guidance in scan results."),
                    EnableMultiSignalDetection = GetEntryValue("Scan", nameof(ScanConfig.EnableMultiSignalDetection), defaults.Scan.EnableMultiSignalDetection, "Enable multi-signal correlation."),
                    AnalyzeExceptionHandlers = GetEntryValue("Scan", nameof(ScanConfig.AnalyzeExceptionHandlers), defaults.Scan.AnalyzeExceptionHandlers, "Analyze exception handlers."),
                    AnalyzeLocalVariables = GetEntryValue("Scan", nameof(ScanConfig.AnalyzeLocalVariables), defaults.Scan.AnalyzeLocalVariables, "Analyze local variables."),
                    AnalyzePropertyAccessors = GetEntryValue("Scan", nameof(ScanConfig.AnalyzePropertyAccessors), defaults.Scan.AnalyzePropertyAccessors, "Analyze property and event accessors."),
                    DetectAssemblyMetadata = GetEntryValue("Scan", nameof(ScanConfig.DetectAssemblyMetadata), defaults.Scan.DetectAssemblyMetadata, "Scan assembly metadata."),
                    EnableCrossMethodAnalysis = GetEntryValue("Scan", nameof(ScanConfig.EnableCrossMethodAnalysis), defaults.Scan.EnableCrossMethodAnalysis, "Enable cross-method analysis."),
                    MaxCallChainDepth = GetEntryValue("Scan", nameof(ScanConfig.MaxCallChainDepth), defaults.Scan.MaxCallChainDepth, "Maximum cross-method call depth."),
                    EnableReturnValueTracking = GetEntryValue("Scan", nameof(ScanConfig.EnableReturnValueTracking), defaults.Scan.EnableReturnValueTracking, "Track method return values."),
                    EnableRecursiveResourceScanning = GetEntryValue("Scan", nameof(ScanConfig.EnableRecursiveResourceScanning), defaults.Scan.EnableRecursiveResourceScanning, "Recursively scan managed assemblies in embedded resources."),
                    MaxRecursiveResourceSizeMB = GetEntryValue("Scan", nameof(ScanConfig.MaxRecursiveResourceSizeMB), defaults.Scan.MaxRecursiveResourceSizeMB, "Maximum embedded resource size in MB."),
                    MinimumEncodedStringLength = GetEntryValue("Scan", nameof(ScanConfig.MinimumEncodedStringLength), defaults.Scan.MinimumEncodedStringLength, "Minimum numeric segments for encoded-string detection.")
                }
            };

            _reportUploadApiBaseUrl = string.IsNullOrWhiteSpace(config.ReportUploadApiBaseUrl)
                ? DefaultReportUploadApiBaseUrl
                : config.ReportUploadApiBaseUrl.Trim();
            config.ReportUploadApiBaseUrl = _reportUploadApiBaseUrl;

            return config;
        }

        private void WriteBepInExConfig(MLVScanConfig config)
        {
            BindEntry("General", nameof(MLVScanConfig.EnableAutoScan), config.EnableAutoScan, "Enable automatic scanning before BepInEx loads plugins.").Value = config.EnableAutoScan;
            BindEntry("General", nameof(MLVScanConfig.EnableAutoDisable), config.EnableAutoDisable, "Disable blocked plugins before they execute.").Value = config.EnableAutoDisable;
            BindEntry("General", nameof(MLVScanConfig.EnableScanCache), config.EnableScanCache, "Reuse signed scan results for unchanged files.").Value = config.EnableScanCache;
            BindEntry("Blocking", nameof(MLVScanConfig.BlockKnownThreats), config.BlockKnownThreats, "Block exact known-malicious samples and known malware-family matches.").Value = config.BlockKnownThreats;
            BindEntry("Blocking", nameof(MLVScanConfig.BlockSuspicious), config.BlockSuspicious, "Block suspicious unknown behavior.").Value = config.BlockSuspicious;
            BindEntry("Blocking", nameof(MLVScanConfig.BlockIncompleteScans), config.BlockIncompleteScans, "Block files that could not be fully analyzed.").Value = config.BlockIncompleteScans;
            BindRaw("Scope", nameof(MLVScanConfig.ScanDirectories), config.ScanDirectories, "Comma-separated BepInEx-relative directories to scan.").Value = JoinList(config.ScanDirectories);
            BindRaw("Allowlist", nameof(MLVScanConfig.WhitelistedHashes), config.WhitelistedHashes, "Comma-separated SHA256 hashes to skip.").Value = JoinList(NormalizeHashes(config.WhitelistedHashes));
            BindEntry("Reports", nameof(MLVScanConfig.DumpFullIlReports), config.DumpFullIlReports, "Write full IL reports for scanned files.").Value = config.DumpFullIlReports;
            BindEntry("Reports", nameof(MLVScanConfig.EnableReportUpload), config.EnableReportUpload, "Allow uploading reports to the configured MLVScan API.").Value = config.EnableReportUpload;
            BindEntry("Reports", nameof(MLVScanConfig.ReportUploadConsentAsked), config.ReportUploadConsentAsked, "Whether report-upload consent has already been handled.").Value = config.ReportUploadConsentAsked;
            BindEntry("Reports", nameof(MLVScanConfig.ReportUploadConsentPending), config.ReportUploadConsentPending, "Whether report-upload consent is pending.").Value = config.ReportUploadConsentPending;
            BindEntry("Reports", nameof(MLVScanConfig.PendingReportUploadPath), config.PendingReportUploadPath ?? string.Empty, "Pending report-upload file path.").Value = config.PendingReportUploadPath ?? string.Empty;
            BindEntry("Reports", nameof(MLVScanConfig.PendingReportUploadVerdictKind), config.PendingReportUploadVerdictKind ?? string.Empty, "Pending report-upload verdict kind.").Value = config.PendingReportUploadVerdictKind ?? string.Empty;
            BindEntry("Reports", nameof(MLVScanConfig.ReportUploadApiBaseUrl), _reportUploadApiBaseUrl, "MLVScan API base URL for report uploads.").Value = _reportUploadApiBaseUrl;
            BindRaw("Reports", nameof(MLVScanConfig.UploadedReportHashes), config.UploadedReportHashes, "Comma-separated SHA256 hashes already uploaded.").Value = JoinList(NormalizeHashes(config.UploadedReportHashes));
        }

        private T GetEntryValue<T>(string section, string key, T defaultValue, string description)
        {
            return _configFile.Bind(section, key, defaultValue, description).Value;
        }

        private ConfigEntry<T> BindEntry<T>(string section, string key, T value, string description)
        {
            return _configFile.Bind(section, key, value, description);
        }

        private string[] BindList(string section, string key, string[] defaultValue, string description)
        {
            return SplitList(BindRaw(section, key, defaultValue, description).Value);
        }

        private ConfigEntry<string> BindRaw(string section, string key, string[] defaultValue, string description)
        {
            return _configFile.Bind(section, key, JoinList(defaultValue), description);
        }

        private static string JoinList(System.Collections.Generic.IEnumerable<string> values)
        {
            return string.Join(", ", values ?? Array.Empty<string>());
        }

        private static string[] SplitList(string value)
        {
            return (value ?? string.Empty)
                .Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(v => v.Trim())
                .Where(v => v.Length > 0)
                .ToArray();
        }
    }
}
