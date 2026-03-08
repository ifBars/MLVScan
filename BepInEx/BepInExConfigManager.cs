using System;
using System.IO;
using System.Linq;
using BepInEx;
using BepInEx.Logging;
using MLVScan.Abstractions;
using MLVScan.Models;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of IConfigManager using JSON file storage.
    /// Required because BepInEx's ConfigFile isn't available at preload time.
    /// </summary>
    public class BepInExConfigManager : IConfigManager
    {
        private const string DefaultReportUploadApiBaseUrl = "https://api.mlvscan.com";

        private readonly ManualLogSource _logger;
        private readonly string[] _defaultWhitelistedHashes;
        private readonly string _configPath;
        private MLVScanConfig _config;
        private string _reportUploadApiBaseUrl = DefaultReportUploadApiBaseUrl;

        // JSON serialization settings
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public BepInExConfigManager(ManualLogSource logger, string[] defaultWhitelistedHashes = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _defaultWhitelistedHashes = defaultWhitelistedHashes ?? Array.Empty<string>();

            // Config stored alongside other BepInEx configs
            _configPath = Path.Combine(Paths.ConfigPath, "MLVScan.json");
            _config = new MLVScanConfig();
        }

        public MLVScanConfig Config => _config;

        public MLVScanConfig LoadConfig()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    var node = JsonNode.Parse(json);
                    if (node is JsonObject obj && obj.TryGetPropertyValue("ReportUploadApiBaseUrl", out var urlNode))
                    {
                        _reportUploadApiBaseUrl = urlNode?.GetValue<string>()?.Trim() ?? DefaultReportUploadApiBaseUrl;
                    }

                    var loaded = JsonSerializer.Deserialize<MLVScanConfig>(json, JsonOptions);

                    if (loaded != null)
                    {
                        _config = loaded;
                        _config.WhitelistedHashes = NormalizeHashes(_config.WhitelistedHashes);
                        _config.UploadedReportHashes = NormalizeHashes(_config.UploadedReportHashes);
                        _logger.LogInfo("Configuration loaded from MLVScan.json");
                        return _config;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to load config, using defaults: {ex.Message}");
            }

            // Create default config
            _config = CreateDefaultConfig();
            SaveConfig(_config);
            _logger.LogInfo("Created default MLVScan.json configuration");

            return _config;
        }

        private MLVScanConfig CreateDefaultConfig()
        {
            return new MLVScanConfig
            {
                EnableAutoScan = true,
                EnableAutoDisable = true,
                MinSeverityForDisable = Severity.Medium,
                ScanDirectories = new[] { "plugins" },
                SuspiciousThreshold = 1,
                WhitelistedHashes = _defaultWhitelistedHashes,
                DumpFullIlReports = false,
                Scan = new ScanConfig
                {
                    DeveloperMode = false
                },
                EnableReportUpload = false,
                ReportUploadConsentAsked = false,
                ReportUploadConsentPending = false,
                PendingReportUploadPath = string.Empty,
                ReportUploadApiBaseUrl = DefaultReportUploadApiBaseUrl,
                UploadedReportHashes = Array.Empty<string>()
            };
        }

        public void SaveConfig(MLVScanConfig config)
        {
            try
            {
                // Ensure config directory exists
                var configDir = Path.GetDirectoryName(_configPath);
                if (!string.IsNullOrEmpty(configDir) && !Directory.Exists(configDir))
                {
                    Directory.CreateDirectory(configDir);
                }

                var node = JsonNode.Parse(JsonSerializer.Serialize(config, JsonOptions));
                if (node is JsonObject obj)
                {
                    obj["ReportUploadApiBaseUrl"] = _reportUploadApiBaseUrl;
                }

                File.WriteAllText(_configPath, node?.ToJsonString(JsonOptions) ?? "{}");
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
    }
}
