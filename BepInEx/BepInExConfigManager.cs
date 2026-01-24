using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using BepInEx;
using BepInEx.Logging;
using MLVScan.Abstractions;
using MLVScan.Models;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of IConfigManager using JSON file storage.
    /// Required because BepInEx's ConfigFile isn't available at preload time.
    /// </summary>
    public class BepInExConfigManager : IConfigManager
    {
        private readonly ManualLogSource _logger;
        private readonly string[] _defaultWhitelistedHashes;
        private readonly string _configPath;
        private ScanConfig _config;

        // JSON serialization options
        private static readonly JsonSerializerOptions JsonOptions = new()
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
            _config = new ScanConfig();
        }

        public ScanConfig Config => _config;

        public ScanConfig LoadConfig()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    var loaded = JsonSerializer.Deserialize<ScanConfig>(json, JsonOptions);

                    if (loaded != null)
                    {
                        _config = loaded;
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

        private ScanConfig CreateDefaultConfig()
        {
            return new ScanConfig
            {
                EnableAutoScan = true,
                EnableAutoDisable = true,
                MinSeverityForDisable = Severity.Medium,
                ScanDirectories = new[] { "plugins" },
                SuspiciousThreshold = 1,
                WhitelistedHashes = _defaultWhitelistedHashes,
                DumpFullIlReports = false,
                DeveloperMode = false
            };
        }

        public void SaveConfig(ScanConfig config)
        {
            try
            {
                // Ensure config directory exists
                var configDir = Path.GetDirectoryName(_configPath);
                if (!string.IsNullOrEmpty(configDir) && !Directory.Exists(configDir))
                {
                    Directory.CreateDirectory(configDir);
                }

                var json = JsonSerializer.Serialize(config, JsonOptions);

                File.WriteAllText(_configPath, json);
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
    }
}
