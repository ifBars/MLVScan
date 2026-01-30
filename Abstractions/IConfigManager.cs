using MLVScan.Models;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction for configuration management across different mod platforms.
    /// MelonLoader uses MelonPreferences (INI-based), BepInEx uses JSON files.
    /// </summary>
    public interface IConfigManager
    {
        /// <summary>
        /// Gets the current configuration.
        /// </summary>
        ScanConfig Config { get; }

        /// <summary>
        /// Loads configuration from persistent storage.
        /// Creates default configuration if none exists.
        /// </summary>
        ScanConfig LoadConfig();

        /// <summary>
        /// Saves configuration to persistent storage.
        /// </summary>
        void SaveConfig(ScanConfig config);

        /// <summary>
        /// Checks if a file hash is in the whitelist.
        /// </summary>
        bool IsHashWhitelisted(string hash);

        /// <summary>
        /// Gets all whitelisted hashes.
        /// </summary>
        string[] GetWhitelistedHashes();

        /// <summary>
        /// Sets the whitelisted hashes (normalizes and deduplicates).
        /// </summary>
        void SetWhitelistedHashes(string[] hashes);
    }
}
