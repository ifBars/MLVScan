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
        MLVScanConfig Config { get; }

        /// <summary>
        /// Loads configuration from persistent storage.
        /// Creates default configuration if none exists.
        /// </summary>
        MLVScanConfig LoadConfig();

        /// <summary>
        /// Saves configuration to persistent storage.
        /// </summary>
        void SaveConfig(MLVScanConfig config);

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

        /// <summary>
        /// Gets the API base URL for report uploads (mod loader implementation-specific).
        /// </summary>
        string GetReportUploadApiBaseUrl();

        /// <summary>
        /// Checks whether a report for the given SHA256 hash was already uploaded.
        /// </summary>
        bool IsReportHashUploaded(string hash);

        /// <summary>
        /// Persists a SHA256 hash after a successful report upload.
        /// </summary>
        void MarkReportHashUploaded(string hash);
    }
}
