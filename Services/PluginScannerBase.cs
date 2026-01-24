using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MLVScan.Abstractions;
using MLVScan.Models;

namespace MLVScan.Services
{
    /// <summary>
    /// Abstract base class for plugin/mod scanning across platforms.
    /// Contains shared scanning logic, with platform-specific details 
    /// delegated to derived classes.
    /// </summary>
    public abstract class PluginScannerBase
    {
        protected readonly IScanLogger Logger;
        protected readonly IAssemblyResolverProvider ResolverProvider;
        protected readonly ScanConfig Config;
        protected readonly IConfigManager ConfigManager;
        protected readonly AssemblyScanner AssemblyScanner;

        protected PluginScannerBase(
            IScanLogger logger,
            IAssemblyResolverProvider resolverProvider,
            ScanConfig config,
            IConfigManager configManager)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            ResolverProvider = resolverProvider ?? throw new ArgumentNullException(nameof(resolverProvider));
            Config = config ?? throw new ArgumentNullException(nameof(config));
            ConfigManager = configManager ?? throw new ArgumentNullException(nameof(configManager));

            var rules = RuleFactory.CreateDefaultRules();
            AssemblyScanner = new AssemblyScanner(rules, Config, ResolverProvider);
        }

        /// <summary>
        /// Gets the directories to scan for plugins.
        /// </summary>
        protected abstract IEnumerable<string> GetScanDirectories();

        /// <summary>
        /// Checks if a file path is this scanner's own assembly.
        /// </summary>
        protected abstract bool IsSelfAssembly(string filePath);

        /// <summary>
        /// Performs any platform-specific post-scan processing.
        /// </summary>
        protected virtual void OnScanComplete(Dictionary<string, List<ScanFinding>> results) { }

        /// <summary>
        /// Scans all plugins in configured directories.
        /// </summary>
        /// <param name="forceScanning">If true, scans even if auto-scan is disabled.</param>
        public Dictionary<string, List<ScanFinding>> ScanAllPlugins(bool forceScanning = false)
        {
            var results = new Dictionary<string, List<ScanFinding>>();

            if (!forceScanning && !Config.EnableAutoScan)
            {
                Logger.Info("Automatic scanning is disabled in configuration");
                return results;
            }

            foreach (var directory in GetScanDirectories())
            {
                if (!Directory.Exists(directory))
                {
                    Logger.Warning($"Directory not found: {directory}");
                    continue;
                }

                ScanDirectory(directory, results);
            }

            OnScanComplete(results);
            return results;
        }

        /// <summary>
        /// Scans a single directory for malicious plugins.
        /// </summary>
        protected virtual void ScanDirectory(string directoryPath, Dictionary<string, List<ScanFinding>> results)
        {
            var pluginFiles = Directory.GetFiles(directoryPath, "*.dll", SearchOption.AllDirectories);
            Logger.Info($"Found {pluginFiles.Length} plugin files in {directoryPath}");

            foreach (var pluginFile in pluginFiles)
            {
                try
                {
                    ScanSingleFile(pluginFile, results);
                }
                catch (Exception ex)
                {
                    Logger.Error($"Error scanning {Path.GetFileName(pluginFile)}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Scans a single file and adds results if suspicious.
        /// </summary>
        protected virtual void ScanSingleFile(string filePath, Dictionary<string, List<ScanFinding>> results)
        {
            var fileName = Path.GetFileName(filePath);
            var hash = HashUtility.CalculateFileHash(filePath);

            // Skip ourselves
            if (IsSelfAssembly(filePath))
            {
                Logger.Debug($"Skipping self: {fileName}");
                return;
            }

            // Skip whitelisted plugins
            if (ConfigManager.IsHashWhitelisted(hash))
            {
                Logger.Debug($"Skipping whitelisted: {fileName}");
                return;
            }

            var findings = AssemblyScanner.Scan(filePath).ToList();

            // Filter out placeholder findings
            var actualFindings = findings
                .Where(f => f.Location != "Assembly scanning")
                .ToList();

            if (actualFindings.Count >= Config.SuspiciousThreshold)
            {
                results.Add(filePath, actualFindings);
                Logger.Warning($"Found {actualFindings.Count} suspicious patterns in {fileName}");
            }
        }
    }
}
