using System;
using System.Collections.Generic;
using System.IO;
using MelonLoader.Utils;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader implementation of plugin scanner.
    /// Scans Mods/, Plugins/, and Thunderstore directories.
    /// </summary>
    public class MelonPluginScanner : PluginScannerBase
    {
        private readonly MelonPlatformEnvironment _environment;

        public MelonPluginScanner(
            IScanLogger logger,
            IAssemblyResolverProvider resolverProvider,
            ScanConfig config,
            IConfigManager configManager,
            MelonPlatformEnvironment environment)
            : base(logger, resolverProvider, config, configManager)
        {
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        protected override IEnumerable<string> GetScanDirectories()
        {
            foreach (var scanDir in Config.ScanDirectories)
            {
                yield return Path.Combine(_environment.GameRootDirectory, scanDir);
            }
        }

        protected override bool IsSelfAssembly(string filePath)
        {
            try
            {
                var selfPath = _environment.SelfAssemblyPath;
                if (string.IsNullOrEmpty(selfPath))
                    return false;

                return Path.GetFullPath(filePath).Equals(
                    Path.GetFullPath(selfPath),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        protected override void OnScanComplete(Dictionary<string, List<ScanFinding>> results)
        {
            // Also scan Thunderstore Mod Manager directories
            ScanThunderstoreModManager(results);
        }

        private void ScanThunderstoreModManager(Dictionary<string, List<ScanFinding>> results)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string thunderstoreBasePath = Path.Combine(appDataPath, "Thunderstore Mod Manager", "DataFolder");

                if (!Directory.Exists(thunderstoreBasePath))
                    return;

                // Find game folders
                foreach (var gameFolder in Directory.GetDirectories(thunderstoreBasePath))
                {
                    // Scan profiles
                    string profilesPath = Path.Combine(gameFolder, "profiles");
                    if (!Directory.Exists(profilesPath))
                        continue;

                    foreach (var profileFolder in Directory.GetDirectories(profilesPath))
                    {
                        // Scan Mods directory
                        string modsPath = Path.Combine(profileFolder, "Mods");
                        if (Directory.Exists(modsPath))
                        {
                            Logger.Info($"Scanning Thunderstore profile mods: {modsPath}");
                            ScanDirectory(modsPath, results);
                        }

                        // Scan Plugins directory
                        string pluginsPath = Path.Combine(profileFolder, "Plugins");
                        if (Directory.Exists(pluginsPath))
                        {
                            Logger.Info($"Scanning Thunderstore profile plugins: {pluginsPath}");
                            ScanDirectory(pluginsPath, results);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error scanning Thunderstore Mod Manager directories: {ex.Message}");
            }
        }
    }
}
