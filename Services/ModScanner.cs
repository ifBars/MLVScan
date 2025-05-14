using MelonLoader;
using MelonLoader.Utils;
using MLVScan.Models;

namespace MLVScan.Services
{
    public class ModScanner(
        AssemblyScanner assemblyScanner,
        MelonLogger.Instance logger,
        ScanConfig config,
        ConfigManager configManager)
    {
        private readonly AssemblyScanner _assemblyScanner = assemblyScanner ?? throw new ArgumentNullException(nameof(assemblyScanner));
        private readonly MelonLogger.Instance _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly ScanConfig _config = config ?? throw new ArgumentNullException(nameof(config));
        private readonly ConfigManager _configManager = configManager ?? throw new ArgumentNullException(nameof(configManager));

        public Dictionary<string, List<ScanFinding>> ScanAllMods(bool forceScanning = false)
        {
            var results = new Dictionary<string, List<ScanFinding>>();

            if (!forceScanning && !_config.EnableAutoScan)
            {
                _logger.Msg("Automatic scanning is disabled in configuration");
                return results;
            }

            // Scan configured directories
            foreach (var scanDir in _config.ScanDirectories)
            {
                var directoryPath = Path.Combine(MelonEnvironment.GameRootDirectory, scanDir);

                if (!Directory.Exists(directoryPath))
                {
                    _logger.Warning($"Directory not found: {directoryPath}");
                    continue;
                }

                ScanDirectory(directoryPath, results);
            }

            // Scan Thunderstore Mod Manager directories
            ScanThunderstoreModManager(results);

            return results;
        }

        private void ScanDirectory(string directoryPath, Dictionary<string, List<ScanFinding>> results)
        {
            var modFiles = Directory.GetFiles(directoryPath, "*.dll", SearchOption.AllDirectories);
            _logger.Msg($"Found {modFiles.Length} potential mod files in {directoryPath}");

            foreach (var modFile in modFiles)
            {
                try
                {
                    var modFileName = Path.GetFileName(modFile);
                    if (_configManager.IsModWhitelisted(modFileName))
                    {
                        _logger.Msg($"Skipping whitelisted mod: {modFileName}");
                        continue;
                    }

                    var findings = _assemblyScanner.Scan(modFile).ToList();
                    if (findings.Count < _config.SuspiciousThreshold) continue;
                    results.Add(modFile, findings);
                    _logger.Warning($"Found {findings.Count} suspicious patterns in {Path.GetFileName(modFile)}");
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error scanning {Path.GetFileName(modFile)}: {ex.Message}");
                }
            }
        }

        private void ScanThunderstoreModManager(Dictionary<string, List<ScanFinding>> results)
        {
            try
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string thunderstoreBasePath = Path.Combine(appDataPath, "Thunderstore Mod Manager", "DataFolder");

                if (!Directory.Exists(thunderstoreBasePath))
                {
                    return;
                }

                // Find game folders (like ScheduleI in the example)
                foreach (var gameFolder in Directory.GetDirectories(thunderstoreBasePath))
                {
                    // Scan profiles
                    string profilesPath = Path.Combine(gameFolder, "profiles");
                    if (Directory.Exists(profilesPath))
                    {
                        foreach (var profileFolder in Directory.GetDirectories(profilesPath))
                        {
                            // Scan Mods directory
                            string modsPath = Path.Combine(profileFolder, "Mods");
                            if (Directory.Exists(modsPath))
                            {
                                _logger.Msg($"Scanning Thunderstore profile mods: {modsPath}");
                                ScanDirectory(modsPath, results);
                            }

                            // Scan Plugins directory
                            string pluginsPath = Path.Combine(profileFolder, "Plugins");
                            if (Directory.Exists(pluginsPath))
                            {
                                _logger.Msg($"Scanning Thunderstore profile plugins: {pluginsPath}");
                                ScanDirectory(pluginsPath, results);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error scanning Thunderstore Mod Manager directories: {ex.Message}");
            }
        }
    }
}