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

            foreach (var scanDir in _config.ScanDirectories)
            {
                var directoryPath = Path.Combine(MelonEnvironment.GameRootDirectory, scanDir);

                if (!Directory.Exists(directoryPath))
                {
                    _logger.Warning($"Directory not found: {directoryPath}");
                    continue;
                }

                var modFiles = Directory.GetFiles(directoryPath, "*.dll", SearchOption.AllDirectories);
                _logger.Msg($"Found {modFiles.Length} potential mod files in {scanDir}");

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

            return results;
        }
    }
}