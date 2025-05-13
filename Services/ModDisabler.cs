using MelonLoader;
using MLVScan.Models;

namespace MLVScan.Services
{
    public class ModDisabler(MelonLogger.Instance logger, ScanConfig config)
    {
        private readonly MelonLogger.Instance _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly ScanConfig _config = config ?? throw new ArgumentNullException(nameof(config));
        private const string DisabledExtension = ".di";

        public List<string> DisableSuspiciousMods(Dictionary<string, List<ScanFinding>> scanResults, bool forceDisable = false)
        {
            if (!forceDisable && !_config.EnableAutoDisable)
            {
                _logger.Msg("Automatic disabling is turned off in configuration");
                return [];
            }

            var disabledMods = new List<string>();

            foreach (var (modFilePath, findings) in scanResults)
            {
                var severeFindings = findings.Where(f =>
                    string.Compare(f.Severity, _config.MinSeverityForDisable, StringComparison.OrdinalIgnoreCase) >= 0)
                    .ToList();

                if (!forceDisable && severeFindings.Count < _config.SuspiciousThreshold)
                {
                    _logger.Msg($"Mod {Path.GetFileName(modFilePath)} has suspicious patterns but below threshold");
                    continue;
                }

                try
                {
                    var newFilePath = Path.ChangeExtension(modFilePath, DisabledExtension);

                    if (File.Exists(newFilePath))
                    {
                        File.Delete(newFilePath);
                    }

                    File.Move(modFilePath, newFilePath);
                    _logger.Warning($"Disabled potentially malicious mod: {Path.GetFileName(modFilePath)}");
                    disabledMods.Add(modFilePath);

                    foreach (var finding in severeFindings.Take(3))
                    {
                        _logger.Warning($"  - {finding}");
                    }

                    if (severeFindings.Count > 3)
                    {
                        _logger.Warning($"  - And {severeFindings.Count - 3} more suspicious patterns...");
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to disable mod {Path.GetFileName(modFilePath)}: {ex.Message}");
                }
            }

            return disabledMods;
        }
    }
}