using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MelonLoader;
using MLVScan.Models;

namespace MLVScan.Services
{
    public class ModDisabler(MelonLogger.Instance logger, ScanConfig config)
    {
        private readonly MelonLogger.Instance _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly ScanConfig _config = config ?? throw new ArgumentNullException(nameof(config));
        private const string DisabledExtension = ".di";

        public List<DisabledModInfo> DisableSuspiciousMods(Dictionary<string, List<ScanFinding>> scanResults, bool forceDisable = false)
        {
            if (!forceDisable && !_config.EnableAutoDisable)
            {
                _logger.Msg("Automatic disabling is turned off in configuration");
                return [];
            }

            var disabledMods = new List<DisabledModInfo>();

            foreach (var (modFilePath, findings) in scanResults)
            {
                var severeFindings = findings.Where(f =>
                    GetSeverityRank(f.Severity) >= GetSeverityRank(_config.MinSeverityForDisable))
                    .ToList();

                if (!forceDisable && severeFindings.Count < _config.SuspiciousThreshold)
                {
                    _logger.Msg($"Mod {Path.GetFileName(modFilePath)} has suspicious patterns but below threshold");
                    continue;
                }

                try
                {
                    var fileHash = ModScanner.CalculateFileHash(modFilePath);
                    var newFilePath = Path.ChangeExtension(modFilePath, DisabledExtension);

                    if (File.Exists(newFilePath))
                    {
                        File.Delete(newFilePath);
                    }

                    File.Move(modFilePath, newFilePath);
                    _logger.Warning($"Disabled potentially malicious mod: {Path.GetFileName(modFilePath)}");
                    disabledMods.Add(new DisabledModInfo(modFilePath, newFilePath, fileHash));

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

        private static int GetSeverityRank(string severity)
        {
            return severity?.ToLower() switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            };
        }
    }
}
