using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MLVScan.Abstractions;
using MLVScan.Models;

namespace MLVScan.Services
{
    /// <summary>
    /// Result info for a disabled plugin.
    /// </summary>
    public class DisabledPluginInfo
    {
        public string OriginalPath { get; }
        public string DisabledPath { get; }
        public string FileHash { get; }
        public ThreatVerdictInfo ThreatVerdict { get; }
        public ScanStatusInfo ScanStatus { get; }

        public DisabledPluginInfo(
            string originalPath,
            string disabledPath,
            string fileHash,
            ThreatVerdictInfo threatVerdict,
            ScanStatusInfo scanStatus)
        {
            OriginalPath = originalPath;
            DisabledPath = disabledPath;
            FileHash = fileHash;
            ThreatVerdict = threatVerdict ?? new ThreatVerdictInfo();
            ScanStatus = scanStatus ?? new ScanStatusInfo();
        }
    }

    /// <summary>
    /// Abstract base class for plugin/mod disabling across platforms.
    /// Contains shared disabling logic, with platform-specific details 
    /// delegated to derived classes.
    /// </summary>
    public abstract class PluginDisablerBase
    {
        protected readonly IScanLogger Logger;
        protected readonly MLVScanConfig Config;

        /// <summary>
        /// Gets the extension used to disable plugins.
        /// Default is ".disabled" for consistency across platforms.
        /// </summary>
        protected virtual string GetDisabledExtension() => ".disabled";

        protected PluginDisablerBase(IScanLogger logger, MLVScanConfig config)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            Config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Gets the disabled file path for a given plugin.
        /// Uses extension replacement style (plugin.dll -> plugin.disabled).
        /// </summary>
        protected virtual string GetDisabledPath(string originalPath)
        {
            return Path.ChangeExtension(originalPath, GetDisabledExtension());
        }

        /// <summary>
        /// Called after a plugin is disabled successfully.
        /// </summary>
        protected virtual void OnPluginDisabled(string originalPath, string disabledPath, string hash) { }

        /// <summary>
        /// Disables plugins that meet the configured verdict or incomplete-scan policy.
        /// </summary>
        /// <param name="scanResults">Dictionary of file paths to their findings.</param>
        /// <param name="forceDisable">If true, disables even if auto-disable is off, while still honoring verdict policy toggles.</param>
        public List<DisabledPluginInfo> DisableSuspiciousPlugins(
            Dictionary<string, ScannedPluginResult> scanResults,
            bool forceDisable = false)
        {
            if (!forceDisable && !Config.EnableAutoDisable)
            {
                Logger.Info("Automatic disabling is turned off in configuration");
                return new List<DisabledPluginInfo>();
            }

            var disabledPlugins = new List<DisabledPluginInfo>();

            foreach (var (pluginPath, scanResult) in scanResults)
            {
                if (!ScanResultFacts.RequiresAttention(scanResult))
                {
                    continue;
                }

                var verdict = scanResult?.ThreatVerdict ?? new ThreatVerdictInfo();
                var scanStatus = scanResult?.ScanStatus ?? new ScanStatusInfo();

                if (!ShouldDisable(scanResult))
                {
                    Logger.Info(
                        $"Plugin {Path.GetFileName(pluginPath)} requires attention ({GetOutcomeTitle(scanResult)}) but blocking for this outcome is disabled in configuration");
                    continue;
                }

                try
                {
                    var info = DisablePlugin(pluginPath, verdict, scanStatus);
                    if (info != null)
                    {
                        disabledPlugins.Add(info);
                        OnPluginDisabled(info.OriginalPath, info.DisabledPath, info.FileHash);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error($"Failed to disable {Path.GetFileName(pluginPath)}: {ex.Message}");
                }
            }

            return disabledPlugins;
        }

        private bool ShouldDisable(ScannedPluginResult scanResult)
        {
            var verdict = scanResult?.ThreatVerdict ?? new ThreatVerdictInfo();
            return verdict.Kind switch
            {
                ThreatVerdictKind.KnownMaliciousSample => Config.BlockKnownThreats,
                ThreatVerdictKind.KnownMalwareFamily => Config.BlockKnownThreats,
                ThreatVerdictKind.Suspicious => Config.BlockSuspicious,
                _ => ShouldDisable(scanResult?.ScanStatus ?? new ScanStatusInfo())
            };
        }

        private bool ShouldDisable(ScanStatusInfo scanStatus)
        {
            return (scanStatus?.Kind ?? ScanStatusKind.Complete) switch
            {
                ScanStatusKind.RequiresReview => Config.BlockIncompleteScans,
                _ => false
            };
        }

        private static string GetOutcomeTitle(ScannedPluginResult scanResult)
        {
            if (ScanResultFacts.HasThreatVerdict(scanResult))
            {
                return scanResult.ThreatVerdict.Title;
            }

            if (ScanResultFacts.RequiresManualReview(scanResult))
            {
                return scanResult.ScanStatus.Title;
            }

            return "No action required";
        }

        /// <summary>
        /// Disables a single plugin by renaming it.
        /// </summary>
        protected virtual DisabledPluginInfo DisablePlugin(
            string pluginPath,
            ThreatVerdictInfo threatVerdict,
            ScanStatusInfo scanStatus)
        {
            var fileHash = HashUtility.CalculateFileHash(pluginPath);
            var disabledPath = GetDisabledPath(pluginPath);

            // Remove existing disabled file if present
            if (File.Exists(disabledPath))
            {
                File.Delete(disabledPath);
            }

            // Rename to disable
            File.Move(pluginPath, disabledPath);

            Logger.Warning($"BLOCKED: {Path.GetFileName(pluginPath)}");
            return new DisabledPluginInfo(pluginPath, disabledPath, fileHash, threatVerdict, scanStatus);
        }
    }
}
