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

        public DisabledPluginInfo(string originalPath, string disabledPath, string fileHash)
        {
            OriginalPath = originalPath;
            DisabledPath = disabledPath;
            FileHash = fileHash;
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
        protected readonly ScanConfig Config;

        /// <summary>
        /// Extension used to disable plugins (platform-specific).
        /// MelonLoader uses ".di", BepInEx uses ".blocked".
        /// </summary>
        protected abstract string DisabledExtension { get; }

        protected PluginDisablerBase(IScanLogger logger, ScanConfig config)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            Config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Gets the disabled file path for a given plugin.
        /// </summary>
        protected virtual string GetDisabledPath(string originalPath)
        {
            // BepInEx style: append extension (plugin.dll.blocked)
            // MelonLoader style: replace extension (plugin.di)
            // Default to append style
            return originalPath + DisabledExtension;
        }

        /// <summary>
        /// Called after a plugin is disabled successfully.
        /// </summary>
        protected virtual void OnPluginDisabled(string originalPath, string disabledPath, string hash) { }

        /// <summary>
        /// Disables plugins that meet severity and threshold criteria.
        /// </summary>
        /// <param name="scanResults">Dictionary of file paths to their findings.</param>
        /// <param name="forceDisable">If true, disables even if auto-disable is off.</param>
        public List<DisabledPluginInfo> DisableSuspiciousPlugins(
            Dictionary<string, List<ScanFinding>> scanResults,
            bool forceDisable = false)
        {
            if (!forceDisable && !Config.EnableAutoDisable)
            {
                Logger.Info("Automatic disabling is turned off in configuration");
                return new List<DisabledPluginInfo>();
            }

            var disabledPlugins = new List<DisabledPluginInfo>();

            foreach (var (pluginPath, findings) in scanResults)
            {
                var severeFindings = findings
                    .Where(f => (int)f.Severity >= (int)Config.MinSeverityForDisable)
                    .ToList();

                if (severeFindings.Count == 0)
                {
                    Logger.Info($"Plugin {Path.GetFileName(pluginPath)} has findings but none meet severity threshold ({Config.MinSeverityForDisable})");
                    continue;
                }

                if (!forceDisable && severeFindings.Count < Config.SuspiciousThreshold)
                {
                    Logger.Info($"Plugin {Path.GetFileName(pluginPath)} below suspicious threshold");
                    continue;
                }

                try
                {
                    var info = DisablePlugin(pluginPath);
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

        /// <summary>
        /// Disables a single plugin by renaming it.
        /// </summary>
        protected virtual DisabledPluginInfo DisablePlugin(string pluginPath)
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
            return new DisabledPluginInfo(pluginPath, disabledPath, fileHash);
        }
    }
}
