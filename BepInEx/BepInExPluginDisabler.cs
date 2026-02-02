using System.IO;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of plugin disabler.
    /// Uses ".disabled" extension for consistency across platforms.
    /// </summary>
    public class BepInExPluginDisabler : PluginDisablerBase
    {
        private const string DisabledExtension = ".disabled";

        public BepInExPluginDisabler(IScanLogger logger, ScanConfig config)
            : base(logger, config)
        {
        }

        protected override string GetDisabledExtension() => DisabledExtension;

        /// <summary>
        /// Standard extension replacement style (plugin.dll -> plugin.disabled).
        /// </summary>
        protected override string GetDisabledPath(string originalPath)
        {
            return Path.ChangeExtension(originalPath, DisabledExtension);
        }
    }
}
