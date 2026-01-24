using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of plugin disabler.
    /// Uses ".blocked" extension (BepInEx convention).
    /// </summary>
    public class BepInExPluginDisabler : PluginDisablerBase
    {
        private const string BepInExBlockedExtension = ".blocked";

        public BepInExPluginDisabler(IScanLogger logger, ScanConfig config)
            : base(logger, config)
        {
        }

        protected override string DisabledExtension => BepInExBlockedExtension;

        /// <summary>
        /// BepInEx uses append style (plugin.dll -> plugin.dll.blocked).
        /// </summary>
        protected override string GetDisabledPath(string originalPath)
        {
            return originalPath + BepInExBlockedExtension;
        }
    }
}
