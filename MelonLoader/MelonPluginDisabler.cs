using System.IO;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader implementation of plugin disabler.
    /// Uses ".di" extension (MelonLoader convention).
    /// </summary>
    public class MelonPluginDisabler : PluginDisablerBase
    {
        private const string MelonDisabledExtension = ".di";

        public MelonPluginDisabler(IScanLogger logger, ScanConfig config)
            : base(logger, config)
        {
        }

        protected override string DisabledExtension => MelonDisabledExtension;

        /// <summary>
        /// MelonLoader uses extension replacement style (plugin.dll -> plugin.di).
        /// </summary>
        protected override string GetDisabledPath(string originalPath)
        {
            return Path.ChangeExtension(originalPath, MelonDisabledExtension);
        }
    }
}
