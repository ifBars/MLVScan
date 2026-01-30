using System;
using System.Collections.Generic;
using System.IO;
using BepInEx;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of plugin scanner.
    /// Scans BepInEx/plugins/ directory.
    /// </summary>
    public class BepInExPluginScanner : PluginScannerBase
    {
        private readonly BepInExPlatformEnvironment _environment;

        public BepInExPluginScanner(
            IScanLogger logger,
            IAssemblyResolverProvider resolverProvider,
            ScanConfig config,
            IConfigManager configManager,
            BepInExPlatformEnvironment environment)
            : base(logger, resolverProvider, config, configManager)
        {
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        protected override IEnumerable<string> GetScanDirectories()
        {
            // BepInEx plugins directory
            if (Directory.Exists(Paths.PluginPath))
            {
                yield return Paths.PluginPath;
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
    }
}
