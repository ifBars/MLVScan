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
            MLVScanConfig config,
            IConfigManager configManager,
            BepInExPlatformEnvironment environment)
            : base(logger, resolverProvider, config, configManager, environment)
        {
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        protected override IEnumerable<string> GetScanDirectories()
        {
            var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (Config.IncludePlugins)
            {
                AddIfPresent(Paths.PluginPath);
            }

            if (Config.IncludePatchers)
            {
                AddIfPresent(Paths.PatcherPluginPath);
            }

            if (Config.IncludeUserLibs)
            {
                AddIfPresent(Path.Combine(_environment.GameRootDirectory, "UserLibs"));
            }

            if (Config.IncludeMods)
            {
                AddIfPresent(Path.Combine(_environment.GameRootDirectory, "Mods"));
            }

            foreach (var scanDir in Config.ScanDirectories)
            {
                AddIfPresent(Path.IsPathRooted(scanDir)
                    ? scanDir
                    : Path.Combine(_environment.GameRootDirectory, scanDir));
            }

            foreach (var path in emitted)
            {
                yield return path;
            }

            void AddIfPresent(string path)
            {
                if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
                {
                    return;
                }

                emitted.Add(Path.GetFullPath(path));
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
