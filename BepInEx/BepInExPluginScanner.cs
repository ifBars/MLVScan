using System;
using System.Collections.Generic;
using System.IO;
using BepInEx;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.Diagnostics;

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
            BepInExPlatformEnvironment environment,
            LoaderScanTelemetryHub telemetry)
            : base(logger, resolverProvider, config, configManager, environment, telemetry)
        {
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        protected override IEnumerable<string> GetScanDirectories()
        {
            var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var builtInRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Path.GetFullPath(Paths.PluginPath),
                Path.GetFullPath(Paths.PatcherPluginPath),
                Path.GetFullPath(Path.Combine(_environment.GameRootDirectory, "UserLibs")),
                Path.GetFullPath(Path.Combine(_environment.GameRootDirectory, "Mods"))
            };

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

            foreach (var scanDir in Config.ScanDirectories ?? Array.Empty<string>())
            {
                AddLegacyIfPresent(scanDir);
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

            void AddLegacyIfPresent(string scanDir)
            {
                if (string.IsNullOrWhiteSpace(scanDir))
                {
                    return;
                }

                var resolvedPath = Path.GetFullPath(Path.IsPathRooted(scanDir)
                    ? scanDir
                    : Path.Combine(_environment.GameRootDirectory, scanDir));

                if (builtInRoots.Contains(resolvedPath))
                {
                    return;
                }

                AddIfPresent(resolvedPath);
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

        protected override IEnumerable<string> GetResolverDirectories()
        {
            var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            AddIfPresent(Paths.PluginPath);
            AddIfPresent(Paths.PatcherPluginPath);
            AddIfPresent(Path.Combine(_environment.GameRootDirectory, "UserLibs"));
            AddIfPresent(Path.Combine(_environment.GameRootDirectory, "Mods"));

            foreach (var scanDir in Config.ScanDirectories ?? Array.Empty<string>())
            {
                AddIfPresent(Path.IsPathRooted(scanDir)
                    ? scanDir
                    : Path.Combine(_environment.GameRootDirectory, scanDir));
            }

            return emitted;

            void AddIfPresent(string path)
            {
                if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
                {
                    return;
                }

                emitted.Add(Path.GetFullPath(path));
            }
        }
    }
}
