using System;
using System.Collections.Generic;
using System.IO;
using MelonLoader.Utils;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services.Caching;
using MLVScan.Services;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader implementation of plugin scanner.
    /// Scans Mods/, Plugins/, and Thunderstore directories.
    /// </summary>
    public class MelonPluginScanner : PluginScannerBase
    {
        private readonly MelonPlatformEnvironment _environment;

        public MelonPluginScanner(
            IScanLogger logger,
            IAssemblyResolverProvider resolverProvider,
            MLVScanConfig config,
            IConfigManager configManager,
            MelonPlatformEnvironment environment)
            : base(logger, resolverProvider, config, configManager, environment)
        {
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        protected override IEnumerable<string> GetScanDirectories()
        {
            var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (Config.IncludeMods)
            {
                AddIfPresent(Path.Combine(_environment.GameRootDirectory, "Mods"));
            }

            if (Config.IncludePlugins)
            {
                AddIfPresent(Path.Combine(_environment.GameRootDirectory, "Plugins"));
            }

            if (Config.IncludeUserLibs)
            {
                AddIfPresent(Path.Combine(_environment.GameRootDirectory, "UserLibs"));
            }

            foreach (var scanDir in Config.ScanDirectories)
            {
                AddIfPresent(Path.IsPathRooted(scanDir)
                    ? scanDir
                    : Path.Combine(_environment.GameRootDirectory, scanDir));
            }

            if (Config.IncludeThunderstoreProfiles)
            {
                foreach (var thunderstoreRoot in GetThunderstoreDirectories())
                {
                    AddIfPresent(thunderstoreRoot);
                }
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

        /// <summary>
        /// Resolves Thunderstore profile mod folders from the Windows AppData layout only.
        /// GetThunderstoreDirectories uses RuntimeInformationHelper to skip non-Windows platforms.
        /// </summary>
        private static IEnumerable<string> GetThunderstoreDirectories()
        {
            if (!RuntimeInformationHelper.IsWindows)
            {
                yield break;
            }

            string appDataPath = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData);
            string thunderstoreBasePath = Path.Combine(appDataPath, "Thunderstore Mod Manager", "DataFolder");

            if (!Directory.Exists(thunderstoreBasePath))
            {
                yield break;
            }

            foreach (var gameFolder in Directory.GetDirectories(thunderstoreBasePath))
            {
                string profilesPath = Path.Combine(gameFolder, "profiles");
                if (!Directory.Exists(profilesPath))
                {
                    continue;
                }

                foreach (var profileFolder in Directory.GetDirectories(profilesPath))
                {
                    var modsPath = Path.Combine(profileFolder, "Mods");
                    if (Directory.Exists(modsPath))
                    {
                        yield return modsPath;
                    }

                    var pluginsPath = Path.Combine(profileFolder, "Plugins");
                    if (Directory.Exists(pluginsPath))
                    {
                        yield return pluginsPath;
                    }
                }
            }
        }
    }
}
