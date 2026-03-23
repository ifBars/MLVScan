using System;
using System.Collections.Generic;
using System.IO;
using MelonLoader.Utils;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services.Caching;
using MLVScan.Services.Diagnostics;
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
            MelonPlatformEnvironment environment,
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
                Path.GetFullPath(Path.Combine(_environment.GameRootDirectory, "Mods")),
                Path.GetFullPath(Path.Combine(_environment.GameRootDirectory, "Plugins")),
                Path.GetFullPath(Path.Combine(_environment.GameRootDirectory, "UserLibs"))
            };

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

            foreach (var scanDir in Config.ScanDirectories ?? Array.Empty<string>())
            {
                AddLegacyIfPresent(scanDir);
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

            AddIfPresent(Path.Combine(_environment.GameRootDirectory, "Mods"));
            AddIfPresent(Path.Combine(_environment.GameRootDirectory, "Plugins"));
            AddIfPresent(Path.Combine(_environment.GameRootDirectory, "UserLibs"));

            foreach (var scanDir in Config.ScanDirectories)
            {
                AddIfPresent(Path.IsPathRooted(scanDir)
                    ? scanDir
                    : Path.Combine(_environment.GameRootDirectory, scanDir));
            }

            foreach (var thunderstoreRoot in GetThunderstoreDirectories())
            {
                AddIfPresent(thunderstoreRoot);
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

            foreach (var gameFolder in SafeGetDirectories(thunderstoreBasePath))
            {
                string profilesPath = Path.Combine(gameFolder, "profiles");
                if (!Directory.Exists(profilesPath))
                {
                    continue;
                }

                foreach (var profileFolder in SafeGetDirectories(profilesPath))
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

        private static IEnumerable<string> SafeGetDirectories(string path)
        {
            string[] directories;
            try
            {
                directories = Directory.GetDirectories(path);
            }
            catch (UnauthorizedAccessException)
            {
                yield break;
            }
            catch (DirectoryNotFoundException)
            {
                yield break;
            }
            catch (IOException)
            {
                yield break;
            }

            foreach (var directory in directories)
            {
                yield return directory;
            }
        }
    }
}
