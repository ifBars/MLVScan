using System;
using System.IO;
using MelonLoader.Utils;
using MLVScan.Abstractions;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader implementation of IPlatformEnvironment.
    /// Uses MelonEnvironment for path resolution.
    /// </summary>
    public class MelonPlatformEnvironment : IPlatformEnvironment
    {
        private readonly string _gameRoot;
        private readonly string _dataDir;
        private readonly string _reportsDir;

        public MelonPlatformEnvironment()
        {
            _gameRoot = MelonEnvironment.GameRootDirectory;
            _dataDir = Path.Combine(_gameRoot, "MLVScan");
            _reportsDir = Path.Combine(_dataDir, "Reports");
        }

        public string GameRootDirectory => _gameRoot;

        public string[] PluginDirectories => new[]
        {
            Path.Combine(_gameRoot, "Mods"),
            Path.Combine(_gameRoot, "Plugins")
        };

        public string DataDirectory
        {
            get
            {
                if (!Directory.Exists(_dataDir))
                    Directory.CreateDirectory(_dataDir);
                return _dataDir;
            }
        }

        public string ReportsDirectory
        {
            get
            {
                if (!Directory.Exists(_reportsDir))
                    Directory.CreateDirectory(_reportsDir);
                return _reportsDir;
            }
        }

        public string ManagedDirectory
        {
            get
            {
                // Unity managed assemblies location
                var managedPath = Path.Combine(_gameRoot, "Schedule I_Data", "Managed");
                if (Directory.Exists(managedPath))
                    return managedPath;

                // Fallback for Il2Cpp games
                var il2cppPath = Path.Combine(_gameRoot, "MelonLoader", "Managed");
                if (Directory.Exists(il2cppPath))
                    return il2cppPath;

                return string.Empty;
            }
        }

        public string SelfAssemblyPath
        {
            get
            {
                try
                {
                    return typeof(MelonPlatformEnvironment).Assembly.Location;
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        public string PlatformName => "MelonLoader";
    }
}
