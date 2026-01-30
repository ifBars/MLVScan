using System;
using System.IO;
using BepInEx;
using MLVScan.Abstractions;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx implementation of IPlatformEnvironment.
    /// Uses BepInEx.Paths for path resolution.
    /// </summary>
    public class BepInExPlatformEnvironment : IPlatformEnvironment
    {
        private readonly string _dataDir;
        private readonly string _reportsDir;
        private readonly string[] _pluginDirectories;

        public BepInExPlatformEnvironment()
        {
            _dataDir = Path.Combine(Paths.BepInExRootPath, "MLVScan");
            _reportsDir = Path.Combine(_dataDir, "Reports");
            _pluginDirectories = new[] { Paths.PluginPath };
        }

        public string GameRootDirectory => Paths.GameRootPath;

        public string[] PluginDirectories => _pluginDirectories;

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

        public string ManagedDirectory => Paths.ManagedPath;

        public string SelfAssemblyPath
        {
            get
            {
                try
                {
                    return typeof(BepInExPlatformEnvironment).Assembly.Location;
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        public string PlatformName => "BepInEx";
    }
}
