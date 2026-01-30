using System;
using System.Collections.Generic;
using BepInEx;
using BepInEx.Logging;
using Mono.Cecil;
using MLVScan.BepInEx;
using MLVScan.BepInEx.Adapters;

namespace MLVScan.BepInEx5
{
    /// <summary>
    /// BepInEx 5.x preloader patcher that scans plugins for malicious patterns
    /// before the chainloader initializes them.
    /// </summary>
    public static class BepInEx5Patcher
    {
        private static ManualLogSource _logger;

        /// <summary>
        /// Default whitelist for known-safe BepInEx ecosystem plugins.
        /// </summary>
        private static readonly string[] DefaultWhitelistedHashes =
        [
            // BepInEx ecosystem - known safe plugins
            "8c0735f521d0fa785bf81b2e627a93042362b736ebc2c4c7ac425276b49fa692",
            "9f86b196ffc845bdbc85192054e2876388ce1294b5a880459c93cbed7de2ae9d",
            "bc67dab59532d0daca129e574c87d43b24a0b63ccb7312ccd25e0d7c4887784c",
            "f1f3ff967bdb8f63a4bfd878255890f6393af37d3cc357babb6b504d9473ee06",
            "d034d0e941deb47ea6b5ee8ca288bdb1d0bb25475dfba02cb61f6eadf0fa448e",
            "e28b71abefdb5c2e90ea2d9e3c79bdff95f8173d08022732f62f35d2c328895d",
            "bd5ec0343880b528ef190afe91778d172a239a625929dc176492eddc5c66cc31",
            "503f851721ffacc7839e42d7c6c8a7c39fa2cea6e70a480b8bad822064d65aa0",
            "184386c0f5f5bae6b63c96b73e312d3f39eba0d0ca81de3e3bd574ef389d1e29"
        ];

        /// <summary>
        /// Required: Declares which assemblies to patch.
        /// Empty = we don't patch game assemblies, just use Initialize() as entry point.
        /// </summary>
        public static IEnumerable<string> TargetDLLs { get; } = Array.Empty<string>();

        /// <summary>
        /// Required: Patching method (no-op - we don't modify game code).
        /// </summary>
        public static void Patch(AssemblyDefinition assembly) { }

        /// <summary>
        /// Called before patching - our main entry point.
        /// Runs BEFORE the chainloader loads any plugins.
        /// </summary>
        public static void Initialize()
        {
            _logger = Logger.CreateLogSource("MLVScan");

            try
            {
                _logger.LogInfo("MLVScan preloader patcher initializing...");
                _logger.LogInfo($"Plugin directory: {Paths.PluginPath}");

                // Create platform environment
                var environment = new BepInExPlatformEnvironment();

                // Load or create configuration
                var configManager = new BepInExConfigManager(_logger, DefaultWhitelistedHashes);
                var config = configManager.LoadConfig();

                // Create adapters
                var scanLogger = new BepInExScanLogger(_logger);
                var resolverProvider = new BepInExAssemblyResolverProvider();

                // Create scanner and disabler
                var pluginScanner = new BepInExPluginScanner(
                    scanLogger,
                    resolverProvider,
                    config,
                    configManager,
                    environment);

                var pluginDisabler = new BepInExPluginDisabler(scanLogger, config);
                var reportGenerator = new BepInExReportGenerator(_logger, config);

                // Scan all plugins
                var scanResults = pluginScanner.ScanAllPlugins();

                if (scanResults.Count > 0)
                {
                    // Disable suspicious plugins
                    var disabledPlugins = pluginDisabler.DisableSuspiciousPlugins(scanResults);

                    // Generate reports for disabled plugins
                    if (disabledPlugins.Count > 0)
                    {
                        reportGenerator.GenerateReports(disabledPlugins, scanResults);

                        _logger.LogWarning($"MLVScan blocked {disabledPlugins.Count} suspicious plugin(s).");
                        _logger.LogWarning("Check BepInEx/MLVScan/Reports/ for details.");
                    }
                }
                else if (!config.EnableAutoScan)
                {
                    _logger.LogInfo("Automatic scanning is disabled in configuration.");
                }
                else
                {
                    _logger.LogInfo("No suspicious plugins detected.");
                }
                }

                _logger.LogInfo("MLVScan preloader scan complete.");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"MLVScan initialization failed: {ex}");
            }
        }

        /// <summary>
        /// Called after all patching and assembly loading is complete.
        /// </summary>
        public static void Finish()
        {
            // Optional: cleanup, final summary logging
            _logger?.LogDebug("MLVScan patcher finished.");
        }
    }
}
