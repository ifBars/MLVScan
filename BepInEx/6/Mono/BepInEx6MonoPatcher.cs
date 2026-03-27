using System;
using System.IO;
using BepInEx;
using BepInEx.Logging;
using BepInEx.Preloader.Core.Patching;
using MLVScan.BepInEx;
using MLVScan.BepInEx.Adapters;
using MLVScan.Services.Diagnostics;

namespace MLVScan.BepInEx6.Mono
{
    /// <summary>
    /// BepInEx 6.x (Mono) preloader patcher that scans plugins for malicious patterns
    /// before the chainloader initializes them.
    /// </summary>
    [PatcherPluginInfo("com.bars.mlvscan", "MLVScan", PlatformConstants.PlatformVersion)]
    public class BepInEx6MonoPatcher : BasePatcher
    {
        private ManualLogSource _logger;

        /// <summary>
        /// Called when the patcher is initialized.
        /// This is the main entry point for BepInEx 6.x patchers.
        /// </summary>
        public override void Initialize()
        {
            _logger = Logger.CreateLogSource("MLVScan");

            try
            {
                _logger.LogInfo("MLVScan BepInEx 6 (Mono) patcher initializing...");
                _logger.LogInfo($"Plugin directory: {Paths.PluginPath}");

                EnsureRuntimeConsentPluginPresent();

                // Create platform environment
                var environment = new BepInExPlatformEnvironment();
                var telemetry = new LoaderScanTelemetryHub();

                // Load or create configuration
                var configManager = new BepInExConfigManager(_logger);
                var config = configManager.LoadConfig();

                // Create adapters
                var scanLogger = new BepInExScanLogger(_logger);
                var resolverProvider = new BepInExAssemblyResolverProvider(telemetry);

                // Create scanner and disabler
                var pluginScanner = new BepInExPluginScanner(
                    scanLogger,
                    resolverProvider,
                    config,
                    configManager,
                    environment,
                    telemetry);

                var pluginDisabler = new BepInExPluginDisabler(scanLogger, config);
                var reportGenerator = new BepInExReportGenerator(_logger, config, configManager.GetReportUploadApiBaseUrl(), configManager);

                if (!config.EnableAutoScan)
                {
                    _logger.LogInfo("Auto-scan is disabled. Skipping plugin scan.");
                }
                else
                {
                    var scanResults = pluginScanner.ScanAllPlugins();

                    if (scanResults.Count > 0)
                    {
                        var disabledPlugins = pluginDisabler.DisableSuspiciousPlugins(scanResults);
                        var reviewOnlyCount = scanResults.Count - disabledPlugins.Count;

                        if (disabledPlugins.Count > 0)
                        {
                            // Queue first-run GUI consent for runtime plugin.
                            if (!config.ReportUploadConsentAsked)
                            {
                                var firstDisabled = disabledPlugins[0];
                                config.ReportUploadConsentPending = true;
                                config.PendingReportUploadPath =
                                    File.Exists(firstDisabled.DisabledPath) ? firstDisabled.DisabledPath : firstDisabled.OriginalPath;
                                config.PendingReportUploadVerdictKind = firstDisabled.ThreatVerdict?.Kind.ToString() ?? string.Empty;
                                configManager.SaveConfig(config);
                                _logger.LogInfo("MLVScan will show an in-game upload consent popup.");
                            }
                        }

                        reportGenerator.GenerateReports(disabledPlugins, scanResults);

                        if (disabledPlugins.Count > 0)
                        {
                            _logger.LogWarning($"MLVScan blocked {disabledPlugins.Count} plugin(s).");
                        }

                        if (reviewOnlyCount > 0)
                        {
                            _logger.LogWarning($"MLVScan flagged {reviewOnlyCount} plugin(s) for manual review without blocking them.");
                        }

                        _logger.LogWarning("Check BepInEx/MLVScan/Reports/ for details.");
                    }
                    else
                    {
                        _logger.LogInfo("No plugins requiring action were detected.");
                    }
                }

                _logger.LogInfo("MLVScan BepInEx 6 (Mono) preloader scan complete.");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"MLVScan initialization failed: {ex}");
            }
        }

        /// <summary>
        /// Called when all patching is complete.
        /// </summary>
        public override void Finalizer()
        {
            _logger?.LogDebug("MLVScan patcher finished.");
        }

        private void EnsureRuntimeConsentPluginPresent()
        {
            try
            {
                var sourcePath = GetType().Assembly.Location;
                if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
                {
                    return;
                }

                Directory.CreateDirectory(Paths.PluginPath);
                var destinationPath = Path.Combine(Paths.PluginPath, Path.GetFileName(sourcePath));
                File.Copy(sourcePath, destinationPath, true);
                _logger.LogDebug($"Ensured runtime consent plugin at: {destinationPath}");
            }
            catch (Exception ex)
            {
                _logger?.LogWarning($"Failed to stage runtime consent plugin: {ex.Message}");
            }
        }
    }
}
