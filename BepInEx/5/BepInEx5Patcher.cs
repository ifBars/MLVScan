using System.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using MLVScan.Services;
using BepInEx;
using BepInEx.Logging;
using Mono.Cecil;
using MLVScan.BepInEx;
using MLVScan.BepInEx.Adapters;
using MLVScan.Services.Diagnostics;

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

                // Scan all plugins
                var scanResults = pluginScanner.ScanAllPlugins();

                if (scanResults.Count > 0)
                {
                    var disabledPlugins = pluginDisabler.DisableSuspiciousPlugins(scanResults);
                    var reviewOnlyCount = scanResults.Count - disabledPlugins.Count;

                    var pendingResult = scanResults.Values.FirstOrDefault(r => SharingConsentPolicy.IsReviewCandidate(r.ThreatVerdict, r.ScanStatus));
                    if (pendingResult != null)
                    {
                        if (SharingConsentPolicy.NeedsDecision(config))
                        {
                            config.ReportUploadConsentPending = true;
                            config.PendingReportUploadPath = pendingResult.FilePath;
                            var disabled = disabledPlugins.FirstOrDefault(d => d.OriginalPath == pendingResult.FilePath);
                            if (disabled != null && File.Exists(disabled.DisabledPath)) config.PendingReportUploadPath = disabled.DisabledPath;
                            config.PendingReportUploadVerdictKind = pendingResult.ThreatVerdict?.Kind.ToString() ?? string.Empty;
                            config.PendingReportUploadScanStatusKind = pendingResult.ScanStatus?.Kind.ToString() ?? string.Empty;
                            configManager.SaveConfig(config);
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
                else if (!config.EnableAutoScan)
                {
                    _logger.LogInfo("Automatic scanning is disabled in configuration.");
                }
                else
                {
                    _logger.LogInfo("No plugins requiring action were detected.");
                }

                _logger.LogInfo("MLVScan preloader scan complete.");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"MLVScan initialization failed: {ex}");
            }
        }

        private static void EnsureRuntimeConsentPluginPresent()
        {
            try
            {
                var source = typeof(BepInEx5Patcher).Assembly.Location;
                var destination = Path.Combine(Paths.PluginPath, Path.GetFileName(source));
                if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(destination), StringComparison.OrdinalIgnoreCase)) return;
                Directory.CreateDirectory(Paths.PluginPath);
                File.Copy(source, destination, true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Could not stage MLVScan sharing UI: {ex.Message}");
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
