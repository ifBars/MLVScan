using System;
using MelonLoader;
using MLVScan.Abstractions;
using MLVScan.Adapters;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.Diagnostics;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// Factory for creating MLVScan services in the MelonLoader context.
    /// </summary>
    public class MelonLoaderServiceFactory
    {
        private readonly MelonLogger.Instance _melonLogger;
        private readonly IScanLogger _scanLogger;
        private readonly IAssemblyResolverProvider _resolverProvider;
        private readonly MelonConfigManager _configManager;
        private readonly MelonPlatformEnvironment _environment;
        private readonly MLVScanConfig _fallbackConfig;
        private readonly LoaderScanTelemetryHub _telemetry;

        public MelonLoaderServiceFactory(MelonLogger.Instance logger)
        {
            _melonLogger = logger ?? throw new ArgumentNullException(nameof(logger));
            _scanLogger = new MelonScanLogger(logger);
            _telemetry = new LoaderScanTelemetryHub();
            _resolverProvider = new GameAssemblyResolverProvider(_telemetry);
            _environment = new MelonPlatformEnvironment();
            _fallbackConfig = new MLVScanConfig();

            try
            {
                _configManager = new MelonConfigManager(logger);
            }
            catch (Exception ex)
            {
                _melonLogger.Error($"Failed to create ConfigManager: {ex.Message}");
                _melonLogger.Msg("Using default configuration values");
            }
        }

        /// <summary>
        /// Creates the configuration manager.
        /// </summary>
        /// <returns>The MelonConfigManager instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the configuration manager is unavailable due to initialization failure.</exception>
        public MelonConfigManager CreateConfigManager()
        {
            if (_configManager == null)
            {
                throw new InvalidOperationException("Configuration manager unavailable: failed to initialize during factory construction.");
            }
            return _configManager;
        }

        public MelonPlatformEnvironment CreateEnvironment()
        {
            return _environment;
        }

        public AssemblyScanner CreateAssemblyScanner()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            var rules = RuleFactory.CreateDefaultRules();

            return new AssemblyScanner(rules, config.Scan, _resolverProvider);
        }

        public MelonPluginScanner CreatePluginScanner()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new MelonPluginScanner(
                _scanLogger,
                _resolverProvider,
                config,
                _configManager,
                _environment,
                _telemetry);
        }

        public MelonPluginDisabler CreatePluginDisabler()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new MelonPluginDisabler(_scanLogger, config);
        }

        public PromptGeneratorService CreatePromptGenerator()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new PromptGeneratorService(config.Scan, _scanLogger);
        }

        public IlDumpService CreateIlDumpService()
        {
            return new IlDumpService(_scanLogger, _environment);
        }

        public DeveloperReportGenerator CreateDeveloperReportGenerator()
        {
            return new DeveloperReportGenerator(_scanLogger);
        }

        public ReportUploadService CreateReportUploadService()
        {
            return new ReportUploadService(
                _configManager,
                msg => _melonLogger.Msg(msg),
                msg => _melonLogger.Warning(msg),
                msg => _melonLogger.Error(msg));
        }
    }
}
