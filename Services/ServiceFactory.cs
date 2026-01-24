using System;
using MelonLoader;
using MLVScan.Abstractions;
using MLVScan.Adapters;
using MLVScan.MelonLoader;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan
{
    /// <summary>
    /// Factory for creating MLVScan services in the MelonLoader context.
    /// </summary>
    public class ServiceFactory
    {
        private readonly MelonLogger.Instance _melonLogger;
        private readonly IScanLogger _scanLogger;
        private readonly IAssemblyResolverProvider _resolverProvider;
        private readonly MelonConfigManager _configManager;
        private readonly MelonPlatformEnvironment _environment;
        private readonly ScanConfig _fallbackConfig;

        public ServiceFactory(MelonLogger.Instance logger)
        {
            _melonLogger = logger ?? throw new ArgumentNullException(nameof(logger));
            _scanLogger = new MelonScanLogger(logger);
            _resolverProvider = new GameAssemblyResolverProvider();
            _environment = new MelonPlatformEnvironment();
            _fallbackConfig = new ScanConfig();

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

        public MelonConfigManager CreateConfigManager()
        {
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

            return new AssemblyScanner(rules, config, _resolverProvider);
        }

        public MelonPluginScanner CreatePluginScanner()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new MelonPluginScanner(
                _scanLogger,
                _resolverProvider,
                config,
                _configManager,
                _environment);
        }

        public MelonPluginDisabler CreatePluginDisabler()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new MelonPluginDisabler(_scanLogger, config);
        }

        public PromptGeneratorService CreatePromptGenerator()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new PromptGeneratorService(config, _scanLogger);
        }

        public IlDumpService CreateIlDumpService()
        {
            return new IlDumpService(_scanLogger, _environment);
        }

        public DeveloperReportGenerator CreateDeveloperReportGenerator()
        {
            return new DeveloperReportGenerator(_scanLogger);
        }
    }
}
