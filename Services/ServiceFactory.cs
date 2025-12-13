using MelonLoader;
using MLVScan.Abstractions;
using MLVScan.Adapters;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan
{
    /// <summary>
    /// Factory for creating MLVScan services in the MelonLoader context.
    /// </summary>
    public class ServiceFactory
    {
        private readonly MelonLogger.Instance _logger;
        private readonly IScanLogger _scanLogger;
        private readonly IAssemblyResolverProvider _resolverProvider;
        private readonly ConfigManager _configManager;
        private readonly ScanConfig _fallbackConfig;

        public ServiceFactory(MelonLogger.Instance logger)
        {
            _logger = logger;
            _scanLogger = new MelonScanLogger(logger);
            _resolverProvider = new GameAssemblyResolverProvider();
            _fallbackConfig = new ScanConfig();

            try
            {
                _configManager = new ConfigManager(logger);
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to create ConfigManager: {ex.Message}");
                _logger.Msg("Using default configuration values");
            }
        }

        public ConfigManager CreateConfigManager()
        {
            return _configManager;
        }

        public AssemblyScanner CreateAssemblyScanner()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            var rules = RuleFactory.CreateDefaultRules();

            return new AssemblyScanner(rules, config, _resolverProvider);
        }

        public ModScanner CreateModScanner()
        {
            var assemblyScanner = CreateAssemblyScanner();
            var config = _configManager?.Config ?? _fallbackConfig;
            return new ModScanner(assemblyScanner, _logger, config, _configManager);
        }

        public ModDisabler CreateModDisabler()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new ModDisabler(_logger, config);
        }
        
        public PromptGeneratorService CreatePromptGenerator()
        {
            var config = _configManager?.Config ?? _fallbackConfig;
            return new PromptGeneratorService(config, _logger);
        }

        public IlDumpService CreateIlDumpService()
        {
            return new IlDumpService(_logger);
        }
    }
}
