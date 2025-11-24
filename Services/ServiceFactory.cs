using MelonLoader;
using MLVScan.Models;

namespace MLVScan.Services
{
    public class ServiceFactory
    {
        private readonly MelonLogger.Instance _logger;
        private readonly ConfigManager _configManager;
        private readonly ScanConfig _fallbackConfig;

        public ServiceFactory(MelonLogger.Instance logger)
        {
            _logger = logger;
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

            var rules = new List<IScanRule>
            {
                new Base64Rule(),
                new ProcessStartRule(),
                new Shell32Rule(),
                new LoadFromStreamRule(),
                new ByteArrayManipulationRule(),
                new DllImportRule(),
                new RegistryRule(),
                new EncodedStringLiteralRule(),
                new ReflectionRule(),
                new EnvironmentPathRule(),
                new EncodedStringPipelineRule(),
                new EncodedBlobSplittingRule()
            };

            return new AssemblyScanner(rules, config);
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
