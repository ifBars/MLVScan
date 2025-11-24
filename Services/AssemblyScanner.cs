using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;

namespace MLVScan.Services
{
    public class AssemblyScanner
    {
        private readonly TypeScanner _typeScanner;
        private readonly MetadataScanner _metadataScanner;
        private readonly DllImportScanner _dllImportScanner;
        private readonly DefaultAssemblyResolver _assemblyResolver;
        private readonly ScanConfig _config;

        public AssemblyScanner(IEnumerable<IScanRule> rules, ScanConfig config = null)
        {
            _config = config ?? new ScanConfig();
            _assemblyResolver = AssemblyResolverFactory.Create();

            // Create all services using composition
            var snippetBuilder = new CodeSnippetBuilder();
            var signalTracker = new SignalTracker(_config);
            var stringPatternDetector = new StringPatternDetector();
            var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
            var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, _config);
            var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, _config);
            
            _typeScanner = new TypeScanner(methodScanner, signalTracker, reflectionDetector, snippetBuilder, rules, _config);
            _metadataScanner = new MetadataScanner(rules);
            _dllImportScanner = new DllImportScanner(rules);
        }

        public IEnumerable<ScanFinding> Scan(string assemblyPath)
        {
            if (string.IsNullOrWhiteSpace(assemblyPath))
                throw new ArgumentException("Assembly path must be provided", nameof(assemblyPath));

            if (!File.Exists(assemblyPath))
                throw new FileNotFoundException("Assembly file not found", assemblyPath);

            var findings = new List<ScanFinding>();

            try
            {
                var readerParameters = new ReaderParameters
                {
                    ReadWrite = false,
                    InMemory = true,
                    ReadSymbols = false,
                    AssemblyResolver = _assemblyResolver,
                };

                var assembly = AssemblyDefinition.ReadAssembly(assemblyPath, readerParameters);

                foreach (var module in assembly.Modules)
                {
                    // Scan assembly metadata for hidden payloads
                    if (_config.DetectAssemblyMetadata)
                    {
                        findings.AddRange(_metadataScanner.ScanAssemblyMetadata(assembly));
                    }

                    findings.AddRange(_dllImportScanner.ScanForDllImports(module));

                    foreach (var type in module.Types)
                    {
                        findings.AddRange(_typeScanner.ScanType(type));
                    }
                }
            }
            catch (Exception)
            {
                findings.Add(new ScanFinding(
                    "Assembly scanning",
                    "Warning: Some parts of the assembly could not be scanned. This doesn't necessarily mean the mod is malicious.",
                    Severity.Low));
            }

            if (findings.Count == 1 && findings[0].Location == "Assembly scanning" && string.IsNullOrEmpty(findings[0].CodeSnippet))
            {
                return new List<ScanFinding>();
            }

            return findings;
        }
    }
}
