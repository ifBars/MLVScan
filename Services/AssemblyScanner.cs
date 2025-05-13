using MelonLoader.Utils;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class AssemblyScanner
    {
        private readonly IEnumerable<IScanRule> _rules;
        private DefaultAssemblyResolver _assemblyResolver;

        public AssemblyScanner(IEnumerable<IScanRule> rules)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            InitializeResolver();
        }

        private void InitializeResolver()
        {
            _assemblyResolver = new DefaultAssemblyResolver();

            var gameDir = MelonEnvironment.GameRootDirectory;
            var melonDir = Path.Combine(gameDir, "MelonLoader");

            _assemblyResolver.AddSearchDirectory(gameDir);

            if (Directory.Exists(melonDir))
            {
                _assemblyResolver.AddSearchDirectory(melonDir);

                var managedDir = Path.Combine(melonDir, "Managed");
                if (Directory.Exists(managedDir))
                {
                    _assemblyResolver.AddSearchDirectory(managedDir);
                }

                var dependenciesDir = Path.Combine(melonDir, "Dependencies");
                if (Directory.Exists(dependenciesDir))
                {
                    _assemblyResolver.AddSearchDirectory(dependenciesDir);

                    foreach (var dir in Directory.GetDirectories(dependenciesDir, "*", SearchOption.AllDirectories))
                    {
                        _assemblyResolver.AddSearchDirectory(dir);
                    }
                }
            }

            var gameManagedDir = Path.Combine(gameDir, "Schedule I_Data", "Managed");
            if (Directory.Exists(gameManagedDir))
            {
                _assemblyResolver.AddSearchDirectory(gameManagedDir);
            }
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
                    ScanForDllImports(module, findings);

                    foreach (var type in module.Types)
                    {
                        ScanType(type, findings);
                    }
                }
            }
            catch (Exception ex)
            {
                findings.Add(new ScanFinding(
                    "Assembly scanning",
                    "Warning: Some parts of the assembly could not be scanned. This doesn't necessarily mean the mod is malicious.",
                    "Low"));
            }

            if (findings.Count == 1 && findings[0].Location == "Assembly scanning")
            {
                return new List<ScanFinding>();
            }

            return findings;
        }

        private void ScanForDllImports(ModuleDefinition module, List<ScanFinding> findings)
        {
            try
            {
                foreach (var type in GetAllTypes(module))
                {
                    foreach (var method in type.Methods.Where(method => method.HasCustomAttributes))
                    {
                        try
                        {
                            if (method.CustomAttributes.All(attr => attr.AttributeType.Name != "DllImportAttribute"))
                                continue;
                            findings.AddRange(from rule in _rules where rule.IsSuspicious(method) select new ScanFinding($"{method.DeclaringType.FullName}.{method.Name}", rule.Description, rule.Severity));
                        }
                        catch (Exception)
                        {
                            // Skip methods that can't be properly analyzed
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Skip module if it can't be properly analyzed
            }
        }

        private void ScanType(TypeDefinition type, List<ScanFinding> findings)
        {
            try
            {
                // Scan methods in this type
                foreach (var method in type.Methods)
                {
                    ScanMethod(method, findings);
                }

                // Recursively scan nested types
                foreach (var nestedType in type.NestedTypes)
                {
                    ScanType(nestedType, findings);
                }
            }
            catch (Exception)
            {
                // Skip type if it can't be properly analyzed
            }
        }

        private void ScanMethod(MethodDefinition method, List<ScanFinding> findings)
        {
            try
            {
                // Skip methods without a body (e.g., abstract or interface methods)
                if (!method.HasBody)
                    return;

                // Check all method references used in this method
                foreach (var instruction in method.Body.Instructions)
                {
                    try
                    {
                        if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) continue;
                        if (instruction.Operand is not MethodReference calledMethod) continue;
                        findings.AddRange(from rule in _rules where rule.IsSuspicious(calledMethod) select new ScanFinding($"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}", rule.Description, rule.Severity));
                    }
                    catch (Exception)
                    {
                        // Skip instruction if it can't be properly analyzed
                    }
                }
            }
            catch (Exception)
            {
                // Skip method if it can't be properly analyzed
            }
        }

        private IEnumerable<TypeDefinition> GetAllTypes(ModuleDefinition module)
        {
            var allTypes = new List<TypeDefinition>();

            try
            {
                // Add top-level types
                foreach (var type in module.Types)
                {
                    allTypes.Add(type);

                    // Add nested types
                    CollectNestedTypes(type, allTypes);
                }
            }
            catch (Exception)
            {
                // Ignore errors
            }

            return allTypes;
        }

        private void CollectNestedTypes(TypeDefinition type, List<TypeDefinition> allTypes)
        {
            try
            {
                foreach (var nestedType in type.NestedTypes)
                {
                    allTypes.Add(nestedType);
                    CollectNestedTypes(nestedType, allTypes);
                }
            }
            catch (Exception)
            {
                // Ignore errors
            }
        }
    }
}
