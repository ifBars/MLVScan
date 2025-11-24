using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;

namespace MLVScan.Services
{
    public class DllImportScanner
    {
        private readonly IEnumerable<IScanRule> _rules;

        public DllImportScanner(IEnumerable<IScanRule> rules)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        }

        public IEnumerable<ScanFinding> ScanForDllImports(ModuleDefinition module)
        {
            var findings = new List<ScanFinding>();

            try
            {
                foreach (var type in TypeCollectionHelper.GetAllTypes(module))
                {
                    foreach (var method in type.Methods.Where(method => method.HasCustomAttributes))
                    {
                        try
                        {
                            var dllImportAttribute = method.CustomAttributes.FirstOrDefault(attr => attr.AttributeType.Name == "DllImportAttribute");
                            if (dllImportAttribute == null)
                                continue;

                            if (_rules.Any(rule => rule.IsSuspicious(method)))
                            {
                                var rule = _rules.First(r => r.IsSuspicious(method)); // Assuming one rule matches or taking the first
                                var snippet = $"[DllImport(\"{dllImportAttribute.ConstructorArguments.FirstOrDefault().Value}\")]\n{method.ReturnType.Name} {method.Name}({string.Join(", ", method.Parameters.Select(p => $"{p.ParameterType.Name} {p.Name}"))});";
                                findings.Add(new ScanFinding(
                                    $"{method.DeclaringType.FullName}.{method.Name}", 
                                    rule.Description, 
                                    rule.Severity,
                                    snippet));
                            }
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

            return findings;
        }
    }
}

