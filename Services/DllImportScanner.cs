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
                    foreach (var method in type.Methods)
                    {
                        try
                        {
                            // Check if this is a PInvoke method
                            if ((method.Attributes & MethodAttributes.PInvokeImpl) == 0)
                                continue;

                            if (method.PInvokeInfo == null)
                                continue;

                            if (_rules.Any(rule => rule.IsSuspicious(method)))
                            {
                                var rule = _rules.First(r => r.IsSuspicious(method));
                                var dllName = method.PInvokeInfo.Module.Name;
                                var entryPoint = method.PInvokeInfo.EntryPoint ?? method.Name;
                                var snippet = $"[DllImport(\"{dllName}\", EntryPoint = \"{entryPoint}\")]\n{method.ReturnType.Name} {method.Name}({string.Join(", ", method.Parameters.Select(p => $"{p.ParameterType.Name} {p.Name}"))});";
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

