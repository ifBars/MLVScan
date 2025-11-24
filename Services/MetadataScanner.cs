using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;

namespace MLVScan.Services
{
    public class MetadataScanner
    {
        private readonly IEnumerable<IScanRule> _rules;

        public MetadataScanner(IEnumerable<IScanRule> rules)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        }

        public IEnumerable<ScanFinding> ScanAssemblyMetadata(AssemblyDefinition assembly)
        {
            var findings = new List<ScanFinding>();

            try
            {
                foreach (var rule in _rules)
                {
                    var ruleFindings = rule.AnalyzeAssemblyMetadata(assembly);
                    findings.AddRange(ruleFindings);
                }
            }
            catch (Exception)
            {
                // Skip metadata scanning if it fails
            }

            return findings;
        }
    }
}

