using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class TypeScanner
    {
        private readonly MethodScanner _methodScanner;
        private readonly SignalTracker _signalTracker;
        private readonly ReflectionDetector _reflectionDetector;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly IEnumerable<IScanRule> _rules;
        private readonly ScanConfig _config;

        public TypeScanner(MethodScanner methodScanner, SignalTracker signalTracker, ReflectionDetector reflectionDetector,
                          CodeSnippetBuilder snippetBuilder, IEnumerable<IScanRule> rules, ScanConfig config)
        {
            _methodScanner = methodScanner ?? throw new ArgumentNullException(nameof(methodScanner));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _reflectionDetector = reflectionDetector ?? throw new ArgumentNullException(nameof(reflectionDetector));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _config = config ?? new ScanConfig();
        }

        public IEnumerable<ScanFinding> ScanType(TypeDefinition type)
        {
            var findings = new List<ScanFinding>();

            try
            {
                string typeFullName = type.FullName;
                
                // Initialize type-level signal tracking for this type
                if (_config.EnableMultiSignalDetection)
                {
                    _signalTracker.GetOrCreateTypeSignals(typeFullName);
                }
                
                // Queue of pending reflection findings that need type-level signals to be confirmed
                var pendingReflectionFindings = new List<(MethodDefinition method, Instruction instruction, int index, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)>();
                
                // Scan methods in this type
                foreach (var method in type.Methods)
                {
                    var methodResult = _methodScanner.ScanMethod(method, typeFullName);
                    findings.AddRange(methodResult.Findings);
                    pendingReflectionFindings.AddRange(methodResult.PendingReflectionFindings);
                }
                
                // After scanning all methods, check pending reflection findings with type-level signals
                if (_config.EnableMultiSignalDetection)
                {
                    ProcessPendingReflectionFindings(pendingReflectionFindings, typeFullName, findings);
                }
                
                // Clear type signals after processing
                _signalTracker.ClearTypeSignals(typeFullName);

                // Recursively scan nested types
                foreach (var nestedType in type.NestedTypes)
                {
                    findings.AddRange(ScanType(nestedType));
                }
            }
            catch (Exception)
            {
                // Skip type if it can't be properly analyzed
            }

            return findings;
        }

        private void ProcessPendingReflectionFindings(List<(MethodDefinition method, Instruction instruction, int index, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)> pendingReflectionFindings,
                                                      string typeFullName, List<ScanFinding> findings)
        {
            if (pendingReflectionFindings.Count == 0)
                return;

            var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
            if (typeSignal == null)
                return;

            // Check if other rules have been triggered at type level (not just ReflectionRule)
            var reflectionRule = _rules.FirstOrDefault(r => r is ReflectionRule);
            if (reflectionRule == null)
                return;
                
            bool hasTypeLevelTriggeredRules = typeSignal.HasTriggeredRuleOtherThan(reflectionRule.RuleId);

            if (!hasTypeLevelTriggeredRules)
                return;

            // Process each pending reflection finding
            foreach (var (method, instruction, index, instructions, methodSignals) in pendingReflectionFindings)
            {
                var snippet = _snippetBuilder.BuildSnippet(instructions, index, 2);

                var finding = new ScanFinding(
                    $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}",
                    reflectionRule.Description + " (combined with other suspicious patterns detected in this type)",
                    reflectionRule.Severity,
                    snippet);
                findings.Add(finding);
                // Mark rule as triggered
                if (methodSignals != null)
                {
                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, reflectionRule.RuleId);
                }
            }
        }
    }
}

