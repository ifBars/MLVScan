using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class MethodScanner
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly InstructionAnalyzer _instructionAnalyzer;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly ScanConfig _config;

        public MethodScanner(IEnumerable<IScanRule> rules, SignalTracker signalTracker, InstructionAnalyzer instructionAnalyzer, 
                            CodeSnippetBuilder snippetBuilder, ScanConfig config)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _instructionAnalyzer = instructionAnalyzer ?? throw new ArgumentNullException(nameof(instructionAnalyzer));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _config = config ?? new ScanConfig();
        }

        public class MethodScanResult
        {
            public List<ScanFinding> Findings { get; set; } = new List<ScanFinding>();
            public List<(MethodDefinition method, Instruction instruction, int index, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)> PendingReflectionFindings { get; set; } = new List<(MethodDefinition, Instruction, int, Mono.Collections.Generic.Collection<Instruction>, MethodSignals)>();
        }

        public MethodScanResult ScanMethod(MethodDefinition method, string typeFullName)
        {
            var result = new MethodScanResult();

            try
            {
                // Skip methods without a body (e.g., abstract or interface methods)
                if (!method.HasBody)
                    return result;

                var instructions = method.Body.Instructions;

                // Initialize signal tracking for this method
                var methodSignals = _signalTracker.CreateMethodSignals();
                
                // Call AnalyzeInstructions for all rules
                foreach (var rule in _rules)
                {
                    var ruleFindings = rule.AnalyzeInstructions(method, instructions, methodSignals);
                    foreach (var finding in ruleFindings)
                    {
                        result.Findings.Add(finding);
                        // Update signals if encoded strings were detected
                        if (methodSignals != null && 
                            (rule is EncodedStringLiteralRule || 
                             rule is EncodedStringPipelineRule || 
                             rule is EncodedBlobSplittingRule))
                        {
                            _signalTracker.MarkEncodedStrings(methodSignals, method.DeclaringType);
                        }
                    }
                }
                
                // Scan for encoded strings in all ldstr instructions
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];

                    // Check for encoded strings using rule analysis
                    if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string strLiteral)
                    {
                        foreach (var rule in _rules)
                        {
                            var ruleFindings = rule.AnalyzeStringLiteral(strLiteral, method, i);
                            foreach (var finding in ruleFindings)
                            {
                                result.Findings.Add(finding);
                                // Update signals if encoded strings were detected
                                if (methodSignals != null)
                                {
                                    _signalTracker.MarkEncodedStrings(methodSignals, method.DeclaringType);
                                }
                            }
                        }
                    }
                }

                // Analyze instructions for method calls and suspicious patterns
                var instructionResult = _instructionAnalyzer.AnalyzeInstructions(method, instructions, methodSignals, typeFullName);
                result.Findings.AddRange(instructionResult.Findings);
                result.PendingReflectionFindings.AddRange(instructionResult.PendingReflectionFindings);

                // After scanning all instructions, check for multi-signal combinations
                if (methodSignals != null && _config.EnableMultiSignalDetection)
                {
                    if (methodSignals.IsCriticalCombination())
                    {
                        result.Findings.Add(new ScanFinding(
                            $"{method.DeclaringType.FullName}.{method.Name}",
                            $"Critical: Multiple suspicious patterns detected ({methodSignals.GetCombinationDescription()})",
                            Severity.Critical,
                            $"This method contains {methodSignals.SignalCount} suspicious signals that form a likely malicious pattern."));
                    }
                    else if (methodSignals.IsHighRiskCombination())
                    {
                        result.Findings.Add(new ScanFinding(
                            $"{method.DeclaringType.FullName}.{method.Name}",
                            $"High risk: Multiple suspicious patterns detected ({methodSignals.GetCombinationDescription()})",
                            Severity.High,
                            $"This method contains {methodSignals.SignalCount} suspicious signals."));
                    }
                }
            }
            catch (Exception)
            {
                // Skip method if it can't be properly analyzed
            }

            return result;
        }
    }
}

