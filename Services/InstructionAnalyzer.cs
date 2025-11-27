using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class InstructionAnalyzer
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly ReflectionDetector _reflectionDetector;
        private readonly StringPatternDetector _stringPatternDetector;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly ScanConfig _config;

        public InstructionAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker, ReflectionDetector reflectionDetector, 
                                   StringPatternDetector stringPatternDetector, CodeSnippetBuilder snippetBuilder, ScanConfig config)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _reflectionDetector = reflectionDetector ?? throw new ArgumentNullException(nameof(reflectionDetector));
            _stringPatternDetector = stringPatternDetector ?? throw new ArgumentNullException(nameof(stringPatternDetector));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _config = config ?? new ScanConfig();
        }

        public class InstructionAnalysisResult
        {
            public List<ScanFinding> Findings { get; set; } = new List<ScanFinding>();
            public List<(MethodDefinition method, Instruction instruction, int index, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)> PendingReflectionFindings { get; set; } = new List<(MethodDefinition, Instruction, int, Mono.Collections.Generic.Collection<Instruction>, MethodSignals)>();
        }

        public InstructionAnalysisResult AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, 
                                                          MethodSignals methodSignals, string typeFullName)
        {
            var result = new InstructionAnalysisResult();

            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                try
                {
                    // Check for direct method calls
                    if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                        instruction.Operand is MethodReference calledMethod)
                    {
                        // Track signals for multi-pattern detection
                        if (methodSignals != null)
                        {
                            _signalTracker.UpdateMethodSignals(methodSignals, calledMethod, method.DeclaringType);

                            // Check for Environment.GetFolderPath with sensitive folder values (for signal tracking)
                            if (calledMethod.DeclaringType?.FullName == "System.Environment" &&
                                calledMethod.Name == "GetFolderPath")
                            {
                                var folderValue = InstructionHelper.ExtractFolderPathArgument(instructions, i);
                                if (folderValue.HasValue && EnvironmentPathRule.IsSensitiveFolder(folderValue.Value))
                                {
                                    _signalTracker.MarkSensitiveFolder(methodSignals, method.DeclaringType);
                                }
                            }
                        }

                        // Call AnalyzeContextualPattern for all rules
                        foreach (var rule in _rules)
                        {
                            var ruleFindings = rule.AnalyzeContextualPattern(calledMethod, instructions, i, methodSignals);
                            foreach (var finding in ruleFindings)
                            {
                                // If rule requires companion finding, check if other rules have been triggered
                                // Exception: Low severity findings are always allowed (e.g., legitimate update checkers)
                                if (rule.RequiresCompanionFinding && finding.Severity != Severity.Low)
                                {
                                    bool hasOtherTriggeredRules = methodSignals != null && 
                                        methodSignals.HasTriggeredRuleOtherThan(rule.RuleId);
                                    
                                    // Also check type-level triggered rules
                                    bool hasTypeLevelTriggeredRules = false;
                                    if (!string.IsNullOrEmpty(typeFullName))
                                    {
                                        var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
                                        if (typeSignal != null)
                                        {
                                            hasTypeLevelTriggeredRules = typeSignal.HasTriggeredRuleOtherThan(rule.RuleId);
                                        }
                                    }
                                    
                                    // Only add finding if other rules have been triggered
                                    if (!hasOtherTriggeredRules && !hasTypeLevelTriggeredRules)
                                        continue;
                                }
                                
                                result.Findings.Add(finding);
                                // Mark rule as triggered
                                if (methodSignals != null)
                                {
                                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                                }
                            }
                        }

                        // For reflection invocations, only flag if combined with other malicious patterns
                        bool isReflectionInvoke = _reflectionDetector.IsReflectionInvokeMethod(calledMethod);
                        if (isReflectionInvoke)
                        {
                            var reflectionRule = _rules.FirstOrDefault(r => r is ReflectionRule);
                            if (reflectionRule == null)
                                continue;
                            
                            // Check if other rules have been triggered (not just ReflectionRule)
                            bool hasOtherTriggeredRules = methodSignals != null && 
                                methodSignals.HasTriggeredRuleOtherThan(reflectionRule.RuleId);
                            
                            // Also check type-level triggered rules
                            bool hasTypeLevelTriggeredRules = false;
                            if (!string.IsNullOrEmpty(typeFullName))
                            {
                                var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
                                if (typeSignal != null)
                                {
                                    hasTypeLevelTriggeredRules = typeSignal.HasTriggeredRuleOtherThan(reflectionRule.RuleId);
                                }
                            }
                            
                            // If no other rules have been triggered, queue for later processing
                            if (!hasOtherTriggeredRules && !hasTypeLevelTriggeredRules)
                            {
                                // Queue for later processing after all methods in type are scanned
                                if (_config.EnableMultiSignalDetection && method.DeclaringType != null)
                                {
                                    result.PendingReflectionFindings.Add((method, instruction, i, instructions, methodSignals));
                                }
                                continue;
                            }
                            
                            // Reflection combined with other triggered rules is suspicious
                            var snippet = _snippetBuilder.BuildSnippet(instructions, i, 2);
                            
                            var finding = new ScanFinding(
                                $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}", 
                                reflectionRule.Description + " (combined with other suspicious patterns)", 
                                reflectionRule.Severity,
                                snippet);
                            result.Findings.Add(finding);
                            // Mark rule as triggered
                            if (methodSignals != null)
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, reflectionRule.RuleId);
                            }
                        }
                        else if (_rules.Any(r => r.IsSuspicious(calledMethod)))
                        {
                            var rule = _rules.First(r => r.IsSuspicious(calledMethod));
                            var snippet = _snippetBuilder.BuildSnippet(instructions, i, 2);
                            
                            var finding = new ScanFinding(
                                $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}", 
                                rule.Description, 
                                rule.Severity,
                                snippet);
                            result.Findings.Add(finding);
                            // Mark rule as triggered
                            if (methodSignals != null)
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                            }
                        }
                        
                        // Check for reflection-based calls that might bypass detection
                        var reflectionFindings = _reflectionDetector.ScanForReflectionInvocation(method, instruction, calledMethod, i, instructions, methodSignals);
                        foreach (var finding in reflectionFindings)
                        {
                            result.Findings.Add(finding);
                            // Mark ReflectionRule as triggered if this is a reflection finding
                            if (methodSignals != null)
                            {
                                var reflectionRule = _rules.FirstOrDefault(r => r is ReflectionRule);
                                if (reflectionRule != null)
                                {
                                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, reflectionRule.RuleId);
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // Skip instruction if it can't be properly analyzed
                }
            }

            return result;
        }
    }
}

