using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class ReflectionDetector
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly StringPatternDetector _stringPatternDetector;
        private readonly CodeSnippetBuilder _snippetBuilder;

        public ReflectionDetector(IEnumerable<IScanRule> rules, SignalTracker signalTracker, StringPatternDetector stringPatternDetector, CodeSnippetBuilder snippetBuilder)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _stringPatternDetector = stringPatternDetector ?? throw new ArgumentNullException(nameof(stringPatternDetector));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
        }

        public bool IsReflectionInvokeMethod(MethodReference method)
        {
            // Check for various reflection invocation patterns
            if (method.DeclaringType == null) return false;
            
            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;
            
            // Check for malicious reflection patterns
            // We only want to detect suspicious invocations, not all reflection usage
            
            // Type.InvokeMember - this is the main method used for COM object invocation
            if (typeName == "System.Type" && methodName == "InvokeMember")
                return true;
                
            // GetTypeFromProgID with Shell.Application is highly suspicious
            if (typeName == "System.Type" && methodName == "GetTypeFromProgID")
                return true;
                
            // Activator.CreateInstance can be used to create COM objects
            if (typeName == "System.Activator" && methodName == "CreateInstance")
                return true;
                
            // Combination of Type.GetTypeFromProgID and subsequent invocation
            if ((typeName == "System.Type" && methodName == "GetTypeFromProgID") || 
                (typeName == "System.Type" && methodName == "GetTypeFromCLSID"))
            {
                // Look for parameter that indicates shell access
                foreach (var param in method.Parameters)
                {
                    if (param.Name.Contains("Shell") || param.Name.Contains("Command") || 
                        param.Name.Contains("Process") || param.Name.Contains("Exec"))
                        return true;
                }
            }
                
            // MethodInfo.Invoke only when part of a chain that starts with GetTypeFromProgID
            if ((typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke"))
            {
                // This is more complex and needs context analysis
                // For simplicity, we're focusing on known dangerous patterns
                return true;
            }
                
            return false;
        }

        public IEnumerable<ScanFinding> ScanForReflectionInvocation(MethodDefinition methodDef, Instruction instruction, MethodReference calledMethod, int index,
                                                                   Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();
            
            try
            {
                // Check if this is a reflection-based method invocation
                bool isReflectionInvoke = IsReflectionInvokeMethod(calledMethod);
                if (!isReflectionInvoke)
                    return findings;

                // Extract the method name being invoked via reflection
                string invokedMethodName = ExtractInvokedMethodName(instructions, index);

                // Check for other malicious patterns in the method
                bool hasOtherMaliciousPatterns = methodSignals != null &&
                    (methodSignals.HasEncodedStrings ||
                     methodSignals.UsesSensitiveFolder ||
                     methodSignals.HasProcessLikeCall ||
                     methodSignals.HasNetworkCall ||
                     methodSignals.HasFileWrite ||
                     methodSignals.HasBase64) ||
                    _stringPatternDetector.HasAssemblyLoadingInMethod(methodDef, instructions) ||
                    _stringPatternDetector.HasSuspiciousStringPatterns(methodDef, instructions, index);

                // Also check type-level signals (from other methods in the same type)
                bool hasTypeLevelSignals = false;
                if (methodDef.DeclaringType != null)
                {
                    var typeSignal = _signalTracker.GetTypeSignals(methodDef.DeclaringType.FullName);
                    if (typeSignal != null)
                    {
                        hasTypeLevelSignals = typeSignal.HasEncodedStrings ||
                                              typeSignal.UsesSensitiveFolder ||
                                              typeSignal.HasProcessLikeCall ||
                                              typeSignal.HasNetworkCall ||
                                              typeSignal.HasFileWrite ||
                                              typeSignal.HasBase64;
                    }
                }

                // If we can't determine the method name (non-literal), only flag when other high-risk signals are present.
                if (string.IsNullOrEmpty(invokedMethodName))
                {
                    if (!hasOtherMaliciousPatterns && !hasTypeLevelSignals)
                        return findings; // Likely benign reflection usage (e.g., API/Il2Cpp glue).

                    var severity = Severity.High;
                    var snippet = _snippetBuilder.BuildSnippet(instructions, index, 4);

                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}:{instruction.Offset}",
                        "Reflection invocation with non-literal target method name (cannot determine what is being invoked) - combined with other suspicious patterns",
                        severity,
                        snippet));
                    return findings;
                }
                
                // Even if we can determine the method name, only flag if combined with other patterns
                if (!hasOtherMaliciousPatterns && !hasTypeLevelSignals)
                    return findings;
                
                // Create a fake method reference for rules to check
                var fakeMethodRef = new MethodReference(invokedMethodName, methodDef.Module.TypeSystem.Object)
                {
                    DeclaringType = new TypeReference("", "ReflectedType", methodDef.Module, null)
                };
                
                // Check if any rules would flag this method name
                if (_rules.Any(rule => rule.IsSuspicious(fakeMethodRef) || WouldRuleMatchMethodName(rule, invokedMethodName)))
                {
                    var rule = _rules.FirstOrDefault(r => r.IsSuspicious(fakeMethodRef) || WouldRuleMatchMethodName(r, invokedMethodName));
                    if (rule == null) return findings;
                    
                    var snippet = _snippetBuilder.BuildSnippet(instructions, index, 4);
                    
                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}:{instruction.Offset}",
                        $"Potential reflection bypass: {rule.Description}",
                        rule.Severity == Severity.Low ? Severity.Medium : rule.Severity, // Elevate severity for reflection bypasses
                        snippet));
                }
            }
            catch (Exception)
            {
                // Skip if reflection analysis fails
            }
            
            return findings;
        }

        private string ExtractInvokedMethodName(Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex)
        {
            // IMPROVEMENT: Track local variables to follow one step back
            var localVarIndex = -1;
            string methodNameFromLocal = null;

            // Look backward for string literals or local variable loads
            for (int i = Math.Max(0, currentIndex - 20); i < currentIndex; i++)
            {
                var instr = instructions[i];

                // Look for string literals (ldstr opcode)
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string str)
                {
                    // IMPROVEMENT: Try to decode numeric strings before checking
                    string effectiveStr = str;
                    if (EncodedStringLiteralRule.IsEncodedString(str))
                    {
                        var decoded = EncodedStringLiteralRule.DecodeNumericString(str);
                        if (!string.IsNullOrEmpty(decoded))
                            effectiveStr = decoded;
                    }

                    // Look for shell-related strings
                    if (effectiveStr.Contains("Shell.Application") || effectiveStr.Contains("shell32"))
                        return "ShellExecute";

                    // Focus on known dangerous method names
                    if (IsSuspiciousMethodName(effectiveStr))
                    {
                        return effectiveStr;
                    }

                    // Store in case it's assigned to a local variable
                    methodNameFromLocal = effectiveStr;
                }

                // Track local variable stores (stloc)
                if (instr.OpCode == OpCodes.Stloc || instr.OpCode == OpCodes.Stloc_0 ||
                    instr.OpCode == OpCodes.Stloc_1 || instr.OpCode == OpCodes.Stloc_2 ||
                    instr.OpCode == OpCodes.Stloc_3 || instr.OpCode == OpCodes.Stloc_S)
                {
                    // If we just saw a string literal, this local might hold it
                    if (methodNameFromLocal != null && i > 0 && instructions[i - 1].OpCode == OpCodes.Ldstr)
                    {
                        if (instr.OpCode == OpCodes.Stloc_0) localVarIndex = 0;
                        else if (instr.OpCode == OpCodes.Stloc_1) localVarIndex = 1;
                        else if (instr.OpCode == OpCodes.Stloc_2) localVarIndex = 2;
                        else if (instr.OpCode == OpCodes.Stloc_3) localVarIndex = 3;
                        else if (instr.Operand is Mono.Cecil.Cil.VariableDefinition varDef)
                            localVarIndex = varDef.Index;
                    }
                }

                // Check if we're loading a local that might have the method name
                if (localVarIndex >= 0 && methodNameFromLocal != null)
                {
                    bool isLoadingTrackedLocal = false;
                    if (instr.OpCode == OpCodes.Ldloc_0 && localVarIndex == 0) isLoadingTrackedLocal = true;
                    else if (instr.OpCode == OpCodes.Ldloc_1 && localVarIndex == 1) isLoadingTrackedLocal = true;
                    else if (instr.OpCode == OpCodes.Ldloc_2 && localVarIndex == 2) isLoadingTrackedLocal = true;
                    else if (instr.OpCode == OpCodes.Ldloc_3 && localVarIndex == 3) isLoadingTrackedLocal = true;
                    else if (instr.Operand is Mono.Cecil.Cil.VariableDefinition varDef2 && varDef2.Index == localVarIndex)
                        isLoadingTrackedLocal = true;

                    if (isLoadingTrackedLocal && IsSuspiciousMethodName(methodNameFromLocal))
                        return methodNameFromLocal;
                }
            }

            // Also look forward a bit for invocation names
            for (int i = currentIndex + 1; i < Math.Min(instructions.Count, currentIndex + 10); i++)
            {
                var instr = instructions[i];

                // Look for string literals (ldstr opcode)
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string str)
                {
                    if (str == "ShellExecute" || str == "Execute" || str == "Shell")
                        return str;
                }
            }

            return null; // Cannot determine method name
        }

        private bool IsSuspiciousMethodName(string str)
        {
            if (string.IsNullOrWhiteSpace(str)) return false;
            
            // Special case for Shell.Application in string literals
            if (str.Contains("Shell.Application") || str.Contains("shell32"))
                return true;
                
            // Focus on specific dangerous method names rather than any valid method name pattern
            string[] suspiciousNames = {
                "ShellExecute", "Shell", "Execute", "Start", "Process", 
                "Exec", "Run", "Launch", "CreateProcess", "Spawn", 
                "Command", "Eval", "LoadLibrary", "LoadFrom", "cmd.exe",
                "powershell.exe", "wscript.exe", "cscript.exe"
            };
            
            return suspiciousNames.Any(name => 
                str.Equals(name, StringComparison.OrdinalIgnoreCase) || 
                str.Contains(name, StringComparison.OrdinalIgnoreCase));
        }

        private bool WouldRuleMatchMethodName(IScanRule rule, string methodName)
        {
            // Don't do generic matching - instead check rule-specific patterns
            // This prevents false positives like "GetTypeFromProgID" being matched by Base64Rule
            
            if (rule is Shell32Rule)
            {
                // For Shell32Rule, check specific shell execution patterns
                string[] shellMethods = {
                    "ShellExecute", "Shell", "Execute", "CreateProcess", "Spawn", 
                    "Command", "cmd.exe", "powershell.exe", "wscript.exe"
                };
                
                return shellMethods.Any(name => 
                    methodName.Equals(name, StringComparison.OrdinalIgnoreCase) ||
                    methodName.Contains(name, StringComparison.OrdinalIgnoreCase));
            }
            
            // For process execution, check specific process methods
            if (rule.Description.Contains("process") || rule.Description.Contains("Process"))
            {
                // For ProcessStartRule, only match exact method names to avoid false positives
                // like "StartUpdateVolume" matching "Start"
                if (rule is ProcessStartRule)
                {
                    // Only match exact "Start" method name, not substrings
                    return methodName.Equals("Start", StringComparison.OrdinalIgnoreCase);
                }
                
                // For other process-related rules, use broader matching
                string[] processMethods = {
                    "Process", "Exec", "Run", "Launch"
                };
                
                return processMethods.Any(name => 
                    methodName.Equals(name, StringComparison.OrdinalIgnoreCase) ||
                    methodName.Contains(name, StringComparison.OrdinalIgnoreCase));
            }
            
            // For Base64 rule, only match actual Base64 methods
            if (rule.Description.Contains("base64") || rule.Description.Contains("Base64"))
            {
                return methodName.Equals("FromBase64String", StringComparison.OrdinalIgnoreCase) || 
                       methodName.Equals("ToBase64String", StringComparison.OrdinalIgnoreCase);
            }
            
            // For registry rule, only match registry manipulation
            if (rule.Description.Contains("Registry"))
            {
                return methodName.Contains("Registry") || 
                       methodName.Contains("GetValue") || 
                       methodName.Contains("SetValue");
            }
            
            // For loading assemblies, only match those specific patterns
            if (rule.Description.Contains("assembly") || rule.Description.Contains("Assembly"))
            {
                return methodName.Contains("Load") || 
                       methodName.Contains("Assembly") || 
                       methodName.Contains("Compile");
            }
            
            // Default - use a more conservative approach for other rules
            return false;
        }
    }
}

