using MelonLoader.Utils;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Text.RegularExpressions;

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

            if (findings.Count == 1 && findings[0].Location == "Assembly scanning" && string.IsNullOrEmpty(findings[0].CodeSnippet))
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

                var instructions = method.Body.Instructions;
                
                // Check for COM reflection attack pattern (GetTypeFromProgID + Activator.CreateInstance + InvokeMember)
                DetectCOMReflectionAttack(method, instructions, findings);
                
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    try
                    {
                        // Check for direct method calls
                        if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) && 
                            instruction.Operand is MethodReference calledMethod)
                        {
                            if (_rules.Any(rule => rule.IsSuspicious(calledMethod)))
                            {
                                var rule = _rules.First(r => r.IsSuspicious(calledMethod)); // Assuming one rule matches or taking the first
                                var snippetBuilder = new System.Text.StringBuilder();
                                int contextLines = 2; // Number of IL lines before and after

                                for (int j = Math.Max(0, i - contextLines); j < Math.Min(instructions.Count, i + contextLines + 1); j++)
                                {
                                    if (j == i) snippetBuilder.Append(">>> ");
                                    else snippetBuilder.Append("    ");
                                    snippetBuilder.AppendLine(instructions[j].ToString());
                                }
                                
                                findings.Add(new ScanFinding(
                                    $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}", 
                                    rule.Description, 
                                    rule.Severity,
                                    snippetBuilder.ToString().TrimEnd()));

                                // Contextual bump for suspicious strings around network/file calls
                                try
                                {
                                    // Identify network or file-related API usage for contextual analysis
                                    string declaringTypeFullName = calledMethod.DeclaringType?.FullName ?? string.Empty;
                                    string calledMethodName = calledMethod.Name ?? string.Empty;

                                    bool isNetworkCall =
                                        declaringTypeFullName.StartsWith("System.Net", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("UnityEngine.Networking.UnityWebRequest", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("HttpClient", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("WebClient", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("WebRequest", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("Sockets", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("TcpClient", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Contains("UdpClient", StringComparison.OrdinalIgnoreCase);

                                    bool isFileCall =
                                        declaringTypeFullName.StartsWith("System.IO.", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Equals("System.IO.File", StringComparison.OrdinalIgnoreCase) ||
                                        declaringTypeFullName.Equals("System.IO.Directory", StringComparison.OrdinalIgnoreCase) ||
                                        (declaringTypeFullName.StartsWith("System.IO", StringComparison.OrdinalIgnoreCase) &&
                                         (calledMethodName.Contains("Write", StringComparison.OrdinalIgnoreCase) ||
                                          calledMethodName.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
                                          calledMethodName.Contains("Move", StringComparison.OrdinalIgnoreCase) ||
                                          calledMethodName.Contains("Copy", StringComparison.OrdinalIgnoreCase)));

                                    if (isNetworkCall || isFileCall)
                                    {
                                        // Sweep nearby string literals for indicators
                                        int windowStart = Math.Max(0, i - 10);
                                        int windowEnd = Math.Min(instructions.Count, i + 11);
                                        var literals = new List<string>();
                                        for (int k = windowStart; k < windowEnd; k++)
                                        {
                                            if (instructions[k].OpCode == OpCodes.Ldstr && instructions[k].Operand is string s && !string.IsNullOrEmpty(s))
                                            {
                                                literals.Add(s);
                                            }
                                        }

                                        if (literals.Count > 0)
                                        {
                                            bool hasDiscordWebhook = literals.Any(s => s.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase));
                                            bool hasRawPaste = literals.Any(s =>
                                                s.Contains("pastebin.com/raw", StringComparison.OrdinalIgnoreCase) ||
                                                s.Contains("raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
                                                s.Contains("hastebin.com/raw", StringComparison.OrdinalIgnoreCase));
                                            bool hasBareIpUrl = literals.Any(s => System.Text.RegularExpressions.Regex.IsMatch(s, @"https?://\d{1,3}(?:\.\d{1,3}){3}", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
                                            bool mentionsNgrokOrTelegram = literals.Any(s => s.Contains("ngrok", StringComparison.OrdinalIgnoreCase) || s.Contains("telegram", StringComparison.OrdinalIgnoreCase));

                                            bool writesStartupOrRoaming = literals.Any(s =>
                                                s.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
                                                s.Contains("AppData", StringComparison.OrdinalIgnoreCase) ||
                                                s.Contains("ProgramData", StringComparison.OrdinalIgnoreCase));
                                            bool writesExecutable = literals.Any(s =>
                                                s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                                                s.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                                                s.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase));

                                            if (isNetworkCall && hasDiscordWebhook)
                                            {
                                                findings.Add(new ScanFinding(
                                                    $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}",
                                                    "Discord webhook endpoint near network call (potential data exfiltration).",
                                                    "Critical",
                                                    snippetBuilder.ToString().TrimEnd()));
                                            }
                                            else if (isNetworkCall && (hasRawPaste || hasBareIpUrl || mentionsNgrokOrTelegram))
                                            {
                                                findings.Add(new ScanFinding(
                                                    $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}",
                                                    "Potential payload download endpoint near network call (raw paste/code host/IP).",
                                                    "High",
                                                    snippetBuilder.ToString().TrimEnd()));
                                            }
                                            else if (isFileCall && writesStartupOrRoaming && writesExecutable)
                                            {
                                                findings.Add(new ScanFinding(
                                                    $"{method.DeclaringType.FullName}.{method.Name}:{instruction.Offset}",
                                                    "Executable write near persistence-prone directory (Startup/AppData/ProgramData).",
                                                    "High",
                                                    snippetBuilder.ToString().TrimEnd()));
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                    // Ignore contextual bump failures
                                }
                            }
                            
                            // Check for reflection-based calls that might bypass detection
                            ScanForReflectionInvocation(method, instruction, calledMethod, i, instructions, findings);
                        }
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
        
        private void DetectCOMReflectionAttack(MethodDefinition methodDef, Mono.Collections.Generic.Collection<Instruction> instructions, List<ScanFinding> findings)
        {
            bool hasTypeFromProgID = false;
            bool hasActivatorCreateInstance = false;
            bool hasInvokeMember = false;
            string progIDValue = null;
            string invokeMemberMethod = null;
            
            // First pass - detect if all components of the attack are present
            foreach (var instruction in instructions)
            {
                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt)
                    continue;
                    
                if (instruction.Operand is not MethodReference calledMethod)
                    continue;
                    
                if (calledMethod.DeclaringType == null)
                    continue;
                
                string typeName = calledMethod.DeclaringType.FullName;
                string methodName = calledMethod.Name;
                
                // Check for GetTypeFromProgID
                if (typeName == "System.Type" && methodName == "GetTypeFromProgID")
                {
                    hasTypeFromProgID = true;
                    
                    // Try to extract the progID value (usually a string literal before the call)
                    int index = instructions.IndexOf(instruction);
                    for (int i = Math.Max(0, index - 5); i < index; i++)
                    {
                        if (instructions[i].OpCode == OpCodes.Ldstr && instructions[i].Operand is string str)
                        {
                            progIDValue = str;
                            break;
                        }
                    }
                }
                
                // Check for Activator.CreateInstance
                if (typeName == "System.Activator" && methodName == "CreateInstance")
                {
                    hasActivatorCreateInstance = true;
                }
                
                // Check for InvokeMember
                if (typeName == "System.Type" && methodName == "InvokeMember")
                {
                    hasInvokeMember = true;
                    
                    // Try to extract the method name being invoked
                    int index = instructions.IndexOf(instruction);
                    for (int i = Math.Max(0, index - 5); i < index; i++)
                    {
                        if (instructions[i].OpCode == OpCodes.Ldstr && instructions[i].Operand is string str)
                        {
                            invokeMemberMethod = str;
                            break;
                        }
                    }
                }
            }
            
            // If we found the full pattern, add a finding
            if (hasTypeFromProgID && (hasActivatorCreateInstance || hasInvokeMember))
            {
                // If we found Shell.Application and ShellExecute, this is definitely malicious
                bool isShellExecution = 
                    (progIDValue != null && progIDValue.Contains("Shell")) ||
                    (invokeMemberMethod != null && invokeMemberMethod.Contains("ShellExecute"));
                
                if (isShellExecution || (progIDValue != null && invokeMemberMethod != null))
                {
                    var fullMethodSnippet = new System.Text.StringBuilder();
                    
                    // Include the full method for context
                    foreach (var instr in instructions)
                    {
                        fullMethodSnippet.AppendLine(instr.ToString());
                    }
                    
                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        $"Reflective shell execution detected via COM (GetTypeFromProgID + InvokeMember pattern)",
                        "Critical",
                        fullMethodSnippet.ToString().TrimEnd()));
                }
            }
        }
        
        private void ScanForReflectionInvocation(MethodDefinition methodDef, Instruction instruction, MethodReference calledMethod, int index, 
                                               Mono.Collections.Generic.Collection<Instruction> instructions, List<ScanFinding> findings)
        {
            try
            {
                // Only check specific reflection patterns that are commonly used for malicious purposes
                // Exclude legitimate reflection patterns commonly used in mods
                
                // Check if this is a reflection-based method invocation
                bool isReflectionInvoke = IsReflectionInvokeMethod(calledMethod);
                if (!isReflectionInvoke)
                    return;
                
                // Extract the method name being invoked via reflection
                string invokedMethodName = ExtractInvokedMethodName(instructions, index);
                if (string.IsNullOrEmpty(invokedMethodName))
                    return;
                
                // Check for suspicious context before flagging
                // If we're in what looks like a legitimate mod context (typical MelonLoader patterns), 
                // don't flag the reflection usage
                if (IsLikelyLegitimateModContext(methodDef))
                    return;
                
                // Create a fake method reference for rules to check
                var fakeMethodRef = new MethodReference(invokedMethodName, methodDef.Module.TypeSystem.Object)
                {
                    DeclaringType = new TypeReference("", "ReflectedType", methodDef.Module, null)
                };
                
                // Check if any rules would flag this method name
                if (_rules.Any(rule => rule.IsSuspicious(fakeMethodRef) || WouldRuleMatchMethodName(rule, invokedMethodName)))
                {
                    var rule = _rules.FirstOrDefault(r => r.IsSuspicious(fakeMethodRef) || WouldRuleMatchMethodName(r, invokedMethodName));
                    if (rule == null) return;
                    
                    var snippetBuilder = new System.Text.StringBuilder();
                    int contextLines = 4; // More context lines for reflection calls
                    
                    for (int j = Math.Max(0, index - contextLines); j < Math.Min(instructions.Count, index + contextLines + 1); j++)
                    {
                        if (j == index) snippetBuilder.Append(">>> ");
                        else snippetBuilder.Append("    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }
                    
                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}:{instruction.Offset}",
                        $"Potential reflection bypass: {rule.Description}",
                        rule.Severity == "Low" ? "Medium" : rule.Severity, // Elevate severity for reflection bypasses
                        snippetBuilder.ToString().TrimEnd()));
                }
            }
            catch (Exception)
            {
                // Skip if reflection analysis fails
            }
        }
        
        private bool IsLikelyLegitimateModContext(MethodDefinition methodDef)
        {
            // Check typical patterns for legitimate mod reflection usage
            
            // 1. Check if we're in a patching context
            if (methodDef.DeclaringType.FullName.Contains("Patch") || 
                methodDef.DeclaringType.FullName.Contains("Harmony") ||
                methodDef.Name.Contains("Patch") ||
                methodDef.DeclaringType.FullName.Contains("MonoMod"))
                return true;
                
            // 2. Check if we're in a typical MelonLoader or Unity context
            if (methodDef.DeclaringType.FullName.Contains("MelonLoader") ||
                methodDef.DeclaringType.Namespace?.Contains("MelonLoader") == true ||
                methodDef.DeclaringType.Namespace?.Contains("UnityEngine") == true)
                return true;
                
            // 3. Check if reflection is being used for typical game interop
            if (methodDef.Name.Contains("Initialize") && !methodDef.Name.Contains("OnInitializeMelon") || 
                methodDef.Name.Contains("Setup") || 
                methodDef.Name == "OnSceneWasLoaded")
                return true;
                
            return false;
        }
        
        private bool IsReflectionInvokeMethod(MethodReference method)
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
        
        private string ExtractInvokedMethodName(Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex)
        {
            // Look backward for string literals that might be method names
            for (int i = Math.Max(0, currentIndex - 15); i < currentIndex; i++)
            {
                var instr = instructions[i];
                
                // Look for string literals (ldstr opcode)
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string str)
                {
                    // Look for shell-related strings
                    if (str.Contains("Shell.Application") || str.Contains("shell32"))
                        return "ShellExecute";
                        
                    // Focus on known dangerous method names rather than all method names
                    if (IsSuspiciousMethodName(str))
                    {
                        return str;
                    }
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
            
            return "UnknownReflectionCall"; // Return default name for unknown reflection calls
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
                string[] processMethods = {
                    "Start", "Process", "Exec", "Run", "Launch"
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
