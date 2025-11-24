using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class COMReflectionAttackRule : IScanRule
    {
        public string Description => "Detected reflective shell execution via COM (GetTypeFromProgID + InvokeMember pattern).";
        public Severity Severity => Severity.Critical;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes instructions, not individual method references
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition methodDef, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
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
                    
                    yield return new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        $"Reflective shell execution detected via COM (GetTypeFromProgID + InvokeMember pattern)",
                        Severity.Critical,
                        fullMethodSnippet.ToString().TrimEnd());
                }
            }
        }
    }
}

