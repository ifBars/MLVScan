using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class StringPatternDetector
    {
        public bool HasSuspiciousStringPatterns(MethodDefinition methodDef, Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex)
        {
            // Check nearby instructions for suspicious string patterns
            int windowStart = Math.Max(0, currentIndex - 20);
            int windowEnd = Math.Min(instructions.Count, currentIndex + 20);
            
            for (int i = windowStart; i < windowEnd; i++)
            {
                var instr = instructions[i];
                
                // Check for encoded strings
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string strLiteral)
                {
                    if (EncodedStringLiteralRule.IsEncodedString(strLiteral))
                    {
                        var decoded = EncodedStringLiteralRule.DecodeNumericString(strLiteral);
                        if (decoded != null && EncodedStringLiteralRule.ContainsSuspiciousContent(decoded))
                        {
                            return true;
                        }
                    }
                    
                    // Check for suspicious string content
                    if (strLiteral.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                        strLiteral.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                        strLiteral.Contains("wscript", StringComparison.OrdinalIgnoreCase) ||
                        strLiteral.Contains("cscript", StringComparison.OrdinalIgnoreCase) ||
                        strLiteral.Contains("ShellExecute", StringComparison.OrdinalIgnoreCase) ||
                        strLiteral.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
                        strLiteral.Contains("RunOnce", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                
                // Check for Base64 decoding calls
                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) &&
                    instr.Operand is MethodReference calledMethod &&
                    calledMethod.DeclaringType != null)
                {
                    string typeName = calledMethod.DeclaringType.FullName;
                    string methodName = calledMethod.Name;
                    
                    if (typeName.Contains("Convert") && methodName.Contains("FromBase64"))
                    {
                        return true;
                    }
                }
            }
            
            return false;
        }

        public bool HasAssemblyLoadingInMethod(MethodDefinition methodDef, Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            foreach (var instruction in instructions)
            {
                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                    instruction.Operand is MethodReference calledMethod &&
                    calledMethod.DeclaringType != null)
                {
                    string typeName = calledMethod.DeclaringType.FullName;
                    string methodName = calledMethod.Name;
                    
                    if ((typeName.Contains("Assembly") || typeName.Contains("AssemblyLoadContext")) &&
                        (methodName == "Load" || methodName.Contains("LoadFrom")))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}

