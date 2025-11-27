using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class EncodedBlobSplittingRule : IScanRule
    {
        public string Description => "Detected structured encoded blob splitting pattern (backtick/dash separator in loop).";
        public Severity Severity => Severity.High;
        public string RuleId => "EncodedBlobSplittingRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze IL instruction patterns in methods
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition methodDef, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();
            
            try
            {
                bool hasSplitWithSeparator = false;
                int splitIndex = -1;
                char separatorChar = '\0';
                
                // Find Split calls with suspicious separators
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instr = instructions[i];
                    
                    if (instr.OpCode == OpCodes.Callvirt && instr.Operand is MethodReference calledMethod &&
                        calledMethod.DeclaringType != null &&
                        calledMethod.DeclaringType.FullName == "System.String" &&
                        calledMethod.Name == "Split")
                    {
                        // Check if Split has the right signature: Split(Char, StringSplitOptions)
                        if (calledMethod.Parameters.Count == 2)
                        {
                            // Look backward for the separator char constant
                            for (int j = Math.Max(0, i - 5); j < i; j++)
                            {
                                var prevInstr = instructions[j];
                                
                                // Check for ldc.i4.s (load constant byte) with value 96 (`) or 45 (-)
                                if (prevInstr.OpCode == OpCodes.Ldc_I4_S && prevInstr.Operand is sbyte byteVal)
                                {
                                    if (byteVal == 96 || byteVal == 45)
                                    {
                                        hasSplitWithSeparator = true;
                                        splitIndex = i;
                                        separatorChar = (char)byteVal;
                                        break;
                                    }
                                }
                                // Also check ldc.i4 (load constant int32)
                                else if (prevInstr.OpCode == OpCodes.Ldc_I4 && prevInstr.Operand is int intVal)
                                {
                                    if (intVal == 96 || intVal == 45)
                                    {
                                        hasSplitWithSeparator = true;
                                        splitIndex = i;
                                        separatorChar = (char)intVal;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if (!hasSplitWithSeparator || splitIndex < 0)
                    return findings;
                
                // Now check if the split result is used in a loop pattern
                // Look for: ldloc.* → clt → brtrue (back edge)
                bool hasLoopPattern = false;
                int loopStartIndex = -1;
                int loopEndIndex = -1;
                
                // Search for loop pattern after the split
                // Pattern: clt → brtrue/brtrue.s with backward branch (loop)
                for (int i = splitIndex + 1; i < instructions.Count - 1; i++)
                {
                    var instr = instructions[i];
                    
                    // Check for clt (compare less than)
                    if (instr.OpCode == OpCodes.Clt)
                    {
                        // Look ahead for brtrue/brtrue.s within a few instructions
                        for (int j = i + 1; j < Math.Min(instructions.Count, i + 5); j++)
                        {
                            var branchInstr = instructions[j];
                            
                            // Check for brtrue/brtrue.s (branch if true - loop back)
                            if (branchInstr.OpCode == OpCodes.Brtrue || branchInstr.OpCode == OpCodes.Brtrue_S)
                            {
                                // Verify it's a backward branch (loop)
                                if (branchInstr.Operand is Instruction targetInstr)
                                {
                                    int targetIndex = instructions.IndexOf(targetInstr);
                                    if (targetIndex >= 0 && targetIndex < i)
                                    {
                                        // Check if there's a ldloc before the clt (indicates loop variable)
                                        bool hasLdlocBefore = false;
                                        for (int k = Math.Max(0, i - 10); k < i; k++)
                                        {
                                            var checkInstr = instructions[k];
                                            if (checkInstr.OpCode == OpCodes.Ldloc || checkInstr.OpCode == OpCodes.Ldloc_0 ||
                                                checkInstr.OpCode == OpCodes.Ldloc_1 || checkInstr.OpCode == OpCodes.Ldloc_2 ||
                                                checkInstr.OpCode == OpCodes.Ldloc_3 || checkInstr.OpCode == OpCodes.Ldloc_S)
                                            {
                                                hasLdlocBefore = true;
                                                break;
                                            }
                                        }
                                        
                                        if (hasLdlocBefore)
                                        {
                                            hasLoopPattern = true;
                                            loopStartIndex = targetIndex;
                                            loopEndIndex = j;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if (hasLoopPattern)
                        break;
                }
                
                if (hasLoopPattern && loopStartIndex >= 0)
                {
                    var snippetBuilder = new System.Text.StringBuilder();
                    int startIdx = Math.Max(0, splitIndex - 3);
                    int endIdx = Math.Min(instructions.Count, loopEndIndex + 3);
                    
                    for (int j = startIdx; j < endIdx; j++)
                    {
                        if (j == splitIndex || (j >= loopStartIndex && j <= loopEndIndex))
                            snippetBuilder.Append(">>> ");
                        else
                            snippetBuilder.Append("    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }
                    
                    string separatorName = separatorChar == 96 ? "backtick (`)" : "dash (-)";
                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        $"Detected structured encoded blob splitting pattern ({separatorName} separator in loop)",
                        Severity.High,
                        snippetBuilder.ToString().TrimEnd()));
                }
            }
            catch
            {
                // Skip if detection fails
            }
            
            return findings;
        }
    }
}

