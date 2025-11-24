using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class EncodedStringPipelineRule : IScanRule
    {
        public string Description => "Detected encoded string to char decoding pipeline (ASCII number parsing pattern).";
        public Severity Severity => Severity.High;

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
                // Pattern: Int32::Parse → conv.u2 → Select<String,Char> → Concat<Char>
                // Note: Parse → conv.u2 may be in a lambda, but Select<String,Char> → Concat<Char> is the key indicator
                bool hasInt32Parse = false;
                bool hasConvU2 = false;
                bool hasSelectStringChar = false;
                bool hasConcatChar = false;
                
                int parseIndex = -1;
                int convU2Index = -1;
                int selectIndex = -1;
                int concatIndex = -1;
                
                // First pass: Find all components
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instr = instructions[i];
                    
                    if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                    {
                        if (instr.Operand is MethodReference calledMethod && calledMethod.DeclaringType != null)
                        {
                            string typeName = calledMethod.DeclaringType.FullName;
                            string methodName = calledMethod.Name;
                            
                            // Check for Int32::Parse(System.String)
                            if (typeName == "System.Int32" && methodName == "Parse" && 
                                calledMethod.Parameters.Count == 1 &&
                                calledMethod.Parameters[0].ParameterType.FullName == "System.String")
                            {
                                hasInt32Parse = true;
                                parseIndex = i;
                            }
                            
                            // Check for Select<String,Char>
                            if (typeName == "System.Linq.Enumerable" && methodName == "Select")
                            {
                                // Check generic arguments
                                if (calledMethod is GenericInstanceMethod genericMethod &&
                                    genericMethod.GenericArguments.Count == 2)
                                {
                                    var arg1 = genericMethod.GenericArguments[0].FullName;
                                    var arg2 = genericMethod.GenericArguments[1].FullName;
                                    if (arg1 == "System.String" && arg2 == "System.Char")
                                    {
                                        hasSelectStringChar = true;
                                        selectIndex = i;
                                    }
                                }
                            }
                            
                            // Check for Concat<Char>
                            if (typeName == "System.String" && methodName == "Concat")
                            {
                                if (calledMethod is GenericInstanceMethod genericMethod &&
                                    genericMethod.GenericArguments.Count == 1 &&
                                    genericMethod.GenericArguments[0].FullName == "System.Char")
                                {
                                    hasConcatChar = true;
                                    concatIndex = i;
                                }
                            }
                        }
                    }
                    
                    // Check for conv.u2 (convert to char) near Parse call
                    if (hasInt32Parse && parseIndex >= 0 && i > parseIndex && i <= parseIndex + 3)
                    {
                        if (instr.OpCode == OpCodes.Conv_U2)
                        {
                            hasConvU2 = true;
                            convU2Index = i;
                        }
                    }
                }
                
                // Detect pattern: Select<String,Char> → Concat<Char> is the key indicator
                // Parse → conv.u2 may be in a lambda, so we check for it separately
                if (hasSelectStringChar && hasConcatChar)
                {
                    // Verify the sequence makes sense (Select → Concat)
                    if (selectIndex < concatIndex)
                    {
                        // If we also found Parse → conv.u2 in the same method, that's even more suspicious
                        bool hasParseConvPattern = hasInt32Parse && hasConvU2 && parseIndex < convU2Index;
                        
                        var snippetBuilder = new System.Text.StringBuilder();
                        int startIdx = Math.Max(0, Math.Min(hasParseConvPattern ? parseIndex : selectIndex, selectIndex) - 2);
                        int endIdx = Math.Min(instructions.Count, concatIndex + 3);
                        
                        for (int j = startIdx; j < endIdx; j++)
                        {
                            if (j == selectIndex || j == concatIndex || 
                                (hasParseConvPattern && (j == parseIndex || j == convU2Index)))
                                snippetBuilder.Append(">>> ");
                            else
                                snippetBuilder.Append("    ");
                            snippetBuilder.AppendLine(instructions[j].ToString());
                        }
                        
                        findings.Add(new ScanFinding(
                            $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                            "Detected encoded string to char decoding pipeline (ASCII number parsing pattern)",
                            Severity.High,
                            snippetBuilder.ToString().TrimEnd()));
                    }
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

