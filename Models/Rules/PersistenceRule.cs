using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class PersistenceRule : IScanRule
    {
        public string Description => "Detected executable write near persistence-prone directory (Startup/AppData/ProgramData).";
        public Severity Severity => Severity.High;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes contextual patterns around method calls
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method, Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            string declaringTypeFullName = method.DeclaringType.FullName ?? string.Empty;
            string calledMethodName = method.Name ?? string.Empty;

            bool isFileCall =
                declaringTypeFullName.StartsWith("System.IO.", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Equals("System.IO.File", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Equals("System.IO.Directory", StringComparison.OrdinalIgnoreCase) ||
                (declaringTypeFullName.StartsWith("System.IO", StringComparison.OrdinalIgnoreCase) &&
                 (calledMethodName.Contains("Write", StringComparison.OrdinalIgnoreCase) ||
                  calledMethodName.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
                  calledMethodName.Contains("Move", StringComparison.OrdinalIgnoreCase) ||
                  calledMethodName.Contains("Copy", StringComparison.OrdinalIgnoreCase)));

            if (!isFileCall)
                yield break;

            // Sweep nearby string literals for indicators
            int windowStart = Math.Max(0, instructionIndex - 10);
            int windowEnd = Math.Min(instructions.Count, instructionIndex + 11);
            var literals = new List<string>();
            for (int k = windowStart; k < windowEnd; k++)
            {
                if (instructions[k].OpCode == OpCodes.Ldstr && instructions[k].Operand is string s && !string.IsNullOrEmpty(s))
                {
                    literals.Add(s);
                }
            }

            if (literals.Count == 0)
                yield break;

            bool writesStartupOrRoaming = literals.Any(s =>
                s.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("AppData", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("ProgramData", StringComparison.OrdinalIgnoreCase));
            bool writesExecutable = literals.Any(s =>
                s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                s.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                s.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase));

            if (writesStartupOrRoaming && writesExecutable)
            {
                // Build code snippet
                var snippetBuilder = new System.Text.StringBuilder();
                int contextLines = 2;
                for (int j = Math.Max(0, instructionIndex - contextLines); j < Math.Min(instructions.Count, instructionIndex + contextLines + 1); j++)
                {
                    if (j == instructionIndex) snippetBuilder.Append(">>> ");
                    else snippetBuilder.Append("    ");
                    snippetBuilder.AppendLine(instructions[j].ToString());
                }

                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    "Executable write near persistence-prone directory (Startup/AppData/ProgramData).",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd());
            }
        }
    }
}

