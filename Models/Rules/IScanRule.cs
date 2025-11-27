using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Linq;

namespace MLVScan.Models
{
    public interface IScanRule
    {
        string Description { get; }
        Severity Severity { get; }
        string RuleId { get; }
        bool RequiresCompanionFinding { get; }
        bool IsSuspicious(MethodReference method);

        /// <summary>
        /// Analyzes IL instructions in a method for suspicious patterns.
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes string literals found in IL code for suspicious patterns.
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method, int instructionIndex)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes assembly metadata attributes for hidden payloads.
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes contextual patterns around method calls (nearby instructions, signals, etc.).
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method, Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals)
        {
            return Enumerable.Empty<ScanFinding>();
        }
    }
}