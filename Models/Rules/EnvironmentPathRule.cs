using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class EnvironmentPathRule : IScanRule
    {
        public string Description => "Detected Environment.GetFolderPath access to sensitive directories (AppData, Startup, etc.).";
        public Severity Severity => Severity.Low;
        public string RuleId => "EnvironmentPathRule";
        public bool RequiresCompanionFinding => false;

        // Map of SpecialFolder enum values to names
        private static readonly Dictionary<int, string> SensitiveFolders = new Dictionary<int, string>
        {
            { 26, "ApplicationData" },      // %APPDATA%
            { 7, "Startup" },               // Startup folder
            { 28, "LocalApplicationData" }, // %LOCALAPPDATA%
            { 35, "CommonApplicationData" }, // %PROGRAMDATA%
            { 44, "CommonStartup" },        // All Users Startup
            { 5, "MyDocuments" },           // Documents (sometimes used for persistence)
            { 38, "ProgramFiles" },         // Program Files
            { 43, "Windows" },              // Windows directory
            { 37, "System" },               // System32
        };

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Detect Environment.GetFolderPath
            return typeName == "System.Environment" && methodName == "GetFolderPath";
        }

        public static bool IsSensitiveFolder(int folderValue)
        {
            return SensitiveFolders.ContainsKey(folderValue);
        }

        public static string GetFolderName(int folderValue)
        {
            return SensitiveFolders.TryGetValue(folderValue, out string name) ? name : $"Folder({folderValue})";
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method, Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Only analyze Environment.GetFolderPath calls
            if (typeName != "System.Environment" || methodName != "GetFolderPath")
                yield break;

            // Extract folder path argument
            int? folderValue = ExtractFolderPathArgument(instructions, instructionIndex);
            if (!folderValue.HasValue || !IsSensitiveFolder(folderValue.Value))
                yield break;

            yield return new ScanFinding(
                $"{method.DeclaringType.FullName}.{method.Name}:{instructions[instructionIndex].Offset}",
                $"Access to sensitive folder: {GetFolderName(folderValue.Value)}",
                Severity.Low,
                $"Environment.GetFolderPath({folderValue.Value}) // {GetFolderName(folderValue.Value)}");
        }

        private int? ExtractFolderPathArgument(Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex)
        {
            // Look backward for ldc.i4 (load constant int32) instructions
            for (int i = Math.Max(0, currentIndex - 5); i < currentIndex; i++)
            {
                var instr = instructions[i];

                // Check for various forms of loading integer constants
                if (instr.OpCode == OpCodes.Ldc_I4)
                {
                    return (int)instr.Operand;
                }
                else if (instr.OpCode == OpCodes.Ldc_I4_S)
                {
                    return (sbyte)instr.Operand;
                }
                else if (instr.OpCode == OpCodes.Ldc_I4_0) return 0;
                else if (instr.OpCode == OpCodes.Ldc_I4_1) return 1;
                else if (instr.OpCode == OpCodes.Ldc_I4_2) return 2;
                else if (instr.OpCode == OpCodes.Ldc_I4_3) return 3;
                else if (instr.OpCode == OpCodes.Ldc_I4_4) return 4;
                else if (instr.OpCode == OpCodes.Ldc_I4_5) return 5;
                else if (instr.OpCode == OpCodes.Ldc_I4_6) return 6;
                else if (instr.OpCode == OpCodes.Ldc_I4_7) return 7;
                else if (instr.OpCode == OpCodes.Ldc_I4_8) return 8;
            }

            return null;
        }
    }
}
