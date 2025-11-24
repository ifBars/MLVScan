using Mono.Cecil.Cil;

namespace MLVScan.Services.Helpers
{
    public static class InstructionHelper
    {
        public static int? ExtractFolderPathArgument(Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex)
        {
            for (int i = Math.Max(0, currentIndex - 5); i < currentIndex; i++)
            {
                var instr = instructions[i];

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

