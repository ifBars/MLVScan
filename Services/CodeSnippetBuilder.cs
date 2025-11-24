using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class CodeSnippetBuilder
    {
        public string BuildSnippet(Mono.Collections.Generic.Collection<Instruction> instructions, int index, int contextLines)
        {
            var snippetBuilder = new System.Text.StringBuilder();

            for (int j = Math.Max(0, index - contextLines); j < Math.Min(instructions.Count, index + contextLines + 1); j++)
            {
                if (j == index) snippetBuilder.Append(">>> ");
                else snippetBuilder.Append("    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            return snippetBuilder.ToString().TrimEnd();
        }
    }
}

