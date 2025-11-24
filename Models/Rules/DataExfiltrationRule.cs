using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;
using System.Text.RegularExpressions;

namespace MLVScan.Models.Rules
{
    public class DataExfiltrationRule : IScanRule
    {
        public string Description => "Detected potential data exfiltration endpoints (Discord webhooks, raw paste sites, IP URLs).";
        public Severity Severity => Severity.Critical;

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

            bool isNetworkCall =
                declaringTypeFullName.StartsWith("System.Net", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("UnityEngine.Networking.UnityWebRequest", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("HttpClient", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("WebClient", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("WebRequest", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("Sockets", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("TcpClient", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("UdpClient", StringComparison.OrdinalIgnoreCase);

            if (!isNetworkCall)
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

            bool hasDiscordWebhook = literals.Any(s => s.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase));
            bool hasRawPaste = literals.Any(s =>
                s.Contains("pastebin.com/raw", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("hastebin.com/raw", StringComparison.OrdinalIgnoreCase));
            bool hasBareIpUrl = literals.Any(s => Regex.IsMatch(s, @"https?://\d{1,3}(?:\.\d{1,3}){3}", RegexOptions.IgnoreCase));
            bool mentionsNgrokOrTelegram = literals.Any(s => s.Contains("ngrok", StringComparison.OrdinalIgnoreCase) || s.Contains("telegram", StringComparison.OrdinalIgnoreCase));

            // Build code snippet
            var snippetBuilder = new System.Text.StringBuilder();
            int contextLines = 2;
            for (int j = Math.Max(0, instructionIndex - contextLines); j < Math.Min(instructions.Count, instructionIndex + contextLines + 1); j++)
            {
                if (j == instructionIndex) snippetBuilder.Append(">>> ");
                else snippetBuilder.Append("    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            if (hasDiscordWebhook)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    "Discord webhook endpoint near network call (potential data exfiltration).",
                    Severity.Critical,
                    snippetBuilder.ToString().TrimEnd());
            }
            else if (hasRawPaste || hasBareIpUrl || mentionsNgrokOrTelegram)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    "Potential payload download endpoint near network call (raw paste/code host/IP).",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd());
            }
        }
    }
}

