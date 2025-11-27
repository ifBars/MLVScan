using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;
using System.Text.RegularExpressions;

namespace MLVScan.Models.Rules
{
    public class DataInfiltrationRule : IScanRule
    {
        public string Description => "Detected data download from suspicious endpoint (potential payload infiltration).";
        public Severity Severity => Severity.High;
        public string RuleId => "DataInfiltrationRule";
        public bool RequiresCompanionFinding => true;

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

            // Only analyze download/read operations (GET, DownloadString, etc.)
            bool isReadOnlyOperation = calledMethodName.Contains("GetStringAsync", StringComparison.OrdinalIgnoreCase) ||
                                       calledMethodName.Contains("GetAsync", StringComparison.OrdinalIgnoreCase) ||
                                       calledMethodName.Contains("GetByteArrayAsync", StringComparison.OrdinalIgnoreCase) ||
                                       calledMethodName.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) ||
                                       calledMethodName.Contains("DownloadData", StringComparison.OrdinalIgnoreCase) ||
                                       calledMethodName.Contains("DownloadFile", StringComparison.OrdinalIgnoreCase);

            // Skip if this is not a download operation
            if (!isReadOnlyOperation)
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

            // Check for suspicious URL patterns
            bool hasRawPaste = literals.Any(s =>
                s.Contains("pastebin.com/raw", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("hastebin.com/raw", StringComparison.OrdinalIgnoreCase));
            bool hasBareIpUrl = literals.Any(s => Regex.IsMatch(s, @"https?://\d{1,3}(?:\.\d{1,3}){3}", RegexOptions.IgnoreCase));
            bool mentionsNgrokOrTelegram = literals.Any(s => s.Contains("ngrok", StringComparison.OrdinalIgnoreCase) || s.Contains("telegram", StringComparison.OrdinalIgnoreCase));
            
            // Check for legitimate sources (GitHub releases, mod hosting sites, common CDNs)
            bool isLegitimateSource = literals.Any(s =>
                (s.Contains("github.com/releases", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("github.com/release", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("api.github.com/repos", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("github.io", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("modrinth.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("curseforge.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("nexusmods.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("cdn.jsdelivr.net", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("unpkg.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("cdnjs.cloudflare.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("gstatic.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("googleapis.com", StringComparison.OrdinalIgnoreCase)) &&
                !s.Contains("discord.com", StringComparison.OrdinalIgnoreCase));

            // Detect specific legitimate source types for more detailed reporting
            bool isGitHubSource = literals.Any(s =>
                (s.Contains("github.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
                 s.Contains("github.io", StringComparison.OrdinalIgnoreCase)) &&
                !s.Contains("discord.com", StringComparison.OrdinalIgnoreCase));
            
            bool isModHostingSource = literals.Any(s =>
                s.Contains("modrinth.com", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("curseforge.com", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("nexusmods.com", StringComparison.OrdinalIgnoreCase));
            
            bool isCDNSource = literals.Any(s =>
                s.Contains("cdn.jsdelivr.net", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("unpkg.com", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("cdnjs.cloudflare.com", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("gstatic.com", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("googleapis.com", StringComparison.OrdinalIgnoreCase));

            // Extract URLs from literals
            var urls = new List<string>();
            foreach (var literal in literals)
            {
                if (literal.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    literal.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    var match = Regex.Match(literal, @"(https?://[^\s""'<>]+)", RegexOptions.IgnoreCase);
                    if (match.Success)
                    {
                        urls.Add(match.Groups[1].Value);
                    }
                }
                else if (Regex.IsMatch(literal, @"https?://", RegexOptions.IgnoreCase))
                {
                    var matches = Regex.Matches(literal, @"(https?://[^\s""'<>]+)", RegexOptions.IgnoreCase);
                    foreach (Match match in matches)
                    {
                        urls.Add(match.Groups[1].Value);
                    }
                }
            }
            urls = urls.Distinct().ToList();
            
            string urlList = urls.Count > 0 
                ? $" URL(s): {string.Join(", ", urls)}" 
                : string.Empty;

            // Build code snippet
            var snippetBuilder = new System.Text.StringBuilder();
            int contextLines = 2;
            for (int j = Math.Max(0, instructionIndex - contextLines); j < Math.Min(instructions.Count, instructionIndex + contextLines + 1); j++)
            {
                if (j == instructionIndex) snippetBuilder.Append(">>> ");
                else snippetBuilder.Append("    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            // For GET operations: legitimate sources get Low severity (always allowed)
            if (isLegitimateSource)
            {
                string sourceType = isGitHubSource ? "GitHub" :
                                    isModHostingSource ? "mod hosting site" :
                                    isCDNSource ? "CDN" : "unknown source";
                
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only network operation to {sourceType} (likely legitimate - version check or resource download).{urlList}",
                    Severity.Low,
                    snippetBuilder.ToString().TrimEnd());
            }
            // Non-legitimate sources: High severity (requires companion finding to actually trigger due to RequiresCompanionFinding = true)
            else if (hasRawPaste || hasBareIpUrl || mentionsNgrokOrTelegram)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only operation to suspicious endpoint (potential payload download).{urlList}",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd());
            }
        }
    }
}

