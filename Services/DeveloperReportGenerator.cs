using MelonLoader;
using MLVScan.Models;
using System.Text;

namespace MLVScan.Services
{
    /// <summary>
    /// Generates developer-friendly reports with remediation guidance.
    /// This service helps legitimate mod developers understand and fix false positives.
    /// </summary>
    public class DeveloperReportGenerator
    {
        private readonly MelonLogger.Instance _logger;

        public DeveloperReportGenerator(MelonLogger.Instance logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Generates a developer-friendly console report with remediation guidance.
        /// </summary>
        public void GenerateConsoleReport(string modName, List<ScanFinding> findings)
        {
            if (findings == null || findings.Count == 0)
                return;

            _logger.Msg("======= DEVELOPER SCAN REPORT =======");
            _logger.Msg($"Mod: {modName}");
            _logger.Msg("--------------------------------------");
            _logger.Msg($"Total findings: {findings.Count}");
            _logger.Msg("");

            var groupedByRule = findings
                .Where(f => f.RuleId != null)
                .GroupBy(f => f.RuleId)
                .OrderByDescending(g => g.Max(f => f.Severity));

            foreach (var ruleGroup in groupedByRule)
            {
                var firstFinding = ruleGroup.First();
                var count = ruleGroup.Count();

                _logger.Msg($"[{firstFinding.Severity}] {firstFinding.Description}");
                _logger.Msg($"  Rule: {firstFinding.RuleId}");
                _logger.Msg($"  Occurrences: {count}");

                // Show developer guidance if available
                if (firstFinding.DeveloperGuidance != null)
                {
                    _logger.Msg("");
                    _logger.Msg("  Developer Guidance:");
                    _logger.Msg($"  {WrapText(firstFinding.DeveloperGuidance.Remediation, 2)}");

                    if (!string.IsNullOrEmpty(firstFinding.DeveloperGuidance.DocumentationUrl))
                    {
                        _logger.Msg($"  Documentation: {firstFinding.DeveloperGuidance.DocumentationUrl}");
                    }

                    if (firstFinding.DeveloperGuidance.AlternativeApis != null && 
                        firstFinding.DeveloperGuidance.AlternativeApis.Length > 0)
                    {
                        _logger.Msg($"  Suggested APIs: {string.Join(", ", firstFinding.DeveloperGuidance.AlternativeApis)}");
                    }

                    if (!firstFinding.DeveloperGuidance.IsRemediable)
                    {
                        _logger.Warning("  ⚠ No safe alternative - this pattern should not be used in MelonLoader mods.");
                    }
                }
                else
                {
                    _logger.Msg("  (No developer guidance available for this rule)");
                }

                // Show sample locations
                _logger.Msg("");
                _logger.Msg("  Sample locations:");
                foreach (var finding in ruleGroup.Take(3))
                {
                    _logger.Msg($"    - {finding.Location}");
                }
                if (count > 3)
                {
                    _logger.Msg($"    ... and {count - 3} more");
                }

                _logger.Msg("");
                _logger.Msg("--------------------------------------");
            }

            _logger.Msg("");
            _logger.Msg("For more information, visit: https://discord.gg/UD4K4chKak");
            _logger.Msg("=====================================");
        }

        /// <summary>
        /// Generates a developer-friendly file report with remediation guidance.
        /// </summary>
        public string GenerateFileReport(string modName, string hash, List<ScanFinding> findings)
        {
            var sb = new StringBuilder();
            sb.AppendLine("======= MLVScan Developer Report =======");
            sb.AppendLine($"Mod: {modName}");
            sb.AppendLine($"SHA256: {hash}");
            sb.AppendLine($"Scan Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Total Findings: {findings.Count}");
            sb.AppendLine("");

            var groupedByRule = findings
                .Where(f => f.RuleId != null)
                .GroupBy(f => f.RuleId)
                .OrderByDescending(g => g.Max(f => f.Severity));

            foreach (var ruleGroup in groupedByRule)
            {
                var firstFinding = ruleGroup.First();
                var count = ruleGroup.Count();

                sb.AppendLine("=========================================");
                sb.AppendLine($"Rule: {firstFinding.RuleId}");
                sb.AppendLine($"Severity: {firstFinding.Severity}");
                sb.AppendLine($"Description: {firstFinding.Description}");
                sb.AppendLine($"Occurrences: {count}");
                sb.AppendLine("");

                // Developer guidance section
                if (firstFinding.DeveloperGuidance != null)
                {
                    sb.AppendLine("--- DEVELOPER GUIDANCE ---");
                    sb.AppendLine($"Remediation: {firstFinding.DeveloperGuidance.Remediation}");
                    sb.AppendLine("");

                    if (!string.IsNullOrEmpty(firstFinding.DeveloperGuidance.DocumentationUrl))
                    {
                        sb.AppendLine($"Documentation: {firstFinding.DeveloperGuidance.DocumentationUrl}");
                    }

                    if (firstFinding.DeveloperGuidance.AlternativeApis != null &&
                        firstFinding.DeveloperGuidance.AlternativeApis.Length > 0)
                    {
                        sb.AppendLine("Suggested APIs:");
                        foreach (var api in firstFinding.DeveloperGuidance.AlternativeApis)
                        {
                            sb.AppendLine($"  - {api}");
                        }
                    }

                    if (!firstFinding.DeveloperGuidance.IsRemediable)
                    {
                        sb.AppendLine("");
                        sb.AppendLine("WARNING: This pattern has no safe alternative and should not be used in MelonLoader mods.");
                    }

                    sb.AppendLine("");
                }
                else
                {
                    sb.AppendLine("(No developer guidance available for this rule)");
                    sb.AppendLine("");
                }

                // Detailed findings
                sb.AppendLine("--- FINDINGS ---");
                foreach (var finding in ruleGroup)
                {
                    sb.AppendLine($"Location: {finding.Location}");
                    if (!string.IsNullOrEmpty(finding.CodeSnippet))
                    {
                        sb.AppendLine("Code Snippet:");
                        sb.AppendLine(finding.CodeSnippet);
                    }
                    sb.AppendLine("");
                }
            }

            sb.AppendLine("=========================================");
            sb.AppendLine("");
            sb.AppendLine("Need help? Join the community: https://discord.gg/UD4K4chKak");

            return sb.ToString();
        }

        private string WrapText(string text, int indent)
        {
            var indentStr = new string(' ', indent);
            var maxWidth = 80 - indent;
            var words = text.Split(' ');
            var lines = new List<string>();
            var currentLine = "";

            foreach (var word in words)
            {
                if (currentLine.Length + word.Length + 1 > maxWidth)
                {
                    if (!string.IsNullOrEmpty(currentLine))
                        lines.Add(currentLine);
                    currentLine = word;
                }
                else
                {
                    currentLine += (currentLine.Length > 0 ? " " : "") + word;
                }
            }

            if (!string.IsNullOrEmpty(currentLine))
                lines.Add(currentLine);

            return string.Join("\n  " + indentStr, lines);
        }
    }
}
