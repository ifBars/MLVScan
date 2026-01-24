using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MLVScan.Abstractions;
using MLVScan.Models;

namespace MLVScan.Services
{
    /// <summary>
    /// Generates developer-friendly reports with remediation guidance.
    /// This service helps legitimate mod developers understand and fix false positives.
    /// </summary>
    public class DeveloperReportGenerator
    {
        private readonly IScanLogger _logger;

        public DeveloperReportGenerator(IScanLogger logger)
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

            _logger.Info("======= DEVELOPER SCAN REPORT =======");
            _logger.Info(PlatformConstants.GetFullVersionInfo());
            _logger.Info($"Mod: {modName}");
            _logger.Info("--------------------------------------");
            _logger.Info($"Total findings: {findings.Count}");
            _logger.Info("");

            var groupedByRule = findings
                .Where(f => f.RuleId != null)
                .GroupBy(f => f.RuleId)
                .OrderByDescending(g => g.Max(f => f.Severity));

            foreach (var ruleGroup in groupedByRule)
            {
                var firstFinding = ruleGroup.First();
                var count = ruleGroup.Count();

                _logger.Info($"[{firstFinding.Severity}] {firstFinding.Description}");
                _logger.Info($"  Rule: {firstFinding.RuleId}");
                _logger.Info($"  Occurrences: {count}");

                // Show developer guidance if available
                if (firstFinding.DeveloperGuidance != null)
                {
                    _logger.Info("");
                    _logger.Info("  Developer Guidance:");
                    _logger.Info($"  {WrapText(firstFinding.DeveloperGuidance.Remediation, 2)}");

                    if (!string.IsNullOrEmpty(firstFinding.DeveloperGuidance.DocumentationUrl))
                    {
                        _logger.Info($"  Documentation: {firstFinding.DeveloperGuidance.DocumentationUrl}");
                    }

                    if (firstFinding.DeveloperGuidance.AlternativeApis != null &&
                        firstFinding.DeveloperGuidance.AlternativeApis.Length > 0)
                    {
                        _logger.Info($"  Suggested APIs: {string.Join(", ", firstFinding.DeveloperGuidance.AlternativeApis)}");
                    }

                    if (!firstFinding.DeveloperGuidance.IsRemediable)
                    {
                        _logger.Warning("  No safe alternative - this pattern should not be used in mods.");
                    }
                }
                else
                {
                    _logger.Info("  (No developer guidance available for this rule)");
                }

                // Show sample locations
                _logger.Info("");
                _logger.Info("  Sample locations:");
                foreach (var finding in ruleGroup.Take(3))
                {
                    _logger.Info($"    - {finding.Location}");
                }
                if (count > 3)
                {
                    _logger.Info($"    ... and {count - 3} more");
                }

                _logger.Info("");
                _logger.Info("--------------------------------------");
            }

            _logger.Info("");
            _logger.Info("For more information, visit: https://discord.gg/UD4K4chKak");
            _logger.Info("=====================================");
        }

        /// <summary>
        /// Generates a developer-friendly file report with remediation guidance.
        /// </summary>
        public string GenerateFileReport(string modName, string hash, List<ScanFinding> findings)
        {
            var sb = new StringBuilder();
            sb.AppendLine("======= MLVScan Developer Report =======");
            sb.AppendLine(PlatformConstants.GetFullVersionInfo());
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
                        sb.AppendLine("WARNING: This pattern has no safe alternative and should not be used in mods.");
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
