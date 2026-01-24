using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BepInEx;
using BepInEx.Logging;
using MLVScan.Models;
using MLVScan.Services;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// Generates detailed reports for blocked plugins.
    /// </summary>
    public class BepInExReportGenerator
    {
        private readonly ManualLogSource _logger;
        private readonly ScanConfig _config;
        private readonly string _reportDirectory;

        public BepInExReportGenerator(ManualLogSource logger, ScanConfig config)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _config = config ?? throw new ArgumentNullException(nameof(config));

            // Reports go to BepInEx/MLVScan/Reports/
            _reportDirectory = Path.Combine(Paths.BepInExRootPath, "MLVScan", "Reports");
        }

        public void GenerateReports(
            List<DisabledPluginInfo> disabledPlugins,
            Dictionary<string, List<ScanFinding>> scanResults)
        {
            EnsureReportDirectoryExists();

            foreach (var pluginInfo in disabledPlugins)
            {
                if (!scanResults.TryGetValue(pluginInfo.OriginalPath, out var findings))
                    continue;

                var pluginName = Path.GetFileName(pluginInfo.OriginalPath);

                // Log to console
                LogConsoleReport(pluginName, pluginInfo.FileHash, findings);

                // Generate file report
                GenerateFileReport(pluginName, pluginInfo, findings);
            }
        }

        private void LogConsoleReport(string pluginName, string hash, List<ScanFinding> findings)
        {
            _logger.LogWarning(new string('=', 50));
            _logger.LogWarning($"BLOCKED PLUGIN: {pluginName}");
            _logger.LogInfo($"SHA256: {hash}");
            _logger.LogInfo($"Suspicious patterns: {findings.Count}");

            var grouped = findings
                .GroupBy(f => f.Severity)
                .OrderByDescending(g => (int)g.Key);

            foreach (var group in grouped)
            {
                _logger.LogInfo($"  {group.Key}: {group.Count()} issue(s)");
            }

            // Show top 3 findings
            var topFindings = findings
                .OrderByDescending(f => f.Severity)
                .Take(3);

            foreach (var finding in topFindings)
            {
                _logger.LogWarning($"[{finding.Severity}] {finding.Description}");
                _logger.LogInfo($"  Location: {finding.Location}");
            }

            if (findings.Count > 3)
            {
                _logger.LogInfo($"  ... and {findings.Count - 3} more findings");
            }

            DisplaySecurityNotice(pluginName);
        }

        private void DisplaySecurityNotice(string pluginName)
        {
            _logger.LogWarning("--- SECURITY NOTICE ---");
            _logger.LogInfo($"MLVScan blocked {pluginName} before it could execute.");
            _logger.LogInfo("If this is your first time with this plugin, you are likely safe.");
            _logger.LogInfo("If you've used it before, consider running a malware scan.");
            _logger.LogInfo("");
            _logger.LogInfo("To whitelist a false positive:");
            _logger.LogInfo("  Add the SHA256 hash to BepInEx/config/MLVScan.json");
            _logger.LogInfo("");
            _logger.LogInfo("Resources:");
            _logger.LogInfo("  Malwarebytes: https://www.malwarebytes.com/");
            _logger.LogInfo("  Community: https://discord.gg/UD4K4chKak");
        }

        private void GenerateFileReport(
            string pluginName,
            DisabledPluginInfo pluginInfo,
            List<ScanFinding> findings)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var reportPath = Path.Combine(_reportDirectory, $"{pluginName}_{timestamp}.report.txt");

                var sb = new StringBuilder();
                sb.AppendLine(new string('=', 60));
                sb.AppendLine("MLVScan Security Report (BepInEx)");
                sb.AppendLine(new string('=', 60));
                sb.AppendLine($"Generated: {DateTime.Now}");
                sb.AppendLine($"Plugin: {pluginName}");
                sb.AppendLine($"SHA256: {pluginInfo.FileHash}");
                sb.AppendLine($"Original Path: {pluginInfo.OriginalPath}");
                sb.AppendLine($"Blocked Path: {pluginInfo.DisabledPath}");
                sb.AppendLine($"Total Findings: {findings.Count}");
                sb.AppendLine();

                // Severity breakdown
                sb.AppendLine("Severity Breakdown:");
                foreach (var group in findings.GroupBy(f => f.Severity).OrderByDescending(g => (int)g.Key))
                {
                    sb.AppendLine($"  {group.Key}: {group.Count()}");
                }
                sb.AppendLine();

                // Detailed findings
                sb.AppendLine(new string('=', 60));
                sb.AppendLine("DETAILED FINDINGS");
                sb.AppendLine(new string('=', 60));

                var groupedByDescription = findings.GroupBy(f => f.Description);
                foreach (var group in groupedByDescription)
                {
                    var first = group.First();
                    sb.AppendLine();
                    sb.AppendLine($"[{first.Severity}] {first.Description}");
                    sb.AppendLine($"Occurrences: {group.Count()}");

                    if (_config.DeveloperMode && first.DeveloperGuidance != null)
                    {
                        sb.AppendLine();
                        sb.AppendLine("Developer Guidance:");
                        sb.AppendLine($"  {first.DeveloperGuidance.Remediation}");

                        if (first.DeveloperGuidance.AlternativeApis?.Length > 0)
                        {
                            sb.AppendLine($"  Alternatives: {string.Join(", ", first.DeveloperGuidance.AlternativeApis)}");
                        }
                    }

                    sb.AppendLine();
                    sb.AppendLine("Locations:");
                    foreach (var finding in group.Take(10))
                    {
                        sb.AppendLine($"  - {finding.Location}");
                        if (!string.IsNullOrEmpty(finding.CodeSnippet))
                        {
                            foreach (var line in finding.CodeSnippet.Split('\n').Take(5))
                            {
                                sb.AppendLine($"      {line.Trim()}");
                            }
                        }
                    }

                    if (group.Count() > 10)
                    {
                        sb.AppendLine($"  ... and {group.Count() - 10} more");
                    }
                }

                // Security notice
                sb.AppendLine();
                sb.AppendLine(new string('=', 60));
                sb.AppendLine("SECURITY RECOMMENDATIONS");
                sb.AppendLine(new string('=', 60));
                sb.AppendLine("1. Verify with the modding community if this is a known mod");
                sb.AppendLine("2. Run a full system scan with Malwarebytes or similar");
                sb.AppendLine("3. Check the Discord for guidance: https://discord.gg/UD4K4chKak");
                sb.AppendLine();
                sb.AppendLine("To whitelist (if false positive):");
                sb.AppendLine($"  Add this hash to BepInEx/config/MLVScan.json:");
                sb.AppendLine($"  \"{pluginInfo.FileHash}\"");

                File.WriteAllText(reportPath, sb.ToString());
                _logger.LogInfo($"Report saved: {reportPath}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to generate report: {ex.Message}");
            }
        }

        private void EnsureReportDirectoryExists()
        {
            try
            {
                if (!Directory.Exists(_reportDirectory))
                {
                    Directory.CreateDirectory(_reportDirectory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to create report directory: {ex.Message}");
            }
        }
    }
}
