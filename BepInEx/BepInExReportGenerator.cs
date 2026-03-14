using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BepInEx;
using BepInEx.Logging;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// Generates detailed reports for blocked plugins.
    /// </summary>
    public class BepInExReportGenerator
    {
        private readonly ManualLogSource _logger;
        private readonly MLVScanConfig _config;
        private readonly string _reportUploadApiBaseUrl;
        private readonly string _reportDirectory;
        private readonly ReportUploadService _reportUploadService;

        public BepInExReportGenerator(ManualLogSource logger, MLVScanConfig config, string reportUploadApiBaseUrl, BepInExConfigManager configManager)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reportUploadApiBaseUrl = reportUploadApiBaseUrl ?? string.Empty;

            _reportUploadService = new ReportUploadService(
                configManager,
                msg => logger.LogInfo(msg),
                msg => logger.LogWarning(msg),
                msg => logger.LogError(msg));

            // Reports go to BepInEx/MLVScan/Reports/
            _reportDirectory = Path.Combine(Paths.BepInExRootPath, "MLVScan", "Reports");
        }

        public void GenerateReports(
            List<DisabledPluginInfo> disabledPlugins,
            Dictionary<string, ScannedPluginResult> scanResults)
        {
            EnsureReportDirectoryExists();

            foreach (var pluginInfo in disabledPlugins)
            {
                if (!scanResults.TryGetValue(pluginInfo.OriginalPath, out var scanResult))
                    continue;

                var pluginName = Path.GetFileName(pluginInfo.OriginalPath);

                // Log to console
                LogConsoleReport(pluginName, pluginInfo, scanResult);

                // Generate file report
                GenerateFileReport(pluginName, pluginInfo, scanResult);
            }
        }

        private void LogConsoleReport(string pluginName, DisabledPluginInfo pluginInfo, ScannedPluginResult scanResult)
        {
            var findings = scanResult?.Findings ?? new List<ScanFinding>();
            var threatVerdict = pluginInfo?.ThreatVerdict ?? scanResult?.ThreatVerdict ?? new ThreatVerdictInfo();

            _logger.LogWarning(new string('=', 50));
            _logger.LogWarning($"BLOCKED PLUGIN: {pluginName}");
            _logger.LogInfo($"SHA256: {pluginInfo.FileHash}");
            _logger.LogWarning($"Verdict: {ThreatVerdictTextFormatter.GetVerdictLabel(threatVerdict)}");
            _logger.LogInfo(threatVerdict.Summary);

            var familyName = ThreatVerdictTextFormatter.GetPrimaryFamilyLabel(threatVerdict);
            if (!string.IsNullOrWhiteSpace(familyName))
            {
                _logger.LogInfo($"Family: {familyName}");
            }

            var confidenceLabel = ThreatVerdictTextFormatter.GetConfidenceLabel(threatVerdict);
            if (!string.IsNullOrWhiteSpace(confidenceLabel))
            {
                _logger.LogInfo($"Confidence: {confidenceLabel}");
            }

            _logger.LogInfo($"Suspicious patterns: {findings.Count}");

            var grouped = findings
                .GroupBy(f => f.Severity)
                .OrderByDescending(g => (int)g.Key);

            foreach (var group in grouped)
            {
                _logger.LogInfo($"  {group.Key}: {group.Count()} issue(s)");
            }

            var topSignals = ThreatVerdictTextFormatter.GetTopFindingSummaries(findings, 3);
            if (topSignals.Count > 0)
            {
                _logger.LogInfo("Top signals:");
                foreach (var signal in topSignals)
                {
                    _logger.LogInfo($"  - {signal}");
                }
            }

            _logger.LogInfo("Full technical details were written to the saved report file for human review.");

            DisplaySecurityNotice(pluginName, threatVerdict);
        }

        private void DisplaySecurityNotice(string pluginName, ThreatVerdictInfo threatVerdict)
        {
            _logger.LogWarning("--- SECURITY NOTICE ---");
            _logger.LogInfo($"MLVScan blocked {pluginName} before it could execute.");
            if (threatVerdict?.Kind == ThreatVerdictKind.KnownMaliciousSample ||
                threatVerdict?.Kind == ThreatVerdictKind.KnownMalwareFamily)
            {
                _logger.LogInfo("This block was reinforced by a match to previously analyzed malware.");
                _logger.LogInfo("If this is your first time with this plugin, you are likely safe.");
                _logger.LogInfo("If you've used it before, run a malware scan and review the report immediately.");
            }
            else
            {
                _logger.LogInfo("This plugin was blocked as a precaution based on suspicious behavior patterns.");
                _logger.LogInfo("It may still be a false positive, so use the saved report for human review before assuming infection.");
            }
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
            ScannedPluginResult scanResult)
        {
            try
            {
                var findings = scanResult?.Findings ?? new List<ScanFinding>();
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

                using (var verdictWriter = new StringWriter(sb))
                {
                    ThreatVerdictTextFormatter.WriteThreatVerdictSection(verdictWriter, pluginInfo.ThreatVerdict ?? scanResult?.ThreatVerdict);
                }

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

                    if (_config.Scan?.DeveloperMode == true && first.DeveloperGuidance != null)
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

                        if (finding.HasCallChain && finding.CallChain != null)
                        {
                            sb.AppendLine("    Call Chain Analysis:");
                            foreach (var node in finding.CallChain.Nodes)
                            {
                                var prefix = node.NodeType switch
                                {
                                    CallChainNodeType.EntryPoint => "[ENTRY]",
                                    CallChainNodeType.IntermediateCall => "[CALL]",
                                    CallChainNodeType.SuspiciousDeclaration => "[DECL]",
                                    _ => "[???]"
                                };
                                sb.AppendLine($"      {prefix} {node.Location}");
                                if (!string.IsNullOrEmpty(node.Description))
                                {
                                    sb.AppendLine($"           {node.Description}");
                                }
                            }
                        }

                        if (finding.HasDataFlow && finding.DataFlowChain != null)
                        {
                            sb.AppendLine("    Data Flow Analysis:");
                            sb.AppendLine($"      Pattern: {finding.DataFlowChain.Pattern}");
                            if (finding.DataFlowChain.IsCrossMethod)
                            {
                                sb.AppendLine($"      Cross-method flow through {finding.DataFlowChain.InvolvedMethods.Count} methods");
                            }

                            sb.AppendLine("      Data Flow Chain:");
                            foreach (var node in finding.DataFlowChain.Nodes)
                            {
                                var nodePrefix = node.NodeType switch
                                {
                                    DataFlowNodeType.Source => "[SOURCE]",
                                    DataFlowNodeType.Transform => "[TRANSFORM]",
                                    DataFlowNodeType.Sink => "[SINK]",
                                    DataFlowNodeType.Intermediate => "[PASS]",
                                    _ => "[???]"
                                };

                                sb.AppendLine(
                                    $"        {nodePrefix} {node.Operation} ({node.DataDescription}) @ {node.Location}");
                            }
                        }

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

                if (_config.EnableReportUpload && !string.IsNullOrWhiteSpace(_reportUploadApiBaseUrl))
                {
                    try
                    {
                        var accessiblePath = File.Exists(pluginInfo.DisabledPath) ? pluginInfo.DisabledPath : pluginInfo.OriginalPath;
                        if (File.Exists(accessiblePath))
                        {
                            var assemblyBytes = File.ReadAllBytes(accessiblePath);
                            var metadata = BuildSubmissionMetadata(pluginName, findings);
                            _reportUploadService.UploadReportNonBlocking(assemblyBytes, pluginName, metadata, _reportUploadApiBaseUrl);
                        }
                    }
                    catch (Exception uploadEx)
                    {
                        _logger.LogWarning($"Report upload skipped for {pluginName}: {uploadEx.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to generate report: {ex.Message}");
            }
        }

        private static SubmissionMetadata BuildSubmissionMetadata(string pluginName, List<ScanFinding> findings)
        {
            var summary = findings
                .Take(20)
                .Select(f => new FindingSummaryItem
                {
                    RuleId = f.RuleId,
                    Description = f.Description,
                    Severity = f.Severity.ToString(),
                    Location = RedactionHelper.RedactLocation(f.Location)
                })
                .ToList();

            return new SubmissionMetadata
            {
                LoaderType = PlatformConstants.PlatformName,
                LoaderVersion = null,
                PluginVersion = PlatformConstants.PlatformVersion,
                ModName = RedactionHelper.RedactFilename(pluginName),
                FindingSummary = summary,
                ConsentVersion = "1",
                ConsentTimestamp = DateTime.UtcNow.ToString("o")
            };
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
