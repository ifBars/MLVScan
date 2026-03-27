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
    /// Generates detailed reports for blocked plugins and review-required plugins.
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

            var disabledByPath = (disabledPlugins ?? new List<DisabledPluginInfo>())
                .ToDictionary(info => info.OriginalPath, StringComparer.OrdinalIgnoreCase);

            foreach (var (pluginPath, scanResult) in scanResults.OrderBy(kv => Path.GetFileName(kv.Key), StringComparer.OrdinalIgnoreCase))
            {
                disabledByPath.TryGetValue(pluginPath, out var pluginInfo);
                var pluginName = Path.GetFileName(pluginPath);

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
            var scanStatus = pluginInfo?.ScanStatus ?? scanResult?.ScanStatus ?? new ScanStatusInfo();
            var wasBlocked = pluginInfo != null;
            var outcomeLabel = ThreatVerdictTextFormatter.GetOutcomeLabel(scanResult);
            var outcomeSummary = ThreatVerdictTextFormatter.GetOutcomeSummary(scanResult);
            var fileHash = pluginInfo?.FileHash ?? scanResult?.FileHash ?? string.Empty;

            _logger.LogWarning(new string('=', 50));
            _logger.LogWarning($"{(wasBlocked ? "BLOCKED PLUGIN" : "REVIEW REQUIRED")}: {pluginName}");
            _logger.LogInfo($"SHA256: {fileHash}");
            if (!string.IsNullOrWhiteSpace(outcomeLabel))
            {
                _logger.LogWarning($"Outcome: {outcomeLabel}");
            }

            if (!string.IsNullOrWhiteSpace(outcomeSummary))
            {
                _logger.LogInfo(outcomeSummary);
            }

            if (scanStatus.Kind != ScanStatusKind.Complete)
            {
                _logger.LogInfo(wasBlocked
                    ? "Action: blocked by current incomplete-scan policy."
                    : "Action: manual review required; not blocked by current config.");
            }

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

            _logger.LogInfo($"Retained findings: {findings.Count}");

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

            DisplaySecurityNotice(pluginName, threatVerdict, scanStatus, wasBlocked);
        }

        private void DisplaySecurityNotice(
            string pluginName,
            ThreatVerdictInfo threatVerdict,
            ScanStatusInfo scanStatus,
            bool wasBlocked)
        {
            _logger.LogWarning("--- SECURITY NOTICE ---");
            _logger.LogInfo(wasBlocked
                ? $"MLVScan blocked {pluginName} before it could execute."
                : $"MLVScan flagged {pluginName} for review but did not block it under the current configuration.");
            if (IsKnownThreatVerdict(threatVerdict))
            {
                _logger.LogInfo("This plugin is likely malware because it matched previously analyzed malware intelligence.");
                _logger.LogInfo("If this is your first time with this plugin, you are likely safe.");
                _logger.LogInfo("If you've used it before, run a malware scan and review the report immediately.");
            }
            else if (threatVerdict?.Kind == ThreatVerdictKind.Suspicious)
            {
                _logger.LogInfo("This plugin was flagged because it triggered suspicious correlated behavior.");
                _logger.LogInfo("It may still be a false positive, so use the saved report for human review before assuming infection.");
                _logger.LogInfo("Review the detailed report before deciding whether to whitelist it.");
            }
            else if (scanStatus?.Kind == ScanStatusKind.RequiresReview)
            {
                _logger.LogInfo("This plugin could not be fully analyzed by the loader because it exceeded the current in-memory scan limit.");
                _logger.LogInfo("MLVScan still calculated its SHA-256 hash and checked exact known-malicious sample matches.");
                _logger.LogInfo("Review the detailed report before deciding whether to whitelist it or enable strict incomplete-scan blocking.");
            }
            else
            {
                _logger.LogInfo("Review the detailed report before deciding whether to whitelist it.");
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
                var resolvedVerdict = pluginInfo?.ThreatVerdict ?? scanResult?.ThreatVerdict ?? new ThreatVerdictInfo();
                var resolvedScanStatus = pluginInfo?.ScanStatus ?? scanResult?.ScanStatus ?? new ScanStatusInfo();
                var wasBlocked = pluginInfo != null;
                var originalPath = pluginInfo?.OriginalPath ?? scanResult?.FilePath ?? string.Empty;
                var currentPath = pluginInfo?.DisabledPath ?? scanResult?.FilePath ?? string.Empty;
                var fileHash = pluginInfo?.FileHash ?? scanResult?.FileHash ?? string.Empty;
                var outcomeLabel = ThreatVerdictTextFormatter.GetOutcomeLabel(scanResult);
                var outcomeSummary = ThreatVerdictTextFormatter.GetOutcomeSummary(scanResult);
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var reportPath = Path.Combine(_reportDirectory, $"{pluginName}_{timestamp}.report.txt");

                var sb = new StringBuilder();
                sb.AppendLine(new string('=', 60));
                sb.AppendLine("MLVScan Security Report (BepInEx)");
                sb.AppendLine(new string('=', 60));
                sb.AppendLine($"Generated: {DateTime.Now}");
                sb.AppendLine($"Plugin: {pluginName}");
                sb.AppendLine($"Outcome: {outcomeLabel}");
                if (!string.IsNullOrWhiteSpace(outcomeSummary))
                {
                    sb.AppendLine($"Outcome Summary: {outcomeSummary}");
                }
                sb.AppendLine($"Action Taken: {(wasBlocked ? "Blocked" : "Manual review required (not blocked by current config)")}");
                sb.AppendLine($"SHA256: {fileHash}");
                sb.AppendLine($"Original Path: {originalPath}");
                sb.AppendLine($"{(wasBlocked ? "Blocked Path" : "Current Path")}: {currentPath}");
                sb.AppendLine($"Total Findings: {findings.Count}");
                sb.AppendLine();

                using (var verdictWriter = new StringWriter(sb))
                {
                    ThreatVerdictTextFormatter.WriteThreatVerdictSection(verdictWriter, resolvedVerdict);
                    ThreatVerdictTextFormatter.WriteScanStatusSection(verdictWriter, resolvedScanStatus);
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
                if (IsKnownThreatVerdict(resolvedVerdict))
                {
                    sb.AppendLine("1. Verify with the modding community if this is a known mod");
                    sb.AppendLine("2. Run a full system scan with Malwarebytes or similar");
                    sb.AppendLine("3. Check the Discord for guidance: https://discord.gg/UD4K4chKak");
                }
                else if (resolvedVerdict?.Kind == ThreatVerdictKind.Suspicious)
                {
                    sb.AppendLine("1. Verify with the modding community if this is a known mod");
                    sb.AppendLine("2. Review the detailed report before assuming infection");
                    sb.AppendLine("3. Only run a full system scan if you have already executed this plugin");
                    sb.AppendLine("4. Check the Discord for guidance: https://discord.gg/UD4K4chKak");
                }
                else if (resolvedScanStatus?.Kind == ScanStatusKind.RequiresReview)
                {
                    sb.AppendLine("1. Review the detailed report before assuming the plugin is safe");
                    sb.AppendLine("2. Validate the plugin with the original author or trusted community sources");
                    sb.AppendLine("3. Enable BlockIncompleteScans if you want oversized or incomplete scans blocked automatically");
                    sb.AppendLine("4. Check the Discord for guidance: https://discord.gg/UD4K4chKak");
                }
                else
                {
                    sb.AppendLine("1. Verify with the modding community if this is a known mod");
                    sb.AppendLine("2. Review the detailed report before assuming infection");
                    sb.AppendLine("3. Only run a full system scan if you have already executed this plugin");
                    sb.AppendLine("4. Check the Discord for guidance: https://discord.gg/UD4K4chKak");
                }
                sb.AppendLine();
                sb.AppendLine("To whitelist (if false positive):");
                sb.AppendLine($"  Add this hash to BepInEx/config/MLVScan.json:");
                sb.AppendLine($"  \"{fileHash}\"");

                File.WriteAllText(reportPath, sb.ToString());
                _logger.LogInfo($"Report saved: {reportPath}");

                if (_config.EnableReportUpload &&
                    !string.IsNullOrWhiteSpace(_reportUploadApiBaseUrl) &&
                    resolvedVerdict.Kind != ThreatVerdictKind.None)
                {
                    try
                    {
                        var accessiblePath = pluginInfo != null && File.Exists(pluginInfo.DisabledPath)
                            ? pluginInfo.DisabledPath
                            : (scanResult?.FilePath ?? string.Empty);
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

        private static bool IsKnownThreatVerdict(ThreatVerdictInfo threatVerdict)
        {
            return threatVerdict?.Kind == ThreatVerdictKind.KnownMaliciousSample ||
                   threatVerdict?.Kind == ThreatVerdictKind.KnownMalwareFamily;
        }
    }
}
