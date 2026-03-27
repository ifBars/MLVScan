using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MelonLoader;
using MelonLoader.Utils;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using UnityEngine;

[assembly: MelonInfo(typeof(MLVScan.MelonLoader.MelonLoaderPlugin), "MLVScan", MLVScan.PlatformConstants.PlatformVersion, "Bars")]
[assembly: MelonPriority(Int32.MinValue)]
[assembly: MelonColor(255, 139, 0, 0)]

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader plugin entry point for MLVScan.
    /// Sets up services and orchestrates scanning, disabling, and reporting.
    /// </summary>
    public class MelonLoaderPlugin : MelonPlugin
    {
        private MelonLoaderServiceFactory _serviceFactory;
        private MelonConfigManager _configManager;
        private MelonPlatformEnvironment _environment;
        private MelonPluginScanner _pluginScanner;
        private MelonPluginDisabler _pluginDisabler;
        private IlDumpService _ilDumpService;
        private DeveloperReportGenerator _developerReportGenerator;
        private ReportUploadService _reportUploadService;
        private bool _initialized = false;
        private bool _showUploadConsentPopup;
        private string _pendingUploadPath = string.Empty;
        private string _pendingUploadModName = string.Empty;
        private string _pendingUploadVerdictKind = string.Empty;
        private bool _pendingUploadWasBlocked = true;
        private List<ScanFinding> _pendingUploadFindings;

        public override void OnEarlyInitializeMelon()
        {
            try
            {
                LoggerInstance.Msg("Pre-scanning for malicious mods...");

                _serviceFactory = new MelonLoaderServiceFactory(LoggerInstance);
                _configManager = _serviceFactory.CreateConfigManager();
                _environment = _serviceFactory.CreateEnvironment();

                _pluginScanner = _serviceFactory.CreatePluginScanner();
                _pluginDisabler = _serviceFactory.CreatePluginDisabler();
                _ilDumpService = _serviceFactory.CreateIlDumpService();
                _developerReportGenerator = _serviceFactory.CreateDeveloperReportGenerator();
                _reportUploadService = _serviceFactory.CreateReportUploadService();

                _initialized = true;

                ScanAndDisableMods(true);
            }
            catch (Exception ex)
            {
                LoggerInstance.Error($"Error in pre-mod scan: {ex.Message}");
                LoggerInstance.Error(ex.StackTrace);
            }
        }

        public override void OnInitializeMelon()
        {
            try
            {
                LoggerInstance.Msg("MLVScan initialization complete");

                if (_configManager.Config.WhitelistedHashes.Length > 0)
                {
                    LoggerInstance.Msg($"{_configManager.Config.WhitelistedHashes.Length} mod(s) are whitelisted and won't be scanned");
                    LoggerInstance.Msg("To manage whitelisted mods, edit MelonPreferences.cfg");
                }
            }
            catch (Exception ex)
            {
                LoggerInstance.Error($"Error initializing MLVScan: {ex.Message}");
                LoggerInstance.Error(ex.StackTrace);
            }
        }

        public override void OnGUI()
        {
            if (!_showUploadConsentPopup)
            {
                return;
            }

            var width = Math.Min(620f, Screen.width - 40f);
            var height = 280f;
            var x = (Screen.width - width) / 2f;
            var y = (Screen.height - height) / 2f;

            GUI.Box(new Rect(0f, 0f, Screen.width, Screen.height), string.Empty);

            GUI.Box(new Rect(x, y, width, height), "MLVScan Upload Consent");
            GUI.Label(new Rect(x + 20f, y + 40f, width - 40f, 140f),
                ConsentMessageHelper.GetUploadConsentMessage(_pendingUploadModName, _pendingUploadVerdictKind, _pendingUploadWasBlocked) + "\n\n" +
                "Would you like to upload this file to the MLVScan API for human review?\n\n" +
                "Yes: upload this mod now and enable automatic uploads for future detections.\n" +
                "No: do not upload and do not show this prompt again.");

            if (GUI.Button(new Rect(x + 20f, y + height - 60f, (width - 60f) / 2f, 36f), "Yes, upload"))
            {
                HandleUploadConsentDecision(true);
            }

            if (GUI.Button(new Rect(x + 40f + (width - 60f) / 2f, y + height - 60f, (width - 60f) / 2f, 36f), "No thanks"))
            {
                HandleUploadConsentDecision(false);
            }
        }

        public Dictionary<string, ScannedPluginResult> ScanAndDisableMods(bool force = false)
        {
            try
            {
                if (!_initialized)
                {
                    LoggerInstance.Error("Cannot scan mods - MLVScan not properly initialized");
                    return new Dictionary<string, ScannedPluginResult>();
                }

                LoggerInstance.Msg("Scanning mods for threats...");
                var scanResults = _pluginScanner.ScanAllPlugins(force);

                var attentionResults = scanResults
                    .Where(kv => kv.Value != null && ScanResultFacts.RequiresAttention(kv.Value))
                    .ToDictionary(kv => kv.Key, kv => kv.Value);

                if (attentionResults.Count > 0)
                {
                    var disabledMods = _pluginDisabler.DisableSuspiciousPlugins(attentionResults, force);
                    var disabledCount = disabledMods.Count;
                    var reviewOnlyCount = attentionResults.Count - disabledCount;

                    if (disabledCount > 0)
                    {
                        LoggerInstance.Msg($"Disabled {disabledCount} mod(s) that matched the active blocking policy");
                    }

                    if (reviewOnlyCount > 0)
                    {
                        LoggerInstance.Warning($"{reviewOnlyCount} mod(s) require manual review but were not blocked by the current configuration");
                    }

                    GenerateDetailedReports(disabledMods, attentionResults);

                    LoggerInstance.Msg("To whitelist any false positives, add their SHA256 hash to the MLVScan → WhitelistedHashes setting in MelonPreferences.cfg");
                }
                else
                {
                    LoggerInstance.Msg("No mods requiring action were found");
                }

                return attentionResults;
            }
            catch (Exception ex)
            {
                LoggerInstance.Error($"Error scanning mods: {ex.Message}");
                return new Dictionary<string, ScannedPluginResult>();
            }
        }

        private void GenerateDetailedReports(List<DisabledPluginInfo> disabledMods, Dictionary<string, ScannedPluginResult> scanResults)
        {
            var isDeveloperMode = _configManager?.Config?.Scan?.DeveloperMode ?? false;
            var disabledByPath = (disabledMods ?? new List<DisabledPluginInfo>())
                .ToDictionary(info => info.OriginalPath, StringComparer.OrdinalIgnoreCase);

            if (isDeveloperMode)
            {
                LoggerInstance.Msg("Developer Mode: Enabled");
            }

            LoggerInstance.Warning("======= DETAILED SCAN REPORT =======");
            LoggerInstance.Msg(PlatformConstants.GetFullVersionInfo());

            foreach (var (scanPath, scanResult) in scanResults.OrderBy(kv => Path.GetFileName(kv.Key), StringComparer.OrdinalIgnoreCase))
            {
                disabledByPath.TryGetValue(scanPath, out var modInfo);

                var wasBlocked = modInfo != null;
                var modName = Path.GetFileName(scanPath);
                var fileHash = modInfo?.FileHash ?? scanResult?.FileHash ?? string.Empty;
                var originalPath = modInfo?.OriginalPath ?? scanResult?.FilePath ?? string.Empty;
                var accessiblePath = wasBlocked && File.Exists(modInfo.DisabledPath)
                    ? modInfo.DisabledPath
                    : (scanResult?.FilePath ?? scanPath);
                var actualFindings = scanResult?.Findings ?? new List<ScanFinding>();
                var threatVerdict = modInfo?.ThreatVerdict ?? scanResult?.ThreatVerdict ?? new ThreatVerdictInfo();
                var scanStatus = modInfo?.ScanStatus ?? scanResult?.ScanStatus ?? new ScanStatusInfo();
                var outcomeLabel = ThreatVerdictTextFormatter.GetOutcomeLabel(scanResult);
                var outcomeSummary = ThreatVerdictTextFormatter.GetOutcomeSummary(scanResult);
                var groupedFindings = actualFindings
                    .GroupBy(f => f.Description)
                    .ToDictionary(g => g.Key, g => g.ToList());

                LoggerInstance.Warning($"{(wasBlocked ? "BLOCKED MOD" : "REVIEW REQUIRED")}: {modName}");
                LoggerInstance.Msg($"SHA256 Hash: {fileHash}");
                LoggerInstance.Msg("-------------------------------");

                if (actualFindings.Count == 0 &&
                    threatVerdict.Kind == ThreatVerdictKind.None &&
                    scanStatus.Kind == ScanStatusKind.Complete)
                {
                    LoggerInstance.Msg("No specific findings were retained.");
                    continue;
                }

                if (threatVerdict.Kind != ThreatVerdictKind.None)
                {
                    QueueConsentPromptIfNeeded(accessiblePath, modName, actualFindings, threatVerdict, wasBlocked);
                }

                LoggerInstance.Warning($"Total retained findings: {actualFindings.Count}");
                if (!string.IsNullOrWhiteSpace(outcomeLabel))
                {
                    LoggerInstance.Warning($"Outcome: {outcomeLabel}");
                }

                if (!string.IsNullOrWhiteSpace(outcomeSummary))
                {
                    LoggerInstance.Msg(outcomeSummary);
                }

                if (scanStatus.Kind != ScanStatusKind.Complete)
                {
                    LoggerInstance.Msg(wasBlocked
                        ? "Action: blocked by current incomplete-scan policy."
                        : "Action: manual review required; not blocked by current config.");
                }

                var familyName = ThreatVerdictTextFormatter.GetPrimaryFamilyLabel(threatVerdict);
                if (!string.IsNullOrWhiteSpace(familyName))
                {
                    LoggerInstance.Msg($"Family: {familyName}");
                }

                var confidenceLabel = ThreatVerdictTextFormatter.GetConfidenceLabel(threatVerdict);
                if (!string.IsNullOrWhiteSpace(confidenceLabel))
                {
                    LoggerInstance.Msg($"Confidence: {confidenceLabel}");
                }

                var severityCounts = actualFindings
                    .GroupBy(f => f.Severity)
                    .OrderByDescending(g => (int)g.Key)
                    .ToDictionary(g => g.Key, g => g.Count());

                LoggerInstance.Warning("Severity breakdown:");
                foreach (var severityCount in severityCounts)
                {
                    var severityLabel = FormatSeverityLabel(severityCount.Key);
                    LoggerInstance.Msg($"  {severityLabel}: {severityCount.Value} issue(s)");
                }

                LoggerInstance.Msg("-------------------------------");

                var topSignals = ThreatVerdictTextFormatter.GetTopFindingSummaries(actualFindings, 3);
                if (topSignals.Count > 0)
                {
                    LoggerInstance.Warning("Top signals:");
                    foreach (var signal in topSignals)
                    {
                        LoggerInstance.Msg($"  - {signal}");
                    }
                }

                if (isDeveloperMode)
                {
                    LoggerInstance.Msg("Developer mode is enabled. Full remediation guidance is included in the report file.");
                }

                LoggerInstance.Msg("Full technical details were written to the saved report file for human review.");
                LoggerInstance.Msg("-------------------------------");
                DisplaySecurityNotice(modName, threatVerdict, scanStatus, wasBlocked);

                try
                {
                    var reportDirectory = _environment?.ReportsDirectory
                        ?? Path.Combine(MelonEnvironment.UserDataDirectory, "MLVScan", "Reports");
                    if (!Directory.Exists(reportDirectory))
                    {
                        Directory.CreateDirectory(reportDirectory);
                    }

                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    var reportPath = Path.Combine(reportDirectory, $"{modName}_{timestamp}.report.txt");
                    var promptDirectory = Path.Combine(reportDirectory, "Prompts");
                    if (!Directory.Exists(promptDirectory))
                    {
                        Directory.CreateDirectory(promptDirectory);
                    }

                    if (_configManager?.Config?.DumpFullIlReports == true &&
                        _ilDumpService != null &&
                        scanStatus.Kind == ScanStatusKind.Complete)
                    {
                        var ilDirectory = Path.Combine(reportDirectory, "IL");
                        var ilDumpPath = Path.Combine(ilDirectory, $"{modName}_{timestamp}.il.txt");
                        var dumped = _ilDumpService.TryDumpAssembly(accessiblePath, ilDumpPath);
                        if (dumped)
                        {
                            LoggerInstance.Msg($"Full IL dump saved to: {ilDumpPath}");
                        }
                        else
                        {
                            LoggerInstance.Warning("Failed to dump IL for this mod (see logs for details).");
                        }
                    }
                    else if (_configManager?.Config?.DumpFullIlReports == true &&
                             scanStatus.Kind == ScanStatusKind.RequiresReview)
                    {
                        LoggerInstance.Warning("Skipped full IL dump because this file was not fully analyzed by the loader.");
                    }

                    var promptGenerator = scanStatus.Kind == ScanStatusKind.Complete
                        ? _serviceFactory.CreatePromptGenerator()
                        : null;

                    using (var writer = new StreamWriter(reportPath))
                    {
                        if (isDeveloperMode && _developerReportGenerator != null)
                        {
                            var devReport = _developerReportGenerator.GenerateFileReport(modName, fileHash, actualFindings, threatVerdict, scanStatus);
                            writer.Write(devReport);
                        }
                        else
                        {
                            writer.WriteLine("MLVScan Security Report");
                            writer.WriteLine(PlatformConstants.GetFullVersionInfo());
                            writer.WriteLine($"Generated: {DateTime.Now}");
                            writer.WriteLine($"Mod File: {modName}");
                            writer.WriteLine($"Outcome: {outcomeLabel}");
                            if (!string.IsNullOrWhiteSpace(outcomeSummary))
                            {
                                writer.WriteLine($"Outcome Summary: {outcomeSummary}");
                            }
                            writer.WriteLine($"Action Taken: {(wasBlocked ? "Blocked" : "Manual review required (not blocked by current config)")}");
                            writer.WriteLine($"SHA256 Hash: {fileHash}");
                            writer.WriteLine($"Original Path: {originalPath}");
                            writer.WriteLine($"{(wasBlocked ? "Disabled Path" : "Current Path")}: {accessiblePath}");
                            writer.WriteLine($"Path Used For Analysis: {accessiblePath}");
                            writer.WriteLine($"Total Retained Findings: {actualFindings.Count}");
                            writer.WriteLine();
                            ThreatVerdictTextFormatter.WriteThreatVerdictSection(writer, threatVerdict);
                            ThreatVerdictTextFormatter.WriteScanStatusSection(writer, scanStatus);
                            writer.WriteLine("\nSeverity Breakdown:");
                            foreach (var severityCount in severityCounts)
                            {
                                writer.WriteLine($"- {severityCount.Key}: {severityCount.Value} issue(s)");
                            }
                            writer.WriteLine("==============================================");

                            foreach (var group in groupedFindings)
                            {
                                writer.WriteLine($"\n== {group.Key} ==");
                                writer.WriteLine($"Severity: {group.Value[0].Severity}");
                                writer.WriteLine($"Instances: {group.Value.Count}");
                                writer.WriteLine("\nLocations & Analysis:");
                                foreach (var finding in group.Value)
                                {
                                    writer.WriteLine($"- {finding.Location}");

                                    if (finding.HasCallChain && finding.CallChain != null)
                                    {
                                        writer.WriteLine("  Call Chain Analysis:");
                                        writer.WriteLine($"  {finding.CallChain.Summary}");
                                        writer.WriteLine("  Attack Path:");
                                        foreach (var node in finding.CallChain.Nodes)
                                        {
                                            var prefix = node.NodeType switch
                                            {
                                                CallChainNodeType.EntryPoint => "[ENTRY]",
                                                CallChainNodeType.IntermediateCall => "[CALL]",
                                                CallChainNodeType.SuspiciousDeclaration => "[DECL]",
                                                _ => "[???]"
                                            };
                                            writer.WriteLine($"    {prefix} {node.Location}");
                                            if (!string.IsNullOrEmpty(node.Description))
                                            {
                                                writer.WriteLine($"         {node.Description}");
                                            }
                                        }
                                    }

                                    if (finding.HasDataFlow && finding.DataFlowChain != null)
                                    {
                                        writer.WriteLine("  Data Flow Analysis:");
                                        writer.WriteLine($"  Pattern: {finding.DataFlowChain.Pattern}");
                                        writer.WriteLine($"  {finding.DataFlowChain.Summary}");
                                        if (finding.DataFlowChain.IsCrossMethod)
                                        {
                                            writer.WriteLine($"  Cross-method flow through {finding.DataFlowChain.InvolvedMethods.Count} methods");
                                        }

                                        writer.WriteLine("  Data Flow Chain:");
                                        foreach (var node in finding.DataFlowChain.Nodes)
                                        {
                                            var prefix = node.NodeType switch
                                            {
                                                DataFlowNodeType.Source => "[SOURCE]",
                                                DataFlowNodeType.Transform => "[TRANSFORM]",
                                                DataFlowNodeType.Sink => "[SINK]",
                                                DataFlowNodeType.Intermediate => "[PASS]",
                                                _ => "[???]"
                                            };
                                            writer.WriteLine(
                                                $"    {prefix} {node.Operation} ({node.DataDescription}) @ {node.Location}");
                                        }
                                    }

                                    if (!string.IsNullOrEmpty(finding.CodeSnippet))
                                    {
                                        writer.WriteLine("  Code Snippet (IL):");
                                        foreach (var line in finding.CodeSnippet.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                                        {
                                            writer.WriteLine($"    {line}");
                                        }
                                        writer.WriteLine();
                                    }
                                }
                            }

                            WriteSecurityNoticeToReport(writer, threatVerdict, scanStatus, wasBlocked);
                        }
                    }

                    var promptSaved = false;
                    if (promptGenerator != null)
                    {
                        promptSaved = promptGenerator.SavePromptToFile(
                            accessiblePath,
                            actualFindings,
                            promptDirectory);
                    }
                    else if (scanStatus.Kind == ScanStatusKind.RequiresReview)
                    {
                        LoggerInstance.Warning("Skipped LLM prompt generation because this file was not fully analyzed by the loader.");
                    }

                    if (promptSaved)
                    {
                        LoggerInstance.Msg($"Detailed report saved to: {reportPath}");
                        LoggerInstance.Msg($"LLM analysis prompt saved to: {Path.Combine(promptDirectory, $"{modName}.prompt.md")}");
                        LoggerInstance.Msg("You can copy the contents of the prompt file into ChatGPT to help determine if this is malware or a false positive, although don't trust ChatGPT to be 100% accurate.");
                    }
                    else
                    {
                        LoggerInstance.Msg($"Detailed report saved to: {reportPath}");
                    }

                    if (_configManager?.Config?.EnableReportUpload == true &&
                        _reportUploadService != null &&
                        threatVerdict.Kind != ThreatVerdictKind.None)
                    {
                        try
                        {
                            var apiBaseUrl = _configManager.GetReportUploadApiBaseUrl();
                            if (!string.IsNullOrWhiteSpace(apiBaseUrl) && File.Exists(accessiblePath))
                            {
                                var assemblyBytes = File.ReadAllBytes(accessiblePath);
                                var metadata = BuildSubmissionMetadata(modName, actualFindings);
                                _reportUploadService.UploadReportNonBlocking(assemblyBytes, modName, metadata, apiBaseUrl);
                            }
                        }
                        catch (Exception uploadEx)
                        {
                            LoggerInstance.Warning($"Report upload skipped for {modName}: {uploadEx.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    LoggerInstance.Error($"Failed to save detailed report: {ex.Message}");
                }
            }

            LoggerInstance.Warning("====== END OF SCAN REPORT ======");
        }

        private void QueueConsentPromptIfNeeded(
            string accessiblePath,
            string modName,
            List<ScanFinding> findings,
            ThreatVerdictInfo threatVerdict,
            bool wasBlocked)
        {
            if (_configManager == null || _showUploadConsentPopup)
            {
                return;
            }

            var config = _configManager.Config;
            if (config.ReportUploadConsentAsked)
            {
                return;
            }

            _showUploadConsentPopup = true;
            _pendingUploadPath = accessiblePath;
            _pendingUploadModName = modName;
            _pendingUploadVerdictKind = threatVerdict?.Kind.ToString() ?? string.Empty;
            _pendingUploadWasBlocked = wasBlocked;
            _pendingUploadFindings = findings;

            config.ReportUploadConsentPending = true;
            config.PendingReportUploadPath = accessiblePath ?? string.Empty;
            config.PendingReportUploadVerdictKind = _pendingUploadVerdictKind;
            _configManager.SaveConfig(config);

            LoggerInstance.Warning("MLVScan is waiting for your upload consent decision in the in-game popup.");
        }

        private void HandleUploadConsentDecision(bool approved)
        {
            _showUploadConsentPopup = false;

            if (_configManager == null)
            {
                return;
            }

            var config = _configManager.Config;
            config.ReportUploadConsentAsked = true;
            config.ReportUploadConsentPending = false;
            config.PendingReportUploadPath = string.Empty;
            config.PendingReportUploadVerdictKind = string.Empty;
            config.EnableReportUpload = approved;
            _configManager.SaveConfig(config);

            if (!approved)
            {
                LoggerInstance.Msg("MLVScan report upload declined. You will not be prompted again.");
                _pendingUploadPath = string.Empty;
                _pendingUploadModName = string.Empty;
                _pendingUploadVerdictKind = string.Empty;
                _pendingUploadWasBlocked = true;
                _pendingUploadFindings = null;
                return;
            }

            LoggerInstance.Msg("MLVScan report upload enabled. Uploading the flagged mod now.");

            try
            {
                if (_reportUploadService != null && !string.IsNullOrWhiteSpace(_pendingUploadPath) && File.Exists(_pendingUploadPath))
                {
                    var apiBaseUrl = _configManager.GetReportUploadApiBaseUrl();
                    if (!string.IsNullOrWhiteSpace(apiBaseUrl))
                    {
                        var assemblyBytes = File.ReadAllBytes(_pendingUploadPath);
                        var metadata = BuildSubmissionMetadata(_pendingUploadModName, _pendingUploadFindings ?? new List<ScanFinding>());
                        _reportUploadService.UploadReportNonBlocking(assemblyBytes, _pendingUploadModName, metadata, apiBaseUrl);
                    }
                }
            }
            catch (Exception uploadEx)
            {
                LoggerInstance.Warning($"Report upload skipped for {_pendingUploadModName}: {uploadEx.Message}");
            }
            finally
            {
                _pendingUploadPath = string.Empty;
                _pendingUploadModName = string.Empty;
                _pendingUploadVerdictKind = string.Empty;
                _pendingUploadWasBlocked = true;
                _pendingUploadFindings = null;
            }
        }

        private static SubmissionMetadata BuildSubmissionMetadata(string modName, List<ScanFinding> findings)
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
                LoaderType = "MelonLoader",
                LoaderVersion = null,
                PluginVersion = PlatformConstants.PlatformVersion,
                ModName = RedactionHelper.RedactFilename(modName),
                FindingSummary = summary,
                ConsentVersion = "1",
                ConsentTimestamp = DateTime.UtcNow.ToString("o")
            };
        }

        private static string FormatSeverityLabel(Severity severity)
        {
            return severity switch
            {
                Severity.Critical => "CRITICAL",
                Severity.High => "HIGH",
                Severity.Medium => "MEDIUM",
                Severity.Low => "LOW",
                _ => severity.ToString().ToUpper()
            };
        }

        private void DisplaySecurityNotice(
            string modName,
            ThreatVerdictInfo threatVerdict,
            ScanStatusInfo scanStatus,
            bool wasBlocked)
        {
            LoggerInstance.Warning("IMPORTANT SECURITY NOTICE");
            LoggerInstance.Msg(wasBlocked
                ? $"MLVScan detected and disabled {modName} before it was loaded."
                : $"MLVScan flagged {modName} for review but did not block it under the current configuration.");
            if (IsKnownThreatVerdict(threatVerdict))
            {
                LoggerInstance.Msg("This mod is likely malware because it matched previously analyzed malware intelligence.");
                LoggerInstance.Msg("If this is your first time running the game with this mod, your PC is likely safe.");
                LoggerInstance.Msg("However, if you've previously run the game with this mod, your system MAY be infected.");
                LoggerInstance.Warning("Recommended security steps:");
                LoggerInstance.Msg("1. Check with the modding community first - no detection is perfect");
                LoggerInstance.Msg("   Join the modding Discord at: https://discord.gg/UD4K4chKak");
                LoggerInstance.Msg("   Ask about this mod in the MLVScan thread of #mod-releases to confirm if it's actually malicious");
                LoggerInstance.Msg("2. Run a full system scan with a trusted antivirus like Malwarebytes");
                LoggerInstance.Msg("   Malwarebytes is recommended as a free and effective antivirus solution");
                LoggerInstance.Msg("3. Use Microsoft Safety Scanner for a secondary scan");
                LoggerInstance.Msg("4. Change important passwords if antivirus shows a threat");
                LoggerInstance.Warning("Resources for malware removal:");
                LoggerInstance.Msg("- Malwarebytes: https://www.malwarebytes.com/cybersecurity/basics/how-to-remove-virus-from-computer");
                LoggerInstance.Msg("- Microsoft Safety Scanner: https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download");
            }
            else if (threatVerdict?.Kind == ThreatVerdictKind.Suspicious)
            {
                LoggerInstance.Msg("This mod was flagged because it triggered suspicious correlated behavior.");
                LoggerInstance.Msg("It may still be a false positive, so review the saved report before assuming infection.");
                LoggerInstance.Warning("Recommended review steps:");
                LoggerInstance.Msg("1. Check with the modding community first - no detection is perfect");
                LoggerInstance.Msg("   Join the modding Discord at: https://discord.gg/UD4K4chKak");
                LoggerInstance.Msg("   Ask about this mod in the MLVScan thread of #mod-releases to confirm if it is actually malicious");
                LoggerInstance.Msg("2. Review the saved report for the exact behavior that triggered the block");
                LoggerInstance.Msg("3. Only run a full antivirus scan if you have already executed this mod or still do not trust it");
                LoggerInstance.Msg("4. Whitelist the SHA256 only if you have independently verified the mod is safe");
            }
            else if (scanStatus?.Kind == ScanStatusKind.RequiresReview)
            {
                LoggerInstance.Msg("This mod could not be fully analyzed by the loader because it exceeded the current in-memory scan limit.");
                LoggerInstance.Msg("MLVScan still calculated its SHA-256 hash and checked exact known-malicious sample matches.");
                LoggerInstance.Warning("Recommended review steps:");
                LoggerInstance.Msg("1. Review the saved report before assuming the mod is safe");
                LoggerInstance.Msg("2. Validate the mod with trusted community sources or the original author");
                LoggerInstance.Msg("3. Enable BlockIncompleteScans if you want oversized or incomplete scans blocked automatically");
                LoggerInstance.Msg("4. Whitelist the SHA256 only after independent verification");
            }
            else
            {
                LoggerInstance.Msg("Review the saved report before deciding whether to whitelist this mod.");
            }
        }

        private static void WriteSecurityNoticeToReport(
            StreamWriter writer,
            ThreatVerdictInfo threatVerdict,
            ScanStatusInfo scanStatus,
            bool wasBlocked)
        {
            writer.WriteLine("\n\n============== SECURITY NOTICE ==============\n");
            writer.WriteLine("IMPORTANT: READ THIS SECURITY INFORMATION\n");
            writer.WriteLine(wasBlocked
                ? "MLVScan detected and disabled this mod before it was loaded."
                : "MLVScan flagged this mod for review but did not block it under the current configuration.");
            if (IsKnownThreatVerdict(threatVerdict))
            {
                writer.WriteLine("This mod is likely malware because it matched previously analyzed malware intelligence.\n");
                writer.WriteLine("YOUR SYSTEM SECURITY STATUS:");
                writer.WriteLine("- If this is your FIRST TIME starting the game with this mod installed:");
                writer.WriteLine("  Your PC is likely SAFE as MLVScan prevented the mod from loading.");
                writer.WriteLine("\n- If you have PREVIOUSLY PLAYED the game with this mod loaded:");
                writer.WriteLine("  Your system MAY BE INFECTED with malware. Take action immediately.\n");
                writer.WriteLine("RECOMMENDED SECURITY STEPS:");
                writer.WriteLine("1. Check with the modding community first - no detection system is perfect");
                writer.WriteLine("   Join the modding Discord at: https://discord.gg/UD4K4chKak");
                writer.WriteLine("   Ask about this mod in the #MLVScan or #report-mods channels to confirm if it is actually malicious");
                writer.WriteLine("\n2. Run a full system scan with a reputable antivirus program");
                writer.WriteLine("   Free option: Malwarebytes (https://www.malwarebytes.com/)");
                writer.WriteLine("   Malwarebytes is recommended as a free and effective antivirus solution");
                writer.WriteLine("\n3. Run Microsoft Safety Scanner as a secondary check");
                writer.WriteLine("   Download: https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download");
                writer.WriteLine("\n4. Update all your software from official sources");
                writer.WriteLine("\n5. Change passwords for important accounts (from a clean device if possible)");
                writer.WriteLine("\n6. Monitor your accounts for any suspicious activity");
                writer.WriteLine("\nDETAILED MALWARE REMOVAL GUIDES:");
                writer.WriteLine("- Malwarebytes Guide: https://www.malwarebytes.com/cybersecurity/basics/how-to-remove-virus-from-computer");
                writer.WriteLine("- Microsoft Safety Scanner: https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download");
                writer.WriteLine("- XWorm (Common Modding Malware) Removal Guide: https://www.pcrisk.com/removal-guides/27436-xworm-rat");
            }
            else if (threatVerdict?.Kind == ThreatVerdictKind.Suspicious)
            {
                writer.WriteLine("This mod was flagged because it triggered suspicious correlated behavior.\n");
                writer.WriteLine("IMPORTANT:");
                writer.WriteLine("- This may still be a false positive.");
                writer.WriteLine("- Review the report details and verify the mod with trusted community sources before assuming infection.\n");
                writer.WriteLine("RECOMMENDED REVIEW STEPS:");
                writer.WriteLine("1. Check with the modding community first - no detection system is perfect");
                writer.WriteLine("   Join the modding Discord at: https://discord.gg/UD4K4chKak");
                writer.WriteLine("   Ask about this mod in the #MLVScan or #report-mods channels to confirm if it is actually malicious");
                writer.WriteLine("\n2. Review the detailed findings and call/data-flow evidence in this report");
                writer.WriteLine("\n3. Only run a full antivirus scan if you already executed the mod or still do not trust it");
                writer.WriteLine("\n4. Whitelist the SHA256 only after independent verification");
            }
            else if (scanStatus?.Kind == ScanStatusKind.RequiresReview)
            {
                writer.WriteLine("This mod could not be fully analyzed by the loader because it exceeded the current in-memory scan limit.\n");
                writer.WriteLine("IMPORTANT:");
                writer.WriteLine("- MLVScan still calculated the SHA-256 hash and checked exact known-malicious sample matches.");
                writer.WriteLine("- No retained malicious verdict was produced, but the file was not fully analyzed.");
                writer.WriteLine("- Review the report details and verify the mod with trusted community sources before assuming it is safe.\n");
                writer.WriteLine("RECOMMENDED REVIEW STEPS:");
                writer.WriteLine("1. Review the report details and confirm whether this mod is expected to be unusually large");
                writer.WriteLine("\n2. Validate the mod with the original author or trusted community sources");
                writer.WriteLine("\n3. Enable BlockIncompleteScans if you want oversized or incomplete scans blocked automatically");
                writer.WriteLine("\n4. Whitelist the SHA256 only after independent verification");
            }
            writer.WriteLine("\n=============================================");
        }

        private static bool IsKnownThreatVerdict(ThreatVerdictInfo threatVerdict)
        {
            return threatVerdict?.Kind == ThreatVerdictKind.KnownMaliciousSample ||
                   threatVerdict?.Kind == ThreatVerdictKind.KnownMalwareFamily;
        }

    }
}
