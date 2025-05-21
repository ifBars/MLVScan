using MelonLoader;
using MLVScan.Models;
using MLVScan.Services;

[assembly: MelonInfo(typeof(MLVScan.Core), "MLVScan", "1.5.3", "Bars")]
[assembly: MelonPriority(Int32.MinValue)]
[assembly: MelonColor(255, 139, 0, 0)]

namespace MLVScan
{
    public class Core : MelonPlugin
    {
        private ServiceFactory _serviceFactory;
        private ConfigManager _configManager;
        private ModScanner _modScanner;
        private ModDisabler _modDisabler;
        private bool _initialized = false;

        private static readonly string[] DefaultWhitelistedMods =
        [
            "MLVScan.dll",
            "MLVScan.MelonLoader.dll",
            "CustomTV.dll",
            "CustomTV_Mono.dll",
            "CustomTV_IL2CPP.dll",
        ];

        public override void OnEarlyInitializeMelon()
        {
            try
            {
                LoggerInstance.Msg("Pre-scanning for malicious mods...");

                _serviceFactory = new ServiceFactory(LoggerInstance);
                _configManager = _serviceFactory.CreateConfigManager();

                InitializeDefaultWhitelist();

                _modScanner = _serviceFactory.CreateModScanner();
                _modDisabler = _serviceFactory.CreateModDisabler();

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

                if (_configManager.Config.WhitelistedMods.Length > 0)
                {
                    LoggerInstance.Msg($"{_configManager.Config.WhitelistedMods.Length} mod(s) are whitelisted and won't be scanned");
                    LoggerInstance.Msg("To manage whitelisted mods, edit MelonPreferences.cfg");
                }
            }
            catch (Exception ex)
            {
                LoggerInstance.Error($"Error initializing MLVScan: {ex.Message}");
                LoggerInstance.Error(ex.StackTrace);
            }
        }

        private void InitializeDefaultWhitelist()
        {
            if (_configManager == null)
                return;

            var currentWhitelist = _configManager.GetWhitelistedMods();

            if (currentWhitelist.Length == 0)
            {
                LoggerInstance.Msg("Initializing default whitelist");
                _configManager.SetWhitelistedMods(DefaultWhitelistedMods);
            }
        }

        public Dictionary<string, List<ScanFinding>> ScanAndDisableMods(bool force = false)
        {
            try
            {
                if (!_initialized)
                {
                    LoggerInstance.Error("Cannot scan mods - MLVScan not properly initialized");
                    return new Dictionary<string, List<ScanFinding>>();
                }

                LoggerInstance.Msg("Scanning for suspicious mods...");
                var scanResults = _modScanner.ScanAllMods(force);

                var filteredResults = scanResults
                    .Where(kv => kv.Value.Count > 0 && kv.Value.Any(f => f.Location != "Assembly scanning"))
                    .ToDictionary(kv => kv.Key, kv => kv.Value);

                if (filteredResults.Count > 0)
                {
                    LoggerInstance.Warning($"Found {filteredResults.Count} potentially malicious mods!");

                    var disabledMods = _modDisabler.DisableSuspiciousMods(filteredResults, force);
                    var disabledCount = disabledMods.Count;
                    LoggerInstance.Msg($"Disabled {disabledCount} suspicious mods");

                    if (disabledCount <= 0) return filteredResults;
                    GenerateDetailedReports(disabledMods, filteredResults);

                    LoggerInstance.Msg("To whitelist any false positives, add them to the MLVScan → WhitelistedMods setting in MelonPreferences.cfg");
                }
                else
                {
                    LoggerInstance.Msg("No suspicious mods found");
                }

                return filteredResults;
            }
            catch (Exception ex)
            {
                LoggerInstance.Error($"Error scanning mods: {ex.Message}");
                return new Dictionary<string, List<ScanFinding>>();
            }
        }

        private void GenerateDetailedReports(List<string> disabledMods, Dictionary<string, List<ScanFinding>> scanResults)
        {
            LoggerInstance.Warning("======= DETAILED SCAN REPORT =======");
            
            var promptGenerator = _serviceFactory.CreatePromptGeneratorService();
            var promptDirectory = Path.Combine(MelonLoader.Utils.MelonEnvironment.UserDataDirectory, "MLVScan", "Prompts");

            foreach (var modPath in disabledMods)
            {
                var modName = Path.GetFileName(modPath);
                LoggerInstance.Warning($"SUSPICIOUS MOD: {modName}");
                LoggerInstance.Msg("-------------------------------");

                if (scanResults.TryGetValue(modPath, out var findings))
                {
                    var actualFindings = findings
                        .Where(f => f.Location != "Assembly scanning")
                        .ToList();

                    if (actualFindings.Count == 0)
                    {
                        LoggerInstance.Msg("No specific suspicious patterns were identified.");
                        continue;
                    }

                    var groupedFindings = actualFindings
                        .GroupBy(f => f.Description)
                        .ToDictionary(g => g.Key, g => g.ToList());

                    LoggerInstance.Warning($"Total suspicious patterns found: {actualFindings.Count}");

                    var severityCounts = actualFindings
                        .GroupBy(f => f.Severity)
                        .OrderByDescending(g => GetSeverityRank(g.Key))
                        .ToDictionary(g => g.Key, g => g.Count());

                    LoggerInstance.Warning("Severity breakdown:");
                    foreach (var severityCount in severityCounts)
                    {
                        var severityLabel = FormatSeverityLabel(severityCount.Key);
                        LoggerInstance.Msg($"  {severityLabel}: {severityCount.Value} issue(s)");
                    }

                    LoggerInstance.Msg("-------------------------------");
                    LoggerInstance.Warning("Suspicious patterns found:");

                    foreach (var (category, categoryFindings) in groupedFindings)
                    {
                        var severity = FormatSeverityLabel(categoryFindings[0].Severity);

                        LoggerInstance.Warning($"[{severity}] {category} ({categoryFindings.Count} instances)");

                        var maxDetailsToShow = Math.Min(categoryFindings.Count, 3);
                        for (var i = 0; i < maxDetailsToShow; i++)
                        {
                            var finding = categoryFindings[i];
                            LoggerInstance.Msg($"  * At: {finding.Location}");
                            if (!string.IsNullOrEmpty(finding.CodeSnippet))
                            {
                                LoggerInstance.Msg($"    Code Snippet (IL):");
                                foreach (var line in finding.CodeSnippet.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                                {
                                    LoggerInstance.Msg($"      {line}");
                                }
                            }
                        }

                        if (categoryFindings.Count > maxDetailsToShow)
                        {
                            LoggerInstance.Msg($"  * And {categoryFindings.Count - maxDetailsToShow} more instances...");
                        }

                        LoggerInstance.Msg("");
                    }

                    LoggerInstance.Msg("-------------------------------");
                    DisplaySecurityNotice(modName);

                    try
                    {
                        // Generate report and prompt files
                        var reportDirectory = Path.Combine(MelonLoader.Utils.MelonEnvironment.UserDataDirectory, "MLVScan", "Reports");
                        Directory.CreateDirectory(reportDirectory);

                        var reportPath = Path.Combine(reportDirectory, $"{modName}.report.txt");
                        using (var writer = new StreamWriter(reportPath))
                        {
                            writer.WriteLine($"MLVScan Detailed Report for {modName}");
                            writer.WriteLine($"Scan Date: {DateTime.Now}");
                            writer.WriteLine($"Total Suspicious Patterns: {actualFindings.Count}");
                            writer.WriteLine("==============================================");

                            writer.WriteLine("\nSEVERITY BREAKDOWN:");
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
                                writer.WriteLine("\nLocations & Snippets:");
                                foreach (var finding in group.Value)
                                {
                                    writer.WriteLine($"- {finding.Location}");
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

                            WriteSecurityNoticeToReport(writer);
                        }

                        // Generate LLM analysis prompt
                        var promptSaved = promptGenerator.SavePromptToFile(
                            modPath, 
                            actualFindings, 
                            promptDirectory);
                            
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
                    }
                    catch (Exception ex)
                    {
                        LoggerInstance.Error($"Failed to save detailed report: {ex.Message}");
                    }
                }

                LoggerInstance.Warning("-------------------------------");
            }

            LoggerInstance.Warning("====== END OF SCAN REPORT ======");
        }

        private static int GetSeverityRank(string severity)
        {
            return severity.ToLower() switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0
            };
        }

        private static string FormatSeverityLabel(string severity)
        {
            return severity.ToLower() switch
            {
                "critical" => "CRITICAL",
                "high" => "HIGH",
                "medium" => "MEDIUM",
                "low" => "LOW",
                _ => severity.ToUpper()
            };
        }

        private void DisplaySecurityNotice(string modName)
        {
            LoggerInstance.Warning("IMPORTANT SECURITY NOTICE");
            LoggerInstance.Msg($"MLVScan has detected and disabled {modName} before it was loaded.");
            LoggerInstance.Msg("If this is your first time running the game with this mod, your PC is likely safe.");
            LoggerInstance.Msg("However, if you've previously run the game with this mod, your system MAY be infected.");
            LoggerInstance.Msg("Keep in mind that no detection system is perfect, and this mod may be falsely flagged.");
            LoggerInstance.Warning("Recommended security steps:");
            LoggerInstance.Msg("1. Check with the modding community first - no detection is perfect");
            LoggerInstance.Msg("   Join the modding Discord at: https://discord.gg/rV2QSAnqhX");
            LoggerInstance.Msg("   Ask about this mod in the #MLVScan or #report-mods channels to confirm if it's actually malicious");
            LoggerInstance.Msg("2. Run a full system scan with a trusted antivirus like Malwarebytes");
            LoggerInstance.Msg("   Malwarebytes is recommended as a free and effective antivirus solution");
            LoggerInstance.Msg("3. Use Microsoft Safety Scanner for a secondary scan");
            LoggerInstance.Msg("4. Change important passwords if antivirus shows a threat");
            LoggerInstance.Warning("Resources for malware removal:");
            LoggerInstance.Msg("- Malwarebytes: https://www.malwarebytes.com/cybersecurity/basics/how-to-remove-virus-from-computer");
            LoggerInstance.Msg("- Microsoft Safety Scanner: https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download");
        }

        private static void WriteSecurityNoticeToReport(StreamWriter writer)
        {
            writer.WriteLine("\n\n============== SECURITY NOTICE ==============\n");
            writer.WriteLine("IMPORTANT: READ THIS SECURITY INFORMATION\n");
            writer.WriteLine("MLVScan has detected and disabled this mod before it was loaded.");
            writer.WriteLine("This mod contains code patterns commonly associated with malware.\n");
            writer.WriteLine("YOUR SYSTEM SECURITY STATUS:");
            writer.WriteLine("- If this is your FIRST TIME starting the game with this mod installed:");
            writer.WriteLine("  Your PC is likely SAFE as MLVScan prevented the mod from loading.");
            writer.WriteLine("\n- If you have PREVIOUSLY PLAYED the game with this mod loaded:");
            writer.WriteLine("  Your system MAY BE INFECTED with malware. Take action immediately.\n");
            writer.WriteLine("RECOMMENDED SECURITY STEPS:");
            writer.WriteLine("1. Check with the modding community first - no detection system is perfect");
            writer.WriteLine("   Join the modding Discord at: https://discord.gg/rV2QSAnqhX");
            writer.WriteLine("   Ask about this mod in the #MLVScan or #report-mods channels to confirm if it's actually malicious");
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
            writer.WriteLine("\n=============================================");
        }
    }
}