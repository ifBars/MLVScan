using System;
using System.Collections.Generic;
using System.Linq;
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;

namespace MLVScan.Services
{
    /// <summary>
    /// Builds user-facing threat verdicts from Core malware family matches.
    /// </summary>
    public class ThreatVerdictBuilder
    {
        private readonly ThreatFamilyClassifier _classifier = new ThreatFamilyClassifier();
        private readonly ThreatDispositionClassifier _dispositionClassifier = new ThreatDispositionClassifier();

        public ScannedPluginResult Build(string filePath, string fileHash, List<ScanFinding> findings)
        {
            if (findings == null)
            {
                findings = new List<ScanFinding>();
            }

            return new ScannedPluginResult
            {
                FilePath = filePath ?? string.Empty,
                FileHash = fileHash ?? string.Empty,
                Findings = findings,
                ThreatVerdict = BuildVerdict(findings, fileHash)
            };
        }

        private ThreatVerdictInfo BuildVerdict(List<ScanFinding> findings, string fileHash)
        {
            var matches = _classifier.Classify(findings, fileHash).ToList();
            var disposition = _dispositionClassifier.Classify(findings, matches);
            var families = matches.Select(MapFamily).ToList();
            var primaryFamily = families
                .OrderByDescending(f => f.ExactHashMatch)
                .ThenByDescending(f => f.Confidence)
                .ThenBy(f => f.DisplayName, StringComparer.Ordinal)
                .FirstOrDefault();

            if (disposition.Classification == ThreatDispositionClassification.KnownThreat &&
                primaryFamily?.ExactHashMatch == true)
            {
                return new ThreatVerdictInfo
                {
                    Kind = ThreatVerdictKind.KnownMaliciousSample,
                    Title = "Known malicious sample match",
                    Summary = "This mod is likely malware because it exactly matches a previously confirmed malicious sample and was blocked before execution.",
                    Confidence = 1.0d,
                    ShouldBypassThreshold = false,
                    PrimaryFamily = primaryFamily,
                    Families = families
                };
            }

            if (disposition.Classification == ThreatDispositionClassification.KnownThreat && primaryFamily != null)
            {
                return new ThreatVerdictInfo
                {
                    Kind = ThreatVerdictKind.KnownMalwareFamily,
                    Title = "Known malware family match",
                    Summary = $"This mod is likely malware because it matches the previously analyzed malware family \"{primaryFamily.DisplayName}\" and was blocked before execution.",
                    Confidence = primaryFamily.Confidence,
                    ShouldBypassThreshold = false,
                    PrimaryFamily = primaryFamily,
                    Families = families
                };
            }

            if (disposition.Classification == ThreatDispositionClassification.Suspicious)
            {
                return new ThreatVerdictInfo
                {
                    Kind = ThreatVerdictKind.Suspicious,
                    Title = "Suspicious mod",
                    Summary = "This mod triggered correlated suspicious behavior and was blocked as a precaution. It may still be a false positive and should be reviewed before assuming infection.",
                    Confidence = 0d,
                    ShouldBypassThreshold = false,
                    PrimaryFamily = primaryFamily,
                    Families = families
                };
            }

            return new ThreatVerdictInfo
            {
                Kind = ThreatVerdictKind.None,
                Title = "No threat verdict",
                Summary = "No suspicious behavior patterns were retained for this mod.",
                Confidence = 0d,
                ShouldBypassThreshold = false,
                PrimaryFamily = primaryFamily,
                Families = families
            };
        }

        private static ThreatFamilyReference MapFamily(ThreatFamilyMatch match)
        {
            var presentation = ThreatFamilyPresentationCatalog.Get(match.FamilyId);

            return new ThreatFamilyReference
            {
                FamilyId = match.FamilyId,
                DisplayName = presentation.DisplayName,
                Summary = string.IsNullOrWhiteSpace(match.Summary) ? presentation.Summary : match.Summary,
                MatchKind = match.MatchKind.ToString(),
                TechnicalName = match.DisplayName,
                ReferenceUrl = presentation.ReferenceUrl,
                Confidence = match.Confidence,
                ExactHashMatch = match.ExactHashMatch,
                MatchedRules = match.MatchedRules.ToList(),
                Evidence = match.Evidence
                    .Select(evidence => string.IsNullOrWhiteSpace(evidence.Kind)
                        ? evidence.Value
                        : $"{evidence.Kind}: {evidence.Value}")
                    .ToList()
            };
        }

        private sealed class ThreatFamilyPresentation
        {
            public string DisplayName { get; set; }
            public string Summary { get; set; }
            public string ReferenceUrl { get; set; }
        }

        private static class ThreatFamilyPresentationCatalog
        {
            private static readonly IReadOnlyDictionary<string, ThreatFamilyPresentation> Families =
                new Dictionary<string, ThreatFamilyPresentation>(StringComparer.Ordinal)
                {
                    ["family-resource-shell32-tempcmd-v2"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Embedded resource temp CMD dropper",
                        Summary = "Writes an embedded payload into a temporary .cmd file and runs it through ShellExecuteEx or Process.Start.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/resource-shell32-tempcmd-v2"
                    },
                    ["family-powershell-iwr-dlbat-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "PowerShell IWR temp batch downloader",
                        Summary = "Uses hidden PowerShell to download a TEMP batch file, run it, then clean it up.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/powershell-iwr-dlbat-v1"
                    },
                    ["family-webdownload-stage-exec-v2"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Web download staged payload executor",
                        Summary = "Downloads a payload into TEMP and immediately executes it via a hidden process chain, regardless of whether the stager uses WebClient or HttpClient.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/webdownload-stage-exec-v2"
                    },
                    ["family-webdownload-stage-exec-v3"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Web download staged payload executor",
                        Summary = "Downloads a payload to TEMP through WebClient, HttpClient, or a similar network API and then executes it via hidden or shell-assisted process launch.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/webdownload-stage-exec-v3"
                    },
                    ["family-embedded-resource-script-stager-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Embedded resource script stager",
                        Summary = "Stores a script payload in a referenced embedded resource, stages it at runtime, and uses hidden shell or PowerShell execution to retrieve or run a payload.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/embedded-resource-script-stager-v1"
                    },
                    ["family-remote-script-pipe-shell-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Remote script piped to shell",
                        Summary = "Launches a command shell that retrieves a remote script and pipes it directly into another shell interpreter.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/remote-script-pipe-shell-v1"
                    },
                    ["family-encoded-powershell-tempcmd-stager-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Encoded PowerShell temp command stager",
                        Summary = "Numeric-encoded strings reconstruct a hidden cmd.exe or PowerShell launcher that downloads a command script into TEMP and starts it hidden.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/encoded-powershell-tempcmd-stager-v1"
                    },
                    ["family-hex-remote-config-tempcmd-stager-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Hex remote config temp CMD stager",
                        Summary = "Hex and byte-array reconstructed strings hide remote command configuration, reflected WebClient retrieval, temporary command-file staging, and hidden cmd.exe execution.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/hex-remote-config-tempcmd-stager-v1"
                    },
                    ["family-dynamic-assembly-reflection-loader-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Dynamic assembly reflection loader",
                        Summary = "Opaque assembly bytes are loaded at runtime and invoked through reflection, separating a visible mod wrapper from the executable payload.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/dynamic-assembly-reflection-loader-v1"
                    },
                    ["family-obfuscated-metadata-loader-v1"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Obfuscated metadata-backed loader",
                        Summary = "Decodes hidden launcher content from numeric strings and assembly metadata at runtime.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/obfuscated-metadata-loader-v1"
                    },
                    ["family-obfuscated-metadata-loader-v2"] = new ThreatFamilyPresentation
                    {
                        DisplayName = "Obfuscated metadata-backed loader",
                        Summary = "Decodes hidden launcher content from numeric strings, metadata, or manifest resources and uses reflection to reach the payload.",
                        ReferenceUrl = "https://mlvscan.com/advisories/families/obfuscated-metadata-loader-v2"
                    }
                };

            public static ThreatFamilyPresentation Get(string familyId)
            {
                if (!string.IsNullOrWhiteSpace(familyId) && Families.TryGetValue(familyId, out var presentation))
                {
                    return presentation;
                }

                return new ThreatFamilyPresentation
                {
                    DisplayName = "Known malware family",
                    Summary = "This mod matches a previously analyzed malware family.",
                    ReferenceUrl = string.Empty
                };
            }
        }
    }
}
