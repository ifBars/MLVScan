using System;
using System.Collections.Generic;
using System.Linq;
using MLVScan.Models;

namespace MLVScan.Services.Caching
{
    internal sealed class ScanCacheEntry
    {
        public string CanonicalPath { get; set; } = string.Empty;

        public string RealPath { get; set; } = string.Empty;

        public FileIdentitySnapshot FileIdentity { get; set; } = new FileIdentitySnapshot();

        public string Sha256 { get; set; } = string.Empty;

        public string ScannerFingerprint { get; set; } = string.Empty;

        public string ResolverFingerprint { get; set; } = string.Empty;

        public DateTime CreatedUtc { get; set; }

        public DateTime VerifiedUtc { get; set; }

        public ScannedPluginResult Result { get; set; } = new ScannedPluginResult();

        // ScanCacheEntry / ScanCacheEntryPayload conversions intentionally keep shallow FileIdentity
        // and Result references for performance. Call CloneResultForPath when mutation-safe Result
        // data is required instead of relying on ToEntry or FromEntry to deep-copy it.
        public bool CanReuseStrictly(FileProbe probe, string scannerFingerprint, string resolverFingerprint, bool canTrustCleanEntries)
        {
            if (probe == null)
            {
                return false;
            }

            if (!string.Equals(ScannerFingerprint, scannerFingerprint, StringComparison.Ordinal) ||
                !string.Equals(ResolverFingerprint, resolverFingerprint, StringComparison.Ordinal))
            {
                return false;
            }

            if (Result?.ThreatVerdict?.Kind == ThreatVerdictKind.None &&
                !canTrustCleanEntries)
            {
                return false;
            }

            return probe.CanReuseByStrongIdentity &&
                   FileIdentity.MatchesStrongIdentity(probe.Identity);
        }

        public ScannedPluginResult CloneResultForPath(string filePath)
        {
            var findings = new List<ScanFinding>(Result?.Findings?.Count ?? 0);
            if (Result?.Findings != null)
            {
                foreach (var finding in Result.Findings)
                {
                    var clonedFinding = new ScanFinding(
                        finding.Location,
                        finding.Description,
                        finding.Severity,
                        finding.CodeSnippet)
                    {
                        RuleId = finding.RuleId,
                        DeveloperGuidance = finding.DeveloperGuidance,
                        CallChain = finding.CallChain,
                        DataFlowChain = finding.DataFlowChain,
                        BypassCompanionCheck = finding.BypassCompanionCheck,
                        RiskScore = finding.RiskScore
                    };

                    findings.Add(clonedFinding);
                }
            }

            ThreatVerdictInfo verdict = null;
            if (Result?.ThreatVerdict != null)
            {
                verdict = new ThreatVerdictInfo
                {
                    Kind = Result.ThreatVerdict.Kind,
                    Title = Result.ThreatVerdict.Title,
                    Summary = Result.ThreatVerdict.Summary,
                    Confidence = Result.ThreatVerdict.Confidence,
                    ShouldBypassThreshold = Result.ThreatVerdict.ShouldBypassThreshold,
                    PrimaryFamily = CloneFamily(Result.ThreatVerdict.PrimaryFamily),
                    Families = Result.ThreatVerdict.Families?
                        .Select(CloneFamily)
                        .ToList() ?? new List<ThreatFamilyReference>()
                };
            }

            return new ScannedPluginResult
            {
                FilePath = filePath,
                FileHash = Result?.FileHash ?? Sha256,
                Findings = findings,
                ThreatVerdict = verdict ?? new ThreatVerdictInfo()
            };
        }

        private static ThreatFamilyReference CloneFamily(ThreatFamilyReference family)
        {
            if (family == null)
            {
                return null;
            }

            return new ThreatFamilyReference
            {
                FamilyId = family.FamilyId,
                DisplayName = family.DisplayName,
                Summary = family.Summary,
                MatchKind = family.MatchKind,
                TechnicalName = family.TechnicalName,
                ReferenceUrl = family.ReferenceUrl,
                Confidence = family.Confidence,
                ExactHashMatch = family.ExactHashMatch,
                MatchedRules = family.MatchedRules?.ToList() ?? new List<string>(),
                Evidence = family.Evidence?.ToList() ?? new List<string>()
            };
        }
    }

    internal sealed class ScanCacheEnvelope
    {
        public int SchemaVersion { get; set; } = 1;

        public string Signature { get; set; } = string.Empty;

        public ScanCacheEntryPayload Payload { get; set; } = new ScanCacheEntryPayload();
    }

    internal sealed class ScanCacheEntryPayload
    {
        public string CanonicalPath { get; set; } = string.Empty;

        public string RealPath { get; set; } = string.Empty;

        public FileIdentitySnapshot FileIdentity { get; set; } = new FileIdentitySnapshot();

        public string Sha256 { get; set; } = string.Empty;

        public string ScannerFingerprint { get; set; } = string.Empty;

        public string ResolverFingerprint { get; set; } = string.Empty;

        public DateTime CreatedUtc { get; set; }

        public DateTime VerifiedUtc { get; set; }

        public ScannedPluginResult Result { get; set; } = new ScannedPluginResult();

        // ToEntry and FromEntry intentionally keep ScanCacheEntry / ScanCacheEntryPayload shallow for
        // FileIdentity and Result. Use CloneResultForPath when callers need a deep-cloned Result.
        public ScanCacheEntry ToEntry()
        {
            return new ScanCacheEntry
            {
                CanonicalPath = CanonicalPath,
                RealPath = RealPath,
                FileIdentity = FileIdentity,
                Sha256 = Sha256,
                ScannerFingerprint = ScannerFingerprint,
                ResolverFingerprint = ResolverFingerprint,
                CreatedUtc = CreatedUtc,
                VerifiedUtc = VerifiedUtc,
                Result = Result
            };
        }

        public static ScanCacheEntryPayload FromEntry(ScanCacheEntry entry)
        {
            return new ScanCacheEntryPayload
            {
                CanonicalPath = entry.CanonicalPath,
                RealPath = entry.RealPath,
                FileIdentity = entry.FileIdentity,
                Sha256 = entry.Sha256,
                ScannerFingerprint = entry.ScannerFingerprint,
                ResolverFingerprint = entry.ResolverFingerprint,
                CreatedUtc = entry.CreatedUtc,
                VerifiedUtc = entry.VerifiedUtc,
                Result = entry.Result
            };
        }
    }
}
