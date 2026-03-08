using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MLVScan.Models;

namespace MLVScan.Services
{
    /// <summary>
    /// Shared formatting helpers for threat verdict console output and report sections.
    /// </summary>
    public static class ThreatVerdictTextFormatter
    {
        public static string GetVerdictLabel(ThreatVerdictInfo threatVerdict)
        {
            return (threatVerdict?.Title ?? string.Empty).Trim();
        }

        public static string GetPrimaryFamilyLabel(ThreatVerdictInfo threatVerdict)
        {
            return threatVerdict?.PrimaryFamily?.DisplayName ?? string.Empty;
        }

        public static string GetConfidenceLabel(ThreatVerdictInfo threatVerdict)
        {
            if (threatVerdict == null || threatVerdict.Confidence <= 0d)
            {
                return string.Empty;
            }

            return $"{threatVerdict.Confidence * 100:F0}%";
        }

        public static List<string> GetTopFindingSummaries(List<ScanFinding> findings, int maxItems = 3)
        {
            if (findings == null || findings.Count == 0)
            {
                return new List<string>();
            }

            return findings
                .GroupBy(f => f.Description)
                .Select(group => new
                {
                    Description = group.Key,
                    Severity = group.Max(f => f.Severity),
                    Count = group.Count()
                })
                .OrderByDescending(item => (int)item.Severity)
                .ThenByDescending(item => item.Count)
                .ThenBy(item => item.Description, StringComparer.Ordinal)
                .Take(maxItems)
                .Select(item => $"[{item.Severity}] {item.Description} ({item.Count} instance{(item.Count == 1 ? string.Empty : "s")})")
                .ToList();
        }

        public static void WriteThreatVerdictSection(TextWriter writer, ThreatVerdictInfo threatVerdict)
        {
            if (writer == null || threatVerdict == null || threatVerdict.Kind == ThreatVerdictKind.None)
            {
                return;
            }

            writer.WriteLine("Threat Verdict:");
            writer.WriteLine($"- Verdict: {threatVerdict.Title}");
            writer.WriteLine($"- Summary: {threatVerdict.Summary}");

            var familyName = GetPrimaryFamilyLabel(threatVerdict);
            if (!string.IsNullOrWhiteSpace(familyName))
            {
                writer.WriteLine($"- Family: {familyName}");
            }

            var confidenceLabel = GetConfidenceLabel(threatVerdict);
            if (!string.IsNullOrWhiteSpace(confidenceLabel))
            {
                writer.WriteLine($"- Confidence: {confidenceLabel}");
            }

            if (threatVerdict.PrimaryFamily != null)
            {
                if (!string.IsNullOrWhiteSpace(threatVerdict.PrimaryFamily.MatchKind))
                {
                    writer.WriteLine($"- Match Type: {threatVerdict.PrimaryFamily.MatchKind}");
                }

                if (!string.IsNullOrWhiteSpace(threatVerdict.PrimaryFamily.TechnicalName))
                {
                    writer.WriteLine($"- Technical Match: {threatVerdict.PrimaryFamily.TechnicalName}");
                }

                if (!string.IsNullOrWhiteSpace(threatVerdict.PrimaryFamily.ReferenceUrl))
                {
                    writer.WriteLine($"- Family Reference: {threatVerdict.PrimaryFamily.ReferenceUrl}");
                }

                if (threatVerdict.PrimaryFamily.MatchedRules.Count > 0)
                {
                    writer.WriteLine($"- Matched Rules: {string.Join(", ", threatVerdict.PrimaryFamily.MatchedRules)}");
                }

                if (threatVerdict.PrimaryFamily.Evidence.Count > 0)
                {
                    writer.WriteLine("- Evidence:");
                    foreach (var evidence in threatVerdict.PrimaryFamily.Evidence)
                    {
                        writer.WriteLine($"  - {evidence}");
                    }
                }
            }

            writer.WriteLine();
        }
    }
}
