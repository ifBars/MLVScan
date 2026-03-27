using System.Collections.Generic;

namespace MLVScan.Models
{
    /// <summary>
    /// User-friendly family reference derived from Core threat intelligence.
    /// </summary>
    public class ThreatFamilyReference
    {
        public string FamilyId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string MatchKind { get; set; } = string.Empty;
        public string TechnicalName { get; set; } = string.Empty;
        public string ReferenceUrl { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public bool ExactHashMatch { get; set; }
        public List<string> MatchedRules { get; set; } = new List<string>();
        public List<string> Evidence { get; set; } = new List<string>();
    }

    /// <summary>
    /// User-facing threat verdict for a scan result.
    /// </summary>
    public class ThreatVerdictInfo
    {
        public ThreatVerdictKind Kind { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public bool ShouldBypassThreshold { get; set; }
        public ThreatFamilyReference PrimaryFamily { get; set; }
        public List<ThreatFamilyReference> Families { get; set; } = new List<ThreatFamilyReference>();
    }

    /// <summary>
    /// User-facing scan completion status for a scan result.
    /// </summary>
    public class ScanStatusInfo
    {
        public ScanStatusKind Kind { get; set; } = ScanStatusKind.Complete;
        public string Title { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
    }

    /// <summary>
    /// Full scan result for a single mod or plugin file.
    /// </summary>
    public class ScannedPluginResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileHash { get; set; } = string.Empty;
        public List<ScanFinding> Findings { get; set; } = new List<ScanFinding>();
        public ThreatVerdictInfo ThreatVerdict { get; set; } = new ThreatVerdictInfo();
        public ScanStatusInfo ScanStatus { get; set; } = new ScanStatusInfo();
    }

    internal static class ScanResultFacts
    {
        public static bool HasThreatVerdict(ScannedPluginResult result)
        {
            return (result?.ThreatVerdict?.Kind ?? ThreatVerdictKind.None) != ThreatVerdictKind.None;
        }

        public static bool RequiresManualReview(ScannedPluginResult result)
        {
            return (result?.ScanStatus?.Kind ?? ScanStatusKind.Complete) != ScanStatusKind.Complete;
        }

        public static bool RequiresAttention(ScannedPluginResult result)
        {
            return HasThreatVerdict(result) || RequiresManualReview(result);
        }

        public static bool IsClean(ScannedPluginResult result)
        {
            return !RequiresAttention(result);
        }
    }
}
