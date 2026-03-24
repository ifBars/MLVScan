namespace MLVScan.Models
{
    /// <summary>
    /// User-facing threat verdict for a scanned mod or plugin.
    /// </summary>
    public enum ThreatVerdictKind
    {
        None,
        Suspicious,
        KnownMalwareFamily,
        KnownMaliciousSample
    }

    /// <summary>
    /// User-facing scan completion status, independent of the threat verdict.
    /// </summary>
    public enum ScanStatusKind
    {
        Complete,
        RequiresReview
    }
}
