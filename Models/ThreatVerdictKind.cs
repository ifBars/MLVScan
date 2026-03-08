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
}
