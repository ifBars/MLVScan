using System.Collections.Generic;

namespace MLVScan.Models
{
    /// <summary>
    /// MLVScan-specific metadata for automated report submissions to the API.
    /// Matches the API SubmissionMetadata schema.
    /// </summary>
    public class SubmissionMetadata
    {
        /// <summary>Mod loader: MelonLoader, BepInEx5, BepInEx6Mono, BepInEx6IL2CPP</summary>
        public string LoaderType { get; set; }

        /// <summary>Loader version</summary>
        public string LoaderVersion { get; set; }

        /// <summary>MLVScan plugin version</summary>
        public string PluginVersion { get; set; }

        /// <summary>Game version if available</summary>
        public string GameVersion { get; set; }

        /// <summary>Reported mod filename or display name (redacted path - basename only)</summary>
        public string ModName { get; set; }

        /// <summary>Optional provenance hint (e.g. Nexus URL, Thunderstore)</summary>
        public string SourceHint { get; set; }

        /// <summary>Finding summary for triage</summary>
        public List<FindingSummaryItem> FindingSummary { get; set; }

        /// <summary>Consent version identifier</summary>
        public string ConsentVersion { get; set; }

        /// <summary>When user gave consent (ISO 8601)</summary>
        public string ConsentTimestamp { get; set; }
    }

    /// <summary>
    /// Single item in the finding summary for triage.
    /// </summary>
    public class FindingSummaryItem
    {
        public string RuleId { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public string Location { get; set; }
    }
}
