using System;
using MLVScan.Models;

namespace MLVScan.Services
{
    /// <summary>Versioned combined choice with independently enforced analytics and file permissions.</summary>
    public static class SharingConsentPolicy
    {
        public const int CurrentVersion = 3;

        public static bool NeedsDecision(MLVScanConfig config) =>
            config != null && config.SharingConsentVersion < CurrentVersion;

        public static bool CanSendAnalytics(MLVScanConfig config) =>
            config != null && !NeedsDecision(config) && config.EnableAnonymousTelemetry;

        /// <summary>Review eligibility is separate from consent: clean complete files are never automatic samples.</summary>
        public static bool IsReviewCandidate(ThreatVerdictInfo verdict, ScanStatusInfo status) =>
            (verdict != null && verdict.Kind != ThreatVerdictKind.None) || status?.Kind == ScanStatusKind.RequiresReview;

        public static bool CanUploadFiles(MLVScanConfig config) =>
            config != null && !NeedsDecision(config) && config.EnableReportUpload;

        /// <summary>Preserves a previous upload choice as the initial checkbox value, without granting analytics.</summary>
        public static bool InitialFileChoice(MLVScanConfig config) => config?.EnableReportUpload == true;

        public static void ApplyDecision(MLVScanConfig config, bool allowSharing, bool shareFiles, DateTimeOffset decidedAt)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            config.EnableAnonymousTelemetry = allowSharing;
            config.EnableReportUpload = allowSharing && shareFiles;
            config.SharingConsentVersion = CurrentVersion;
            config.SharingConsentTimestamp = decidedAt.ToUniversalTime().ToString("o");
            // Retire the old upload-only prompt, including any persisted pending state.
            config.ReportUploadConsentAsked = true;
            config.ReportUploadConsentPending = false;
            config.PendingReportUploadPath = string.Empty;
            config.PendingReportUploadVerdictKind = string.Empty;
            config.PendingReportUploadScanStatusKind = string.Empty;
        }
    }
}
