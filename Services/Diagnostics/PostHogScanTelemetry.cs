using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MLVScan.Models;
using MLVScan.Models.Telemetry;
using MLVScan.Models.Dto;

namespace MLVScan.Services.Diagnostics
{
    /// <summary>
    /// Opt-in, best-effort aggregate analytics. Separate from local profiling and sample uploads.
    /// One pending request at most; no retries, disk queue, persistent identity, or scan dependency.
    /// </summary>
    public sealed class PostHogScanTelemetry
    {
        private int _pending;

        /// <summary>Finding IDs the loader creates itself, allowlisted for diagnostics.</summary>
        public static readonly IReadOnlyList<string> HostFindingIds = new[] { PluginScannerBase.OversizedAssemblyRuleId };

        /// <summary>Creates a diagnostics accumulator that recognises Core and loader finding IDs.</summary>
        public static ScanDiagnosticSummary CreateDiagnosticSummary() => new ScanDiagnosticSummary(HostFindingIds);

        /// <summary>Maps loader verdicts to the shared vocabulary without examining findings or input data.</summary>
        public static ScanTelemetryOutcome GetOutcome(ScannedPluginResult result)
        {
            return result?.ThreatVerdict?.Kind switch
            {
                ThreatVerdictKind.KnownMaliciousSample => ScanTelemetryOutcome.KnownThreat,
                ThreatVerdictKind.KnownMalwareFamily => ScanTelemetryOutcome.KnownThreat,
                ThreatVerdictKind.Suspicious => ScanTelemetryOutcome.Suspicious,
                ThreatVerdictKind.None when result.ScanStatus?.Kind == ScanStatusKind.Complete
                    => ScanTelemetryOutcome.Clean,
                ThreatVerdictKind.None when result.ScanStatus?.Kind == ScanStatusKind.RequiresReview
                    => ScanTelemetryOutcome.ManualReviewRequired,
                ThreatVerdictKind.None when result.ScanStatus?.Kind == ScanStatusKind.NotApplicable
                    => Enum.TryParse<ScanTelemetryOutcome>("NotApplicable", out var outsideScope) ? outsideScope : ScanTelemetryOutcome.Unknown,
                _ => ScanTelemetryOutcome.Unknown
            };
        }

        /// <summary>
        /// Enqueues only numeric aggregate outcomes after separate consent. The config provider is
        /// checked again at dispatch so revocation before dispatch drops the pending event.
        /// </summary>
        public void CaptureNonBlocking(Func<MLVScanConfig> getConfig, IEnumerable<ScanTelemetryOutcome> outcomes, ScanDiagnosticSummary diagnostics = null)
        {
            var acquired = false;
            try
            {
                if (!IsConfigured(getConfig()) || Interlocked.CompareExchange(ref _pending, 1, 0) != 0)
                    return;
                acquired = true;
                var snapshot = outcomes.ToArray();
                var diagnosticSnapshot = diagnostics?.Copy();
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
                        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                        await SendAsync(client, getConfig(), snapshot, diagnostics: diagnosticSnapshot).ConfigureAwait(false);
                    }
                    catch (Exception) { /* Analytics must never affect protection or expose payloads in logs. */ }
                    finally { Interlocked.Exchange(ref _pending, 0); }
                });
            }
            catch (Exception) { if (acquired) Interlocked.Exchange(ref _pending, 0); }
        }

        /// <summary>
        /// Sends one bounded event using an injected client. Returns false for disabled, invalid,
        /// rejected, cancelled, or failed delivery; never retries. The caller owns the client.
        /// </summary>
        public static async Task<bool> SendAsync(HttpClient client, MLVScanConfig config,
            IEnumerable<ScanTelemetryOutcome> outcomes, CancellationToken cancellationToken = default, ScanDiagnosticSummary diagnostics = null)
        {
            try
            {
                if (!IsConfigured(config)) return false;
                var properties = ScanTelemetrySummary.Create(outcomes)
                    .ToDictionary(pair => pair.Key, pair => (object)pair.Value, StringComparer.Ordinal);
                properties["telemetry_schema_version"] = ScanDiagnosticSummary.SchemaVersion;
                if (diagnostics != null) foreach (var item in diagnostics.Snapshot()) properties[item.Key] = item.Value;
                properties["core_version"] = MLVScanVersions.CoreVersion;
                properties["plugin_version"] = PlatformConstants.PlatformVersion;
                properties["loader"] = PlatformConstants.PlatformName;
                properties["$process_person_profile"] = false;
                properties["$geoip_disable"] = true;
                properties["$ip"] = "0.0.0.0";
                properties["consumer"] = "loader";
                properties["environment"] = config.TelemetryEnvironment;
                properties["review_candidate_count"] = new[] { "suspicious_count", "known_threat_count", "manual_review_required_count" }
                    .Sum(key => properties.TryGetValue(key, out var count) ? (int)count : 0);
                properties["file_sharing_enabled"] = SharingConsentPolicy.CanUploadFiles(config);
                return await SendEnvelopeAsync(client, config, "mlvscan_scan_run_completed",
                    "scan-run:" + Guid.NewGuid().ToString("N"), properties, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception) { return false; }
        }

        /// <summary>Correlates a confirmed private receipt only while BOTH sharing permissions remain enabled.</summary>
        public static async Task<bool> SendReviewReceiptAsync(HttpClient client, MLVScanConfig config,
            string reviewId, string verdict, string scanStatus, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!IsConfigured(config) || !SharingConsentPolicy.CanUploadFiles(config) || !IsValidReviewId(reviewId)) return false;
                var properties = new Dictionary<string, object>
                {
                    ["telemetry_schema_version"] = 1,
                    ["submission_reference"] = Guid.Parse(reviewId).ToString("D"),
                    ["original_verdict"] = Enum.TryParse<ThreatVerdictKind>(verdict, out var kind) && Enum.IsDefined(typeof(ThreatVerdictKind), kind) ? kind.ToString() : "Unknown",
                    ["scan_status"] = Enum.TryParse<ScanStatusKind>(scanStatus, out var status) && Enum.IsDefined(typeof(ScanStatusKind), status) ? status.ToString() : "Unknown",
                    ["core_version"] = MLVScanVersions.CoreVersion,
                    ["plugin_version"] = PlatformConstants.PlatformVersion,
                    ["loader"] = PlatformConstants.PlatformName,
                    ["consumer"] = "loader", ["environment"] = config.TelemetryEnvironment,
                    ["$process_person_profile"] = false, ["$geoip_disable"] = true, ["$ip"] = "0.0.0.0"
                };
                return await SendEnvelopeAsync(client, config, "mlvscan_private_review_uploaded",
                    "review-event:" + Guid.Parse(reviewId).ToString("D"), properties, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception) { return false; }
        }

        public static bool IsValidReviewId(string value) => value != null && value.Length == 36 &&
            Guid.TryParseExact(value, "D", out _) && value[14] == '4' && "89abAB".IndexOf(value[19]) >= 0;

        /// <summary>One terminal outcome per upload operation; no sample identity or response text.</summary>
        public static async Task<bool> SendUploadOutcomeAsync(HttpClient client, MLVScanConfig config,
            string outcome, string reason, int attempts)
        {
            if (!IsConfigured(config) || !new[] { "accepted", "failed", "skipped" }.Contains(outcome) ||
                !new[] { "none", "invalid_receipt", "size_limit", "empty_file", "duplicate", "in_flight", "not_configured",
                    "consent_revoked", "read_error", "not_found", "rejected", "rate_limited", "server_error", "network_error", "timeout", "preparation_error" }.Contains(reason))
                return false;
            var properties = new Dictionary<string, object> {
                ["telemetry_schema_version"] = 1, ["consumer"] = "loader", ["environment"] = config.TelemetryEnvironment,
                ["core_version"] = MLVScanVersions.CoreVersion, ["plugin_version"] = PlatformConstants.PlatformVersion,
                ["loader"] = PlatformConstants.PlatformName, ["upload_outcome"] = outcome, ["upload_reason"] = reason,
                ["upload_operation_count"] = 1, ["upload_attempt_count"] = Math.Max(0, Math.Min(3, attempts)),
                ["$process_person_profile"] = false, ["$geoip_disable"] = true, ["$ip"] = "0.0.0.0"
            };
            try { return await SendEnvelopeAsync(client, config, "mlvscan_private_review_upload_outcome",
                "upload-outcome:" + Guid.NewGuid().ToString("N"), properties, default).ConfigureAwait(false); }
            catch (Exception) { return false; }
        }

        private static async Task<bool> SendEnvelopeAsync(HttpClient client, MLVScanConfig config,
            string eventName, string distinctId, Dictionary<string, object> properties, CancellationToken cancellationToken)
        {
            var payload = new CaptureEnvelope
            {
                ProjectToken = config.PostHogProjectToken,
                Event = eventName,
                DistinctId = distinctId,
                Properties = properties
            };
            var serializer = new DataContractJsonSerializer(typeof(CaptureEnvelope),
                new DataContractJsonSerializerSettings
                {
                    UseSimpleDictionaryFormat = true
                });
            using var stream = new MemoryStream();
            serializer.WriteObject(stream, payload);
            using var content = new StringContent(Encoding.UTF8.GetString(stream.ToArray()), Encoding.UTF8, "application/json");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            // Only official ingestion hosts are permitted. Configuration cannot redirect sample analytics.
            var endpoint = config.PostHogRegion == "eu"
                ? "https://eu.i.posthog.com/i/v0/e/" : "https://us.i.posthog.com/i/v0/e/";
            using var response = await client.PostAsync(endpoint, content, timeout.Token).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }

        // Visibility is explicitly unknown when the loader cache did not retain the DTO's correlation mapping.
        // Incompleteness reasons carry only the finding ID that limited analysis; the DTO is never sent.
        public static ScanResultDto ToDiagnosticResult(ScannedPluginResult result) => new ScanResultDto
        {
            AnalysisCompleteness = new AnalysisCompletenessDto
            {
                Status = result.ScanStatus?.Kind == ScanStatusKind.NotApplicable ? "NotApplicable" :
                    result.ScanStatus?.Kind == ScanStatusKind.RequiresReview ? "Incomplete" : "Complete",
                IsComplete = result.ScanStatus?.Kind == ScanStatusKind.Complete,
                Reasons = result.ScanStatus?.Kind == ScanStatusKind.RequiresReview
                    ? result.Findings
                        .Where(f => AnalysisCompletenessEvaluator.IsIncompleteFinding(f) ||
                                    f.RuleId == PluginScannerBase.OversizedAssemblyRuleId)
                        .Select(f => new AnalysisCompletenessReasonDto { ReasonId = "scanner-incomplete", RuleId = f.RuleId, Summary = f.Description })
                        .ToList()
                    : new List<AnalysisCompletenessReasonDto>()
            },
            Findings = result.Findings.Select((f, i) => new FindingDto { RuleId = f.RuleId, Severity = f.Severity.ToString(),
                Visibility = result.ThreatVerdict.RelatedFindingIndices == null ? null : result.ThreatVerdict.RelatedFindingIndices.Contains(i) ? "Default" : "Advanced" }).ToList(),
            ThreatFamilies = result.ThreatVerdict.Families.Select(f => new ThreatFamilyDto { FamilyId = f.FamilyId, ExactHashMatch = f.ExactHashMatch }).ToList(),
            DataFlows = result.Findings.Where(f => f.DataFlowChain != null).Select(f => f.DataFlowChain).Distinct()
                .Select(f => new DataFlowChainDto { Pattern = f.Pattern.ToString() }).ToList()
        };

        [DataContract]
        private sealed class CaptureEnvelope
        {
            [DataMember(Name = "api_key")] public string ProjectToken { get; set; }
            [DataMember(Name = "event")] public string Event { get; set; }
            [DataMember(Name = "distinct_id")] public string DistinctId { get; set; }
            [DataMember(Name = "properties")] public Dictionary<string, object> Properties { get; set; }
        }

        private static bool IsConfigured(MLVScanConfig config) =>
            SharingConsentPolicy.CanSendAnalytics(config) &&
            !string.IsNullOrWhiteSpace(config.PostHogProjectToken) &&
            config.PostHogProjectToken.StartsWith("phc_", StringComparison.Ordinal) &&
            config.PostHogProjectToken.Length <= 200 &&
            (config.PostHogRegion == "us" || config.PostHogRegion == "eu") &&
            (config.TelemetryEnvironment == "development" || config.TelemetryEnvironment == "staging" ||
             config.TelemetryEnvironment == "production");
    }
}
