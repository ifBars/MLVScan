using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services.Diagnostics;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace MLVScan.Services
{
    /// <summary>
    /// Non-blocking service to upload scan reports and assemblies to the MLVScan API.
    /// Uses only POST /files/private-review for files up to 64 MiB; larger files remain local.
    /// Never blocks startup; failures are logged and local behavior continues.
    /// </summary>
    public class ReportUploadService
    {
        private const int SmallFileLimitBytes = 64 * 1024 * 1024; // private review limit
        private const int DefaultTimeoutSeconds = 120;
        private const int MaxRetries = 2;
        private static readonly object InFlightUploadsLock = new object();
        private static readonly HashSet<string> InFlightUploads = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private readonly IConfigManager _configManager;
        private readonly Func<HttpClient> _createHttpClient;
        private static readonly object ReceiptLock = new object();
        private readonly Action<string> _logInfo;
        private readonly Action<string> _logWarn;
        private readonly Action<string> _logError;

        public ReportUploadService(IConfigManager configManager, Action<string> logInfo, Action<string> logWarn, Action<string> logError, Func<HttpClient> createHttpClient = null)
        {
            _createHttpClient = createHttpClient ?? CreateDefaultHttpClient;
            _configManager = configManager;
            _logInfo = logInfo ?? (_ => { });
            _logWarn = logWarn ?? (_ => { });
            _logError = logError ?? (_ => { });
        }

        /// <summary>Reads an optional upload within its transport budget, independently of local scanning.</summary>
        public static byte[] ReadPrivateSampleBytes(string path, Action<string> onSkipped = null)
        {
            var sizeLimitExceeded = false;
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (stream.Length > SmallFileLimitBytes)
                {
                    sizeLimitExceeded = true;
                    try { onSkipped?.Invoke("size_limit"); } catch (Exception) { }
                    throw new IOException("Private review skipped: file exceeds 64 MiB. Local scanning is not size limited.");
                }
                var bytes = new byte[checked((int)stream.Length)];
                var offset = 0;
                while (offset < bytes.Length)
                {
                    var count = stream.Read(bytes, offset, bytes.Length - offset);
                    if (count == 0) throw new EndOfStreamException("Sample changed while preparing private review.");
                    offset += count;
                }
                return bytes;
            }
            catch (Exception error) when (error is IOException || error is UnauthorizedAccessException)
            {
                if (!sizeLimitExceeded)
                    try { onSkipped?.Invoke("read_error"); } catch (Exception) { }
                throw;
            }
        }

        private int _outcomePending;
        public void RecordPreparationFailure(string reason) => RecordOutcome("skipped", reason, 0);

        private void RecordOutcome(string outcome, string reason, int attempts)
        {
            if (!SharingConsentPolicy.CanSendAnalytics(_configManager?.Config) ||
                Interlocked.CompareExchange(ref _outcomePending, 1, 0) != 0) return;
            _ = Task.Run(async () =>
            {
                try
                {
                    using var client = _createHttpClient();
                    await PostHogScanTelemetry.SendUploadOutcomeAsync(client, _configManager?.Config, outcome, reason, attempts).ConfigureAwait(false);
                }
                catch (Exception) { }
                finally { Interlocked.Exchange(ref _outcomePending, 0); }
            });
        }

        /// <summary>
        /// Upload assembly and metadata to the API in a non-blocking manner.
        /// Call this from a fire-and-forget task; do not await if you must not block.
        /// </summary>
        public void UploadReportNonBlocking(byte[] assemblyBytes, string filename, SubmissionMetadata metadata, string apiBaseUrl)
        {
            if (!SharingConsentPolicy.CanUploadFiles(_configManager?.Config)) return;
            if (assemblyBytes == null || assemblyBytes.Length == 0)
            {
                RecordOutcome("skipped", "empty_file", 0);
                _logWarn($"ReportUploadService: No assembly bytes to upload for {filename ?? "<unknown>"}");
                return;
            }

            if (string.IsNullOrWhiteSpace(apiBaseUrl))
            {
                RecordOutcome("skipped", "not_configured", 0);
                _logWarn("ReportUploadService: API base URL not configured");
                return;
            }

            var baseUrl = apiBaseUrl.TrimEnd('/');

            Task.Run(async () =>
            {
                try
                {
                    if (!SharingConsentPolicy.CanUploadFiles(_configManager?.Config)) return;
                    await UploadReportAsync(assemblyBytes, filename, metadata, baseUrl);
                }
                catch (Exception ex)
                {
                    _logError($"ReportUploadService: Upload failed: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Upload assembly and metadata to the API.
        /// </summary>
        public async Task UploadReportAsync(byte[] assemblyBytes, string filename, SubmissionMetadata metadata, string apiBaseUrl)
        {
            if (!SharingConsentPolicy.CanUploadFiles(_configManager?.Config)) return;
            if (assemblyBytes == null || assemblyBytes.Length == 0)
            {
                RecordOutcome("skipped", "empty_file", 0);
                _logWarn($"ReportUploadService: No assembly bytes to upload for {filename ?? "<unknown>"}");
                return;
            }

            if (assemblyBytes.Length > SmallFileLimitBytes)
            {
                RecordOutcome("skipped", "size_limit", 0);
                _logWarn("Private review skipped: file exceeds 64 MiB. It remains local.");
                return;
            }
            var assemblyHash = HashUtility.CalculateBytesHash(assemblyBytes);
            if (HashUtility.IsValidHash(assemblyHash))
            {
                if (_configManager?.IsReportHashUploaded(assemblyHash) == true)
                {
                    RecordOutcome("skipped", "duplicate", 0);
                    _logInfo($"ReportUploadService: Skipping duplicate upload for {filename} ({assemblyHash})");
                    return;
                }

                lock (InFlightUploadsLock)
                {
                    if (InFlightUploads.Contains(assemblyHash))
                    {
                        RecordOutcome("skipped", "in_flight", 0);
                        _logInfo($"ReportUploadService: Upload already queued for {filename} ({assemblyHash})");
                        return;
                    }

                    InFlightUploads.Add(assemblyHash);
                }
            }

            var outcome = "failed";
            var reason = "preparation_error";
            var attempts = 0;
            try
            {
                if (string.IsNullOrWhiteSpace(apiBaseUrl)) { outcome = "skipped"; reason = "not_configured"; return; }
                var baseUrl = apiBaseUrl.TrimEnd('/');
                _logInfo("ReportUploadService: Submitting a file for private review.");
                if (metadata?.OriginalFindings != null)
                {
                    // Map the findings from the original scan; never execute the sample or run a new scan here.
                    var original = ScanResultMapper.ToDto(metadata.OriginalFindings, RedactionHelper.RedactFilename(filename), assemblyBytes);
                    foreach (var finding in original.Findings) finding.Location = RedactionHelper.RedactLocation(finding.Location);
                    // A loader analysis limit must not become a clean report when mapping retained findings.
                    if (metadata.OriginalScanStatus == nameof(ScanStatusKind.RequiresReview) && original.AnalysisCompleteness.IsComplete)
                    {
                        original.AnalysisCompleteness.IsComplete = false;
                        original.AnalysisCompleteness.Status = "Incomplete";
                        original.AnalysisCompleteness.ReviewRecommended = true;
                        if (original.Disposition.Classification == "Clean")
                        {
                            original.Disposition.Classification = "ManualReviewRequired";
                            original.Disposition.Headline = "Manual review required";
                            original.Disposition.Summary = "The loader reported incomplete analysis.";
                        }
                    }
                    metadata.OriginalVerdict ??= original.Disposition?.Classification;
                    metadata.OriginalScanStatus ??= original.AnalysisCompleteness.Status;
                    using var reportStream = new MemoryStream();
                    new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(MLVScan.Models.Dto.ScanResultDto)).WriteObject(reportStream, original);
                    var json = Encoding.UTF8.GetString(reportStream.ToArray());
                    // Retain the bounded summary when a full report would exceed the private endpoint's cap.
                    if (Encoding.UTF8.GetByteCount(json) <= 180000) metadata.OriginalResultJson = json;
                }
                string receipt = null;
                for (var attempt = 0; attempt <= MaxRetries; attempt++)
                {
                    try
                    {
                        if (!SharingConsentPolicy.CanUploadFiles(_configManager?.Config)) { outcome = "skipped"; reason = "consent_revoked"; return; }
                        attempts++;
                        receipt = await UploadViaPostFilesAsync(assemblyBytes, filename, metadata, baseUrl);
                        outcome = "accepted";
                        reason = receipt == null ? "invalid_receipt" : "none";
                        break;
                    }
                    catch (Exception ex)
                    {
                        reason = ex is PrivateUploadException uploadError ? uploadError.Reason
                            : ex is OperationCanceledException ? "timeout" : "network_error";
                        _logWarn($"ReportUploadService: Attempt {attempt + 1} failed: {ex.Message}");
                        if (attempt == MaxRetries || ex is PrivateUploadException permanent && !permanent.Retryable)
                        {
                            throw;
                        }
                        await Task.Delay(1000 * (attempt + 1));
                    }
                }
                // The server accepted the sample. Local persistence or analytics failure must never retry it.
                try
                {
                    lock (ReceiptLock)
                    {
                        if (HashUtility.IsValidHash(assemblyHash)) _configManager?.MarkReportHashUploaded(assemblyHash);
                        if (receipt != null && _configManager?.Config != null)
                        {
                            var config = _configManager.Config;
                            config.UploadedReviewReceipts = (config.UploadedReviewReceipts ?? Array.Empty<string>())
                                .Append(assemblyHash + ":" + receipt).Distinct(StringComparer.Ordinal).ToArray();
                            _configManager.SaveConfig(config);
                        }
                    }
                }
                catch (Exception) { _logWarn("Private upload accepted, but its local receipt could not be saved."); }
                if (receipt == null) { _logWarn("Private upload accepted, but no valid receipt was returned; telemetry correlation unavailable."); return; }
                _logInfo("Private review submitted. Reference: " + receipt);
                try
                {
                    using var analyticsClient = _createHttpClient();
                    await PostHogScanTelemetry.SendReviewReceiptAsync(analyticsClient, _configManager?.Config,
                        receipt, metadata?.OriginalVerdict, metadata?.OriginalScanStatus).ConfigureAwait(false);
                }
                catch (Exception) { /* Best effort: never retry an accepted upload for telemetry. */ }

            }
            finally
            {
                RecordOutcome(outcome, reason, attempts);
                if (HashUtility.IsValidHash(assemblyHash))
                {
                    lock (InFlightUploadsLock)
                    {
                        InFlightUploads.Remove(assemblyHash);
                    }
                }
            }
        }

        private async Task<string> UploadViaPostFilesAsync(byte[] assemblyBytes, string filename, SubmissionMetadata metadata, string baseUrl)
        {
            using var client = _createHttpClient();
            using var content = new MultipartFormDataContent();

            // Explicitly set Content-Disposition on each part so Cloudflare's FormData parser
            // receives the required 'name' parameter (RFC 7578). MultipartFormDataContent.Add
            // can behave differently across .NET runtimes (Unity/Mono); manual setup guarantees
            // RFC-compliant output that workerd expects.
            var safeFilename = RedactionHelper.RedactFilename(filename);
            var fileContent = new ByteArrayContent(assemblyBytes);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"file\"",
                FileName = $"\"{safeFilename}\""
            };
            content.Add(fileContent);

            var metadataJson = SerializeMetadata(metadata);
            if (!string.IsNullOrEmpty(metadataJson))
            {
                var metaContent = new StringContent(metadataJson, Encoding.UTF8, "application/json");
                metaContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
                {
                    Name = "\"metadata\""
                };
                content.Add(metaContent);
            }

            var url = $"{baseUrl}/files/private-review";
            using var response = await client.PostAsync(url, content);

            if (!response.IsSuccessStatusCode)
            {
                throw new PrivateUploadException((int)response.StatusCode);
            }
            try
            {
                var bytes = await response.Content.ReadAsByteArrayAsync();
                if (bytes.Length > 8192) return null;
                using var stream = new MemoryStream(bytes);
                var receipt = (PrivateReviewReceipt)new DataContractJsonSerializer(typeof(PrivateReviewReceipt)).ReadObject(stream);
                return receipt.Visibility == "private" && PostHogScanTelemetry.IsValidReviewId(receipt.ReviewId)
                    ? Guid.Parse(receipt.ReviewId).ToString("D") : null;
            }
            catch (Exception) { return null; }

        }

        [DataContract]
        private sealed class PrivateReviewReceipt
        {
            [DataMember(Name = "reviewId")] public string ReviewId { get; set; }
            [DataMember(Name = "visibility")] public string Visibility { get; set; }
        }

        private sealed class PrivateUploadException : IOException
        {
            public string Reason { get; }
            public bool Retryable { get; }
            public PrivateUploadException(int status) : base($"Private review returned {status}.")
            {
                Reason = status == 404 ? "not_found" : status == 413 ? "size_limit" : status == 429 ? "rate_limited"
                    : status >= 500 ? "server_error" : "rejected";
                Retryable = status >= 500;
            }
        }

        private static HttpClient CreateDefaultHttpClient()
        {
            // Enable TLS 1.2 on older runtimes (Unity/Mono); otherwise "TLS Support not available" occurs.
            try
            {
                const SecurityProtocolType Tls12 = (SecurityProtocolType)3072;
                if ((ServicePointManager.SecurityProtocol & Tls12) == 0)
                    ServicePointManager.SecurityProtocol |= Tls12;
            }
            catch
            {
                // Ignore if ServicePointManager is unavailable (e.g. some mobile runtimes)
            }

            return new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
            {
                Timeout = TimeSpan.FromSeconds(DefaultTimeoutSeconds),
            };
        }

        private static string SerializeMetadata(SubmissionMetadata metadata)
        {
            if (metadata == null)
                return null;

            var sb = new StringBuilder();
            sb.Append('{');

            var parts = new List<string>();
            parts.Add($"\"coreVersion\":\"{EscapeJson(metadata.CoreVersion)}\"");
            if (metadata.OriginalVerdict != null) parts.Add($"\"originalVerdict\":\"{EscapeJson(metadata.OriginalVerdict)}\"");
            if (metadata.OriginalScanStatus != null) parts.Add($"\"originalScanStatus\":\"{EscapeJson(metadata.OriginalScanStatus)}\"");
            if (metadata.OriginalResultJson != null) parts.Add($"\"originalResultJson\":\"{EscapeJson(metadata.OriginalResultJson)}\"");

            if (!string.IsNullOrEmpty(metadata.LoaderType))
                parts.Add($"\"loaderType\":\"{EscapeJson(metadata.LoaderType)}\"");
            if (!string.IsNullOrEmpty(metadata.LoaderVersion))
                parts.Add($"\"loaderVersion\":\"{EscapeJson(metadata.LoaderVersion)}\"");
            if (!string.IsNullOrEmpty(metadata.PluginVersion))
                parts.Add($"\"pluginVersion\":\"{EscapeJson(metadata.PluginVersion)}\"");
            if (!string.IsNullOrEmpty(metadata.GameVersion))
                parts.Add($"\"gameVersion\":\"{EscapeJson(metadata.GameVersion)}\"");
            if (!string.IsNullOrEmpty(metadata.ModName))
                parts.Add($"\"modName\":\"{EscapeJson(metadata.ModName)}\"");
            if (!string.IsNullOrEmpty(metadata.SourceHint))
                parts.Add($"\"sourceHint\":\"{EscapeJson(metadata.SourceHint)}\"");
            if (!string.IsNullOrEmpty(metadata.ConsentVersion))
                parts.Add($"\"consentVersion\":\"{EscapeJson(metadata.ConsentVersion)}\"");
            if (!string.IsNullOrEmpty(metadata.ConsentTimestamp))
                parts.Add($"\"consentTimestamp\":\"{EscapeJson(metadata.ConsentTimestamp)}\"");

            if (metadata.FindingSummary != null && metadata.FindingSummary.Count > 0)
            {
                var items = metadata.FindingSummary.Take(64).Select(f => "{" + string.Join(",", new[]
                {
                    "\"ruleId\":\"" + EscapeJson(f.RuleId) + "\"",
                    "\"description\":\"" + EscapeJson(f.Description) + "\"",
                    "\"severity\":\"" + EscapeJson(f.Severity) + "\"",
                    "\"location\":\"" + EscapeJson(f.Location) + "\""
                }) + "}").ToArray();
                parts.Add($"\"findingSummary\":[{string.Join(",", items)}]");
            }

            sb.Append(string.Join(",", parts));
            sb.Append('}');
            return sb.ToString();
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;
            var escaped = new StringBuilder();
            foreach (var character in s)
            {
                if (character == '\\') escaped.Append("\\\\");
                else if (character == '"') escaped.Append("\\\"");
                else if (character < 32) escaped.Append("\\u").Append(((int)character).ToString("x4"));
                else escaped.Append(character);
            }
            return escaped.ToString();
        }
    }
}
