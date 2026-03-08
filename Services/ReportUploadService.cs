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

namespace MLVScan.Services
{
    /// <summary>
    /// Non-blocking service to upload scan reports and assemblies to the MLVScan API.
    /// Uses POST /files for small files (≤32MB) and GET /files/upload_url + PUT for large files.
    /// Never blocks startup; failures are logged and local behavior continues.
    /// </summary>
    public class ReportUploadService
    {
        private const int SmallFileLimitBytes = 32 * 1024 * 1024; // 32 MB
        private const int DefaultTimeoutSeconds = 30;
        private const int MaxRetries = 2;
        private static readonly object InFlightUploadsLock = new object();
        private static readonly HashSet<string> InFlightUploads = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private readonly IConfigManager _configManager;
        private readonly Action<string> _logInfo;
        private readonly Action<string> _logWarn;
        private readonly Action<string> _logError;

        public ReportUploadService(IConfigManager configManager, Action<string> logInfo, Action<string> logWarn, Action<string> logError)
        {
            _configManager = configManager;
            _logInfo = logInfo ?? (_ => { });
            _logWarn = logWarn ?? (_ => { });
            _logError = logError ?? (_ => { });
        }

        /// <summary>
        /// Upload assembly and metadata to the API in a non-blocking manner.
        /// Call this from a fire-and-forget task; do not await if you must not block.
        /// </summary>
        public void UploadReportNonBlocking(byte[] assemblyBytes, string filename, SubmissionMetadata metadata, string apiBaseUrl)
        {
            if (assemblyBytes == null || assemblyBytes.Length == 0)
            {
                _logWarn("ReportUploadService: No assembly bytes to upload");
                return;
            }

            if (string.IsNullOrWhiteSpace(apiBaseUrl))
            {
                _logWarn("ReportUploadService: API base URL not configured");
                return;
            }

            var baseUrl = apiBaseUrl.TrimEnd('/');

            Task.Run(async () =>
            {
                try
                {
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
            if (assemblyBytes == null || assemblyBytes.Length == 0)
            {
                _logWarn("ReportUploadService: No assembly bytes to upload");
                return;
            }

            var assemblyHash = HashUtility.CalculateBytesHash(assemblyBytes);
            if (HashUtility.IsValidHash(assemblyHash))
            {
                if (_configManager?.IsReportHashUploaded(assemblyHash) == true)
                {
                    _logInfo($"ReportUploadService: Skipping duplicate upload for {filename} ({assemblyHash})");
                    return;
                }

                lock (InFlightUploadsLock)
                {
                    if (InFlightUploads.Contains(assemblyHash))
                    {
                        _logInfo($"ReportUploadService: Upload already queued for {filename} ({assemblyHash})");
                        return;
                    }

                    InFlightUploads.Add(assemblyHash);
                }
            }

            var baseUrl = apiBaseUrl.TrimEnd('/');
            var useDirectUpload = assemblyBytes.Length <= SmallFileLimitBytes;

            try
            {
                for (var attempt = 0; attempt <= MaxRetries; attempt++)
                {
                    try
                    {
                        if (useDirectUpload)
                        {
                            await UploadViaPostFilesAsync(assemblyBytes, filename, metadata, baseUrl);
                        }
                        else
                        {
                            await UploadViaPresignedUrlAsync(assemblyBytes, filename, metadata, baseUrl);
                        }

                        if (HashUtility.IsValidHash(assemblyHash))
                        {
                            _configManager?.MarkReportHashUploaded(assemblyHash);
                        }

                        _logInfo($"ReportUploadService: Successfully uploaded {filename}");
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logWarn($"ReportUploadService: Attempt {attempt + 1} failed: {ex.Message}");
                        if (attempt == MaxRetries)
                        {
                            throw;
                        }
                        await Task.Delay(1000 * (attempt + 1));
                    }
                }
            }
            finally
            {
                if (HashUtility.IsValidHash(assemblyHash))
                {
                    lock (InFlightUploadsLock)
                    {
                        InFlightUploads.Remove(assemblyHash);
                    }
                }
            }
        }

        private async Task UploadViaPostFilesAsync(byte[] assemblyBytes, string filename, SubmissionMetadata metadata, string baseUrl)
        {
            using var client = CreateHttpClient();
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

            var url = $"{baseUrl}/files";
            var response = await client.PostAsync(url, content);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new IOException($"POST /files returned {(int)response.StatusCode}: {body}");
            }
        }

        private async Task UploadViaPresignedUrlAsync(byte[] assemblyBytes, string filename, SubmissionMetadata metadata, string baseUrl)
        {
            using var client = CreateHttpClient();

            var metadataJson = SerializeMetadata(metadata);
            var metadataBase64Url = string.IsNullOrEmpty(metadataJson)
                ? null
                : Convert.ToBase64String(Encoding.UTF8.GetBytes(metadataJson))
                    .Replace('+', '-')
                    .Replace('/', '_')
                    .TrimEnd('=');

            var query = new List<string>
            {
                $"filename={Uri.EscapeDataString(filename)}",
                "contentType=application/octet-stream"
            };
            if (!string.IsNullOrEmpty(metadataBase64Url))
            {
                query.Add($"metadata={Uri.EscapeDataString(metadataBase64Url)}");
            }

            var getUrl = $"{baseUrl}/files/upload_url?{string.Join("&", query)}";
            var getResponse = await client.GetAsync(getUrl);

            if (!getResponse.IsSuccessStatusCode)
            {
                var body = await getResponse.Content.ReadAsStringAsync();
                throw new IOException($"GET /files/upload_url returned {(int)getResponse.StatusCode}: {body}");
            }

            var json = await getResponse.Content.ReadAsStringAsync();
            var (uploadUrl, _) = ParseUploadUrlResponse(json);
            if (string.IsNullOrEmpty(uploadUrl))
            {
                throw new IOException("Failed to parse upload URL from response");
            }

            using var putClient = CreateHttpClient();
            using var putContent = new ByteArrayContent(assemblyBytes);
            putContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

            var putResponse = await putClient.PutAsync(uploadUrl, putContent);

            if (!putResponse.IsSuccessStatusCode)
            {
                var body = await putResponse.Content.ReadAsStringAsync();
                throw new IOException($"PUT to presigned URL returned {(int)putResponse.StatusCode}: {body}");
            }
        }

        private static HttpClient CreateHttpClient()
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

            return new HttpClient
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
                var items = metadata.FindingSummary.Select(f => "{" +
                    (string.IsNullOrEmpty(f.RuleId) ? "" : $"\"ruleId\":\"{EscapeJson(f.RuleId)}\",") +
                    (string.IsNullOrEmpty(f.Description) ? "" : $"\"description\":\"{EscapeJson(f.Description)}\",") +
                    (string.IsNullOrEmpty(f.Severity) ? "" : $"\"severity\":\"{EscapeJson(f.Severity)}\",") +
                    (string.IsNullOrEmpty(f.Location) ? "" : $"\"location\":\"{EscapeJson(f.Location)}\"") +
                    "}").ToArray();
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
            return s
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }

        private static (string uploadUrl, string submissionId) ParseUploadUrlResponse(string json)
        {
            try
            {
                var uploadUrl = ExtractJsonString(json, "upload_url");
                var submissionId = ExtractJsonString(json, "submission_id");
                if (string.IsNullOrEmpty(uploadUrl) && json.Contains("\"data\""))
                {
                    var dataStart = json.IndexOf("\"data\"", StringComparison.Ordinal);
                    var dataObj = json.Substring(dataStart);
                    uploadUrl = ExtractJsonString(dataObj, "upload_url");
                    submissionId = ExtractJsonString(dataObj, "submission_id");
                }
                return (uploadUrl, submissionId);
            }
            catch
            {
                return (null, null);
            }
        }

        private static string ExtractJsonString(string json, string key)
        {
            var pattern = $"\"{key}\"";
            var idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return null;
            idx = json.IndexOf(':', idx);
            if (idx < 0)
                return null;
            idx = json.IndexOf('"', idx);
            if (idx < 0)
                return null;
            var start = idx + 1;
            var end = start;
            while (end < json.Length && json[end] != '"')
            {
                if (json[end] == '\\')
                    end++;
                end++;
            }
            var raw = json.Substring(start, end - start);
            return raw.Replace("\\\"", "\"").Replace("\\\\", "\\");
        }
    }
}
