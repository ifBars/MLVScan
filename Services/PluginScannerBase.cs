using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Caching;
using MLVScan.Services.Diagnostics;
using MLVScan.Services.Resolution;
using MLVScan.Services.Scope;

namespace MLVScan.Services
{
    /// <summary>
    /// Abstract base class for plugin/mod scanning across platforms.
    /// Contains shared scanning logic, with platform-specific details
    /// delegated to derived classes.
    /// </summary>
    public abstract class PluginScannerBase
    {
        protected readonly IScanLogger Logger;
        protected readonly IAssemblyResolverProvider ResolverProvider;
        protected readonly MLVScanConfig Config;
        protected readonly IConfigManager ConfigManager;
        protected readonly IPlatformEnvironment Environment;
        protected readonly AssemblyScanner AssemblyScanner;
        protected readonly ThreatVerdictBuilder ThreatVerdictBuilder;
        private const long MaxAssemblyScanBytes = 256L * 1024 * 1024;

        private readonly IFileIdentityProvider _fileIdentityProvider;
        private readonly IResolverCatalogProvider _resolverCatalogProvider;
        private readonly LoaderScanTelemetryHub _telemetry;
        private readonly TargetAssemblyScopeFilter _scopeFilter = new TargetAssemblyScopeFilter();
        private readonly string _scannerFingerprint;
        private readonly string _selfAssemblyHash;
        private IScanCacheStore _cacheStore;
        private bool _cacheUnavailable;

        protected PluginScannerBase(
            IScanLogger logger,
            IAssemblyResolverProvider resolverProvider,
            MLVScanConfig config,
            IConfigManager configManager,
            IPlatformEnvironment environment,
            LoaderScanTelemetryHub telemetry)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            ResolverProvider = resolverProvider ?? throw new ArgumentNullException(nameof(resolverProvider));
            Config = config ?? throw new ArgumentNullException(nameof(config));
            ConfigManager = configManager ?? throw new ArgumentNullException(nameof(configManager));
            Environment = environment ?? throw new ArgumentNullException(nameof(environment));

            _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
            _fileIdentityProvider = new CrossPlatformFileIdentityProvider();
            _resolverCatalogProvider = resolverProvider as IResolverCatalogProvider;

            var rules = RuleFactory.CreateDefaultRules().ToArray();
            AssemblyScanner = new AssemblyScanner(rules, Config.Scan, ResolverProvider);
            ThreatVerdictBuilder = new ThreatVerdictBuilder();
            _scannerFingerprint = ComputeScannerFingerprint(Config.Scan, rules);
            _selfAssemblyHash = GetSelfAssemblyHash(environment.SelfAssemblyPath);
        }

        /// <summary>
        /// Gets the directories to scan for plugins.
        /// </summary>
        protected abstract IEnumerable<string> GetScanDirectories();

        /// <summary>
        /// Checks if a file path is this scanner's own assembly.
        /// </summary>
        protected abstract bool IsSelfAssembly(string filePath);

        /// <summary>
        /// Gets directories that should participate in dependency resolution, even if they are
        /// currently excluded from target scanning.
        /// </summary>
        protected virtual IEnumerable<string> GetResolverDirectories()
        {
            return GetScanDirectories();
        }

        /// <summary>
        /// Performs any platform-specific post-scan processing.
        /// </summary>
        protected virtual void OnScanComplete(Dictionary<string, ScannedPluginResult> results) { }

        /// <summary>
        /// Scans all plugins in configured directories.
        /// </summary>
        /// <param name="forceScanning">If true, scans even if auto-scan is disabled.</param>
        public Dictionary<string, ScannedPluginResult> ScanAllPlugins(bool forceScanning = false)
        {
            var results = new Dictionary<string, ScannedPluginResult>(StringComparer.OrdinalIgnoreCase);

            if (!forceScanning && !Config.EnableAutoScan)
            {
                Logger.Info("Automatic scanning is disabled in configuration");
                return results;
            }

            _telemetry.BeginRun($"{Environment.PlatformName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}");

            var rawRoots = GetScanDirectories().ToArray();
            foreach (var directory in rawRoots.Where(static directory => !Directory.Exists(directory)))
            {
                Logger.Warning($"Directory not found: {directory}");
            }

            var scopeStart = _telemetry.StartTimestamp();
            var effectiveRoots = _scopeFilter.BuildEffectiveRoots(rawRoots, Config);
            _telemetry.AddPhaseElapsed("Scope.BuildEffectiveRoots", scopeStart);

            var pathComparer = GetPathComparer();
            var resolverRoots = GetResolverDirectories()
                .Concat(Config.AdditionalTargetRoots)
                .Where(static root => !string.IsNullOrWhiteSpace(root))
                .Select(Path.GetFullPath)
                .Distinct(pathComparer)
                .ToArray();

            var resolverFingerprint = BuildResolverCatalog(resolverRoots);
            var candidateFiles = effectiveRoots
                .SelectMany(EnumerateCandidateFiles)
                .Distinct(pathComparer)
                .ToArray();

            var activeCanonicalPaths = new HashSet<string>(pathComparer);
            var processedCanonicalPaths = new HashSet<string>(pathComparer);

            foreach (var pluginFile in candidateFiles)
            {
                try
                {
                    ScanSingleFile(
                        pluginFile,
                        effectiveRoots,
                        results,
                        activeCanonicalPaths,
                        processedCanonicalPaths,
                        resolverFingerprint);
                }
                catch (Exception ex)
                {
                    Logger.Error($"Error scanning {Path.GetFileName(pluginFile)}: {ex.Message}");
                }
            }

            var cacheStore = GetCacheStore();
            if (cacheStore != null)
            {
                cacheStore.PruneMissingEntries(activeCanonicalPaths);
            }

            OnScanComplete(results);
            _telemetry.CompleteRun(effectiveRoots.Count, candidateFiles.Length, results.Count);

            var dataDirectory = TryGetDataDirectory();
            if (!string.IsNullOrWhiteSpace(dataDirectory))
            {
                var artifactPath = _telemetry.TryWriteArtifact(Path.Combine(dataDirectory, "Diagnostics"));
                if (!string.IsNullOrWhiteSpace(artifactPath))
                {
                    Logger.Debug($"Wrote loader profile artifact: {artifactPath}");
                }
            }

            return results;
        }

        protected virtual IEnumerable<string> EnumerateCandidateFiles(string directoryPath)
        {
            Logger.Info($"Scanning directory: {directoryPath}");
            return Directory.EnumerateFiles(directoryPath, "*.dll", SearchOption.AllDirectories);
        }

        /// <summary>
        /// Scans a single file and adds results when the file requires user attention.
        /// </summary>
        protected virtual void ScanSingleFile(
            string filePath,
            IReadOnlyCollection<string> effectiveRoots,
            Dictionary<string, ScannedPluginResult> results,
            ISet<string> activeCanonicalPaths,
            ISet<string> processedCanonicalPaths,
            string resolverFingerprint)
        {
            var fileStart = _telemetry.StartTimestamp();
            var fileName = Path.GetFileName(filePath);

            using var probe = _fileIdentityProvider.OpenProbe(filePath);
            if (!_scopeFilter.IsTargetAssembly(probe.CanonicalPath, effectiveRoots, Config))
            {
                _telemetry.IncrementCounter("Files.OutOfScope");
                return;
            }

            activeCanonicalPaths.Add(probe.CanonicalPath);
            if (!processedCanonicalPaths.Add(probe.CanonicalPath))
            {
                _telemetry.IncrementCounter("Files.DuplicateCanonicalPath");
                return;
            }

            if (IsSelfAssembly(probe.CanonicalPath))
            {
                Logger.Debug($"Skipping self: {fileName}");
                _telemetry.IncrementCounter("Files.Self");
                return;
            }

            if (Config.EnableScanCache &&
                TryReuseByPathCache(probe, filePath, resolverFingerprint, results))
            {
                _telemetry.RecordFileSample(filePath, fileStart, "cache-hit:path", 0, 0);
                return;
            }

            var isOversized = probe.Stream.CanSeek && probe.Stream.Length > MaxAssemblyScanBytes;
            var bytesRead = 0L;
            byte[] assemblyBytes = null;
            string hash;

            if (isOversized)
            {
                Logger.Warning(
                    $"Manual review required for {fileName}: it exceeds the loader scan limit of {MaxAssemblyScanBytes / (1024 * 1024)} MB and cannot be fully analyzed in memory.");
                _telemetry.IncrementCounter("Files.TooLarge");
                bytesRead = probe.Stream.CanSeek ? probe.Stream.Length : 0L;
                if (bytesRead > 0)
                {
                    _telemetry.IncrementCounter("Bytes.Read", bytesRead);
                }

                var hashStart = _telemetry.StartTimestamp();
                hash = CalculateStreamHash(probe.Stream);
                _telemetry.AddPhaseElapsed("Hash.CalculateSha256", hashStart);
            }
            else
            {
                var readStart = _telemetry.StartTimestamp();
                assemblyBytes = ReadFileBytes(probe.Stream);
                _telemetry.AddPhaseElapsed("File.ReadBytes", readStart);
                bytesRead = assemblyBytes.Length;
                _telemetry.IncrementCounter("Bytes.Read", bytesRead);

                var hashStart = _telemetry.StartTimestamp();
                hash = HashUtility.CalculateBytesHash(assemblyBytes);
                _telemetry.AddPhaseElapsed("Hash.CalculateSha256", hashStart);
            }

            if (IsExactSelfCopy(hash))
            {
                Logger.Debug($"Skipping self copy: {fileName}");
                _telemetry.IncrementCounter("Files.SelfCopy");
                return;
            }

            if (IsHashWhitelisted(fileName, hash))
            {
                return;
            }

            if (Config.EnableScanCache &&
                TryReuseByHashCache(hash, probe, filePath, resolverFingerprint, results))
            {
                _telemetry.RecordFileSample(filePath, fileStart, "cache-hit:hash", bytesRead, 0);
                return;
            }

            var exactHashResult = ThreatVerdictBuilder.Build(filePath, hash, new List<ScanFinding>());
            if (exactHashResult.ThreatVerdict.Kind == ThreatVerdictKind.KnownMaliciousSample)
            {
                UpsertCacheEntry(probe, hash, resolverFingerprint, exactHashResult);
                RegisterResultIfNeeded(fileName, exactHashResult, results);
                _telemetry.RecordFileSample(filePath, fileStart, "hash-only-known-sample", bytesRead, 0);
                return;
            }

            if (isOversized)
            {
                var oversizedResult = CreateOversizedAssemblyResult(filePath, hash, bytesRead);
                UpsertCacheEntry(probe, hash, resolverFingerprint, oversizedResult);
                RegisterResultIfNeeded(fileName, oversizedResult, results);
                _telemetry.RecordFileSample(filePath, fileStart, "oversized:review-required", bytesRead, oversizedResult.Findings.Count);
                return;
            }

            var scanStart = _telemetry.StartTimestamp();
            using var assemblyStream = new MemoryStream(assemblyBytes, writable: false);
            var findings = AssemblyScanner.Scan(assemblyStream, filePath).ToList();
            _telemetry.AddPhaseElapsed("Scan.Assembly", scanStart);

            var actualFindings = findings
                .Where(static finding => finding.Location != "Assembly scanning")
                .ToList();

            var scannedResult = ThreatVerdictBuilder.Build(filePath, hash, actualFindings);
            UpsertCacheEntry(probe, hash, resolverFingerprint, scannedResult);

            RegisterResultIfNeeded(fileName, scannedResult, results);
            _telemetry.RecordFileSample(filePath, fileStart, "scan", bytesRead, actualFindings.Count);
        }

        private bool TryReuseByPathCache(
            FileProbe probe,
            string filePath,
            string resolverFingerprint,
            Dictionary<string, ScannedPluginResult> results)
        {
            var cacheStore = GetCacheStore();
            if (cacheStore == null)
            {
                return false;
            }

            var entry = cacheStore.TryGetByPath(probe.CanonicalPath);
            if (entry == null)
            {
                _telemetry.IncrementCounter("Cache.PathMiss");
                return false;
            }

            if (!entry.CanReuseStrictly(probe, _scannerFingerprint, resolverFingerprint, cacheStore.CanTrustCleanEntries))
            {
                _telemetry.IncrementCounter("Cache.PathRejected");
                return false;
            }

            _telemetry.IncrementCounter("Cache.PathHit");
            RegisterResultIfNeeded(Path.GetFileName(filePath), entry.CloneResultForPath(filePath), results);
            return true;
        }

        private bool TryReuseByHashCache(
            string hash,
            FileProbe probe,
            string filePath,
            string resolverFingerprint,
            Dictionary<string, ScannedPluginResult> results)
        {
            var cacheStore = GetCacheStore();
            if (cacheStore == null)
            {
                return false;
            }

            var entry = cacheStore.TryGetByHash(hash);
            if (entry == null)
            {
                _telemetry.IncrementCounter("Cache.HashMiss");
                return false;
            }

            if (!string.Equals(entry.ScannerFingerprint, _scannerFingerprint, StringComparison.Ordinal) ||
                !string.Equals(entry.ResolverFingerprint, resolverFingerprint, StringComparison.Ordinal))
            {
                _telemetry.IncrementCounter("Cache.HashRejected");
                return false;
            }

            if (!ScanResultFacts.HasThreatVerdict(entry.Result) &&
                !cacheStore.CanTrustCleanEntries)
            {
                _telemetry.IncrementCounter("Cache.HashRejected");
                return false;
            }

            var clonedResult = entry.CloneResultForPath(filePath);
            UpsertCacheEntry(probe, hash, resolverFingerprint, clonedResult);
            _telemetry.IncrementCounter("Cache.HashHit");
            RegisterResultIfNeeded(Path.GetFileName(filePath), clonedResult, results);
            return true;
        }

        private void RegisterResultIfNeeded(
            string fileName,
            ScannedPluginResult scannedResult,
            Dictionary<string, ScannedPluginResult> results)
        {
            if (scannedResult == null)
            {
                return;
            }

            if (IsHashWhitelisted(fileName, scannedResult.FileHash))
            {
                return;
            }

            if (!ScanResultFacts.RequiresAttention(scannedResult))
            {
                return;
            }

            results[scannedResult.FilePath] = scannedResult;
            if (scannedResult.ThreatVerdict.Kind == ThreatVerdictKind.KnownMaliciousSample ||
                scannedResult.ThreatVerdict.Kind == ThreatVerdictKind.KnownMalwareFamily)
            {
                var familyName = scannedResult.ThreatVerdict.PrimaryFamily?.DisplayName;
                if (!string.IsNullOrWhiteSpace(familyName))
                {
                    Logger.Warning($"Detected likely malware in {fileName} - {scannedResult.ThreatVerdict.Title}: {familyName}");
                }
                else
                {
                    Logger.Warning($"Detected likely malware in {fileName} - {scannedResult.ThreatVerdict.Title}");
                }

                return;
            }

            if (scannedResult.ThreatVerdict.Kind == ThreatVerdictKind.Suspicious)
            {
                Logger.Warning($"Detected suspicious behavior in {fileName} - {scannedResult.ThreatVerdict.Title}");
                return;
            }

            Logger.Warning($"Manual review required for {fileName} - {scannedResult.ScanStatus.Title}");
        }

        private bool IsHashWhitelisted(string fileName, string fileHash)
        {
            if (!ConfigManager.IsHashWhitelisted(fileHash))
            {
                return false;
            }

            Logger.Debug($"Skipping whitelisted: {fileName}");
            _telemetry.IncrementCounter("Files.Whitelisted");
            return true;
        }

        private void UpsertCacheEntry(FileProbe probe, string hash, string resolverFingerprint, ScannedPluginResult result)
        {
            var cacheStore = GetCacheStore();
            if (cacheStore == null)
            {
                return;
            }

            cacheStore.Upsert(new ScanCacheEntry
            {
                CanonicalPath = probe.CanonicalPath,
                RealPath = probe.OriginalPath,
                FileIdentity = probe.Identity,
                Sha256 = hash,
                ScannerFingerprint = _scannerFingerprint,
                ResolverFingerprint = resolverFingerprint,
                Result = result
            });
        }

        private static ScannedPluginResult CreateOversizedAssemblyResult(string filePath, string fileHash, long fileSizeBytes)
        {
            var limitMb = MaxAssemblyScanBytes / (1024 * 1024);
            var sizeMb = fileSizeBytes > 0
                ? Math.Ceiling(fileSizeBytes / (1024d * 1024d))
                : 0d;
            var findings = new List<ScanFinding>
            {
                new ScanFinding(
                    "Loader scan preflight",
                    $"Assembly exceeds the loader scan limit ({sizeMb:0.#} MB > {limitMb} MB). SHA-256 and exact known-malicious sample checks still ran, but full IL analysis was skipped and the file requires manual review.",
                    Severity.Medium)
                {
                    RuleId = "OversizedAssembly"
                }
            };

            return new ScannedPluginResult
            {
                FilePath = filePath ?? string.Empty,
                FileHash = fileHash ?? string.Empty,
                Findings = findings,
                ThreatVerdict = new ThreatVerdictInfo
                {
                    Kind = ThreatVerdictKind.None,
                    Title = "No threat verdict",
                    Summary = "No retained malicious verdict was produced before the loader hit a scan-completeness limit.",
                    Confidence = 0d,
                    ShouldBypassThreshold = false
                },
                ScanStatus = new ScanStatusInfo
                {
                    Kind = ScanStatusKind.RequiresReview,
                    Title = "Manual review required",
                    Summary = $"This file exceeds the loader scan size limit ({limitMb} MB). MLVScan calculated its SHA-256 hash and checked exact known-malicious sample matches, but full IL analysis was skipped to avoid loading the entire assembly into memory."
                }
            };
        }

        private string BuildResolverCatalog(IReadOnlyCollection<string> effectiveRoots)
        {
            if (_resolverCatalogProvider == null)
            {
                return "resolver-provider-unavailable";
            }

            var start = _telemetry.StartTimestamp();
            _resolverCatalogProvider.BuildCatalog(effectiveRoots);
            _telemetry.AddPhaseElapsed("Resolver.BuildCatalog", start);
            return _resolverCatalogProvider.ContextFingerprint;
        }

        private IScanCacheStore GetCacheStore()
        {
            if (!Config.EnableScanCache || _cacheUnavailable)
            {
                return null;
            }

            if (_cacheStore != null)
            {
                return _cacheStore;
            }

            try
            {
                _cacheStore = CreateDefaultCacheStore(Environment);
            }
            catch (Exception ex)
            {
                _cacheUnavailable = true;
                Logger.Warning($"Scan cache unavailable; continuing without cache reuse: {ex.Message}");
            }

            return _cacheStore;
        }

        private bool IsExactSelfCopy(string hash)
        {
            return !string.IsNullOrWhiteSpace(_selfAssemblyHash) &&
                   _selfAssemblyHash.Equals(hash, StringComparison.OrdinalIgnoreCase);
        }

        private string TryGetDataDirectory()
        {
            try
            {
                return Environment.DataDirectory;
            }
            catch (Exception ex)
            {
                Logger.Warning($"Diagnostics output unavailable: {ex.Message}");
                return null;
            }
        }

        private static string GetSelfAssemblyHash(string selfAssemblyPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(selfAssemblyPath) || !File.Exists(selfAssemblyPath))
                {
                    return string.Empty;
                }

                return HashUtility.CalculateFileHash(selfAssemblyPath);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static byte[] ReadFileBytes(FileStream stream)
        {
            stream.Position = 0;
            using var memory = new MemoryStream(stream.CanSeek ? (int)stream.Length : 0);
            stream.CopyTo(memory);
            return memory.ToArray();
        }

        private static string CalculateStreamHash(FileStream stream)
        {
            stream.Position = 0;
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
        }

        private static IScanCacheStore CreateDefaultCacheStore(IPlatformEnvironment environment)
        {
            var cacheDirectory = Path.Combine(environment.DataDirectory, "Cache");
            return new SecureScanCacheStore(cacheDirectory, new ScanCacheSigner(cacheDirectory));
        }

        private static string ComputeScannerFingerprint(ScanConfig config, IReadOnlyCollection<IScanRule> rules)
        {
            var parts = new List<string>
            {
                PlatformConstants.PlatformName,
                PlatformConstants.PlatformVersion,
                MLVScanVersions.CoreVersion,
                MLVScanVersions.SchemaVersion.ToString(),
                $"EnableMultiSignalDetection={config.EnableMultiSignalDetection}",
                $"AnalyzeExceptionHandlers={config.AnalyzeExceptionHandlers}",
                $"AnalyzeLocalVariables={config.AnalyzeLocalVariables}",
                $"AnalyzePropertyAccessors={config.AnalyzePropertyAccessors}",
                $"DetectAssemblyMetadata={config.DetectAssemblyMetadata}",
                $"EnableCrossMethodAnalysis={config.EnableCrossMethodAnalysis}",
                $"MaxCallChainDepth={config.MaxCallChainDepth}",
                $"EnableReturnValueTracking={config.EnableReturnValueTracking}",
                $"EnableRecursiveResourceScanning={config.EnableRecursiveResourceScanning}",
                $"MaxRecursiveResourceSizeMB={config.MaxRecursiveResourceSizeMB}",
                $"MinimumEncodedStringLength={config.MinimumEncodedStringLength}"
            };

            parts.AddRange(rules
                .OrderBy(rule => rule.RuleId, StringComparer.Ordinal)
                .ThenBy(rule => rule.GetType().FullName, StringComparer.Ordinal)
                .Select(rule => $"{rule.RuleId}|{rule.Severity}|{rule.GetType().FullName}"));

            return HashUtility.CalculateBytesHash(Encoding.UTF8.GetBytes(string.Join("\n", parts)));
        }

        private static StringComparer GetPathComparer()
        {
            return RuntimeInformationHelper.IsWindows || RuntimeInformationHelper.IsMacOs
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal;
        }
    }
}
