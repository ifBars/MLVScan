using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        private readonly IScanCacheStore _cacheStore;
        private readonly IResolverCatalogProvider _resolverCatalogProvider;
        private readonly LoaderScanTelemetryHub _telemetry;
        private readonly TargetAssemblyScopeFilter _scopeFilter = new TargetAssemblyScopeFilter();
        private readonly string _scannerFingerprint;
        private readonly string _selfAssemblyHash;

        protected PluginScannerBase(
            IScanLogger logger,
            IAssemblyResolverProvider resolverProvider,
            MLVScanConfig config,
            IConfigManager configManager,
            IPlatformEnvironment environment)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            ResolverProvider = resolverProvider ?? throw new ArgumentNullException(nameof(resolverProvider));
            Config = config ?? throw new ArgumentNullException(nameof(config));
            ConfigManager = configManager ?? throw new ArgumentNullException(nameof(configManager));
            Environment = environment ?? throw new ArgumentNullException(nameof(environment));

            _telemetry = new LoaderScanTelemetryHub();
            _fileIdentityProvider = new CrossPlatformFileIdentityProvider();
            _cacheStore = CreateDefaultCacheStore(environment);
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

            var resolverFingerprint = BuildResolverCatalog(effectiveRoots);
            var pathComparer = GetPathComparer();
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

            if (Config.EnableScanCache)
            {
                _cacheStore.PruneMissingEntries(activeCanonicalPaths);
            }

            OnScanComplete(results);
            _telemetry.CompleteRun(effectiveRoots.Count, candidateFiles.Length, results.Count);

            var artifactPath = _telemetry.TryWriteArtifact(Path.Combine(Environment.DataDirectory, "Diagnostics"));
            if (!string.IsNullOrWhiteSpace(artifactPath))
            {
                Logger.Debug($"Wrote loader profile artifact: {artifactPath}");
            }

            return results;
        }

        protected virtual IEnumerable<string> EnumerateCandidateFiles(string directoryPath)
        {
            Logger.Info($"Scanning directory: {directoryPath}");
            return Directory.EnumerateFiles(directoryPath, "*.dll", SearchOption.AllDirectories);
        }

        /// <summary>
        /// Scans a single file and adds results if suspicious.
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

            if (probe.Stream.CanSeek && probe.Stream.Length > MaxAssemblyScanBytes)
            {
                Logger.Warning(
                    $"Skipping {fileName} because it is larger than the loader scan limit of {MaxAssemblyScanBytes / (1024 * 1024)} MB.");
                _telemetry.IncrementCounter("Files.TooLarge");
                _telemetry.RecordFileSample(filePath, fileStart, "skip:too-large", 0, 0);
                return;
            }

            var readStart = _telemetry.StartTimestamp();
            var assemblyBytes = ReadFileBytes(probe.Stream);
            _telemetry.AddPhaseElapsed("File.ReadBytes", readStart);
            _telemetry.IncrementCounter("Bytes.Read", assemblyBytes.Length);

            var hashStart = _telemetry.StartTimestamp();
            var hash = HashUtility.CalculateBytesHash(assemblyBytes);
            _telemetry.AddPhaseElapsed("Hash.CalculateSha256", hashStart);

            if (IsExactSelfCopy(hash))
            {
                Logger.Debug($"Skipping self copy: {fileName}");
                _telemetry.IncrementCounter("Files.SelfCopy");
                return;
            }

            if (Config.EnableScanCache &&
                TryReuseByHashCache(hash, probe, filePath, resolverFingerprint, results))
            {
                _telemetry.RecordFileSample(filePath, fileStart, "cache-hit:hash", assemblyBytes.Length, 0);
                return;
            }

            var exactHashResult = ThreatVerdictBuilder.Build(filePath, hash, new List<ScanFinding>());
            if (exactHashResult.ThreatVerdict.Kind == ThreatVerdictKind.KnownMaliciousSample)
            {
                UpsertCacheEntry(probe, hash, resolverFingerprint, exactHashResult);
                RegisterFlaggedResultIfNeeded(fileName, exactHashResult, results);
                _telemetry.RecordFileSample(filePath, fileStart, "hash-only-known-sample", assemblyBytes.Length, 0);
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

            RegisterFlaggedResultIfNeeded(fileName, scannedResult, results);
            _telemetry.RecordFileSample(filePath, fileStart, "scan", assemblyBytes.Length, actualFindings.Count);
        }

        private bool TryReuseByPathCache(
            FileProbe probe,
            string filePath,
            string resolverFingerprint,
            Dictionary<string, ScannedPluginResult> results)
        {
            var entry = _cacheStore.TryGetByPath(probe.CanonicalPath);
            if (entry == null)
            {
                _telemetry.IncrementCounter("Cache.PathMiss");
                return false;
            }

            if (!entry.CanReuseStrictly(probe, _scannerFingerprint, resolverFingerprint, _cacheStore.CanTrustCleanEntries))
            {
                _telemetry.IncrementCounter("Cache.PathRejected");
                return false;
            }

            _telemetry.IncrementCounter("Cache.PathHit");
            RegisterFlaggedResultIfNeeded(Path.GetFileName(filePath), entry.CloneResultForPath(filePath), results);
            return true;
        }

        private bool TryReuseByHashCache(
            string hash,
            FileProbe probe,
            string filePath,
            string resolverFingerprint,
            Dictionary<string, ScannedPluginResult> results)
        {
            var entry = _cacheStore.TryGetByHash(hash);
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

            if (entry.Result?.ThreatVerdict?.Kind == ThreatVerdictKind.None &&
                !_cacheStore.CanTrustCleanEntries)
            {
                _telemetry.IncrementCounter("Cache.HashRejected");
                return false;
            }

            var clonedResult = entry.CloneResultForPath(filePath);
            UpsertCacheEntry(probe, hash, resolverFingerprint, clonedResult);
            _telemetry.IncrementCounter("Cache.HashHit");
            RegisterFlaggedResultIfNeeded(Path.GetFileName(filePath), clonedResult, results);
            return true;
        }

        private void RegisterFlaggedResultIfNeeded(
            string fileName,
            ScannedPluginResult scannedResult,
            Dictionary<string, ScannedPluginResult> results)
        {
            if (scannedResult == null)
            {
                return;
            }

            if (ConfigManager.IsHashWhitelisted(scannedResult.FileHash))
            {
                Logger.Debug($"Skipping whitelisted: {fileName}");
                _telemetry.IncrementCounter("Files.Whitelisted");
                return;
            }

            if (scannedResult.ThreatVerdict.Kind == ThreatVerdictKind.None)
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

            Logger.Warning($"Detected suspicious behavior in {fileName} - {scannedResult.ThreatVerdict.Title}");
        }

        private void UpsertCacheEntry(FileProbe probe, string hash, string resolverFingerprint, ScannedPluginResult result)
        {
            if (!Config.EnableScanCache)
            {
                return;
            }

            _cacheStore.Upsert(new ScanCacheEntry
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

        private bool IsExactSelfCopy(string hash)
        {
            return !string.IsNullOrWhiteSpace(_selfAssemblyHash) &&
                   _selfAssemblyHash.Equals(hash, StringComparison.OrdinalIgnoreCase);
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
