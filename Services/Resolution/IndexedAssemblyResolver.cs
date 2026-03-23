using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Mono.Cecil;
using MLVScan.Services.Diagnostics;

namespace MLVScan.Services.Resolution
{
    internal sealed class IndexedAssemblyResolver : BaseAssemblyResolver
    {
        private readonly ResolverCatalog _catalog;
        private readonly Dictionary<string, AssemblyDefinition> _resolved = new Dictionary<string, AssemblyDefinition>(StringComparer.Ordinal);
        private readonly HashSet<string> _missing = new HashSet<string>(StringComparer.Ordinal);
        private readonly LoaderScanTelemetryHub _telemetry;

        public IndexedAssemblyResolver(ResolverCatalog catalog, LoaderScanTelemetryHub telemetry = null)
        {
            _catalog = catalog ?? ResolverCatalog.Empty;
            _telemetry = telemetry;
        }

        public override AssemblyDefinition Resolve(AssemblyNameReference name)
        {
            return Resolve(name, new ReaderParameters
            {
                AssemblyResolver = this
            });
        }

        public override AssemblyDefinition Resolve(AssemblyNameReference name, ReaderParameters parameters)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            var cacheKey = name.FullName;
            if (_resolved.TryGetValue(cacheKey, out var cached))
            {
                _telemetry?.IncrementCounter("Resolver.CacheHit");
                return cached;
            }

            if (_missing.Contains(cacheKey))
            {
                _telemetry?.IncrementCounter("Resolver.NegativeCacheHit");
                throw new AssemblyResolutionException(name);
            }

            if (!_catalog.CandidatesBySimpleName.TryGetValue(name.Name, out var candidates))
            {
                _missing.Add(cacheKey);
                _telemetry?.IncrementCounter("Resolver.Miss");
                throw new AssemblyResolutionException(name);
            }

            foreach (var candidate in OrderCandidates(name, candidates))
            {
                try
                {
                    var readParameters = parameters ?? new ReaderParameters();
                    readParameters.AssemblyResolver = this;
                    var assembly = AssemblyDefinition.ReadAssembly(candidate.Path, readParameters);
                    _resolved[cacheKey] = assembly;
                    _telemetry?.IncrementCounter("Resolver.ResolveHit");
                    return assembly;
                }
                catch
                {
                    // Try the next candidate path.
                }
            }

            _missing.Add(cacheKey);
            _telemetry?.IncrementCounter("Resolver.Miss");
            throw new AssemblyResolutionException(name);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (var assembly in _resolved.Values.Distinct())
                {
                    assembly.Dispose();
                }

                _resolved.Clear();
                _missing.Clear();
            }

            base.Dispose(disposing);
        }

        private static IEnumerable<ResolverCatalogCandidate> OrderCandidates(
            AssemblyNameReference reference,
            IEnumerable<ResolverCatalogCandidate> candidates)
        {
            var expectedVersion = reference.Version?.ToString() ?? string.Empty;
            var expectedToken = FormatPublicKeyToken(reference.PublicKeyToken);

            return candidates
                .OrderBy(candidate => CandidateMatches(reference.Name, expectedVersion, expectedToken, candidate) ? 0 : 1)
                .ThenBy(candidate => candidate.Priority)
                .ThenBy(candidate => candidate.Path, GetPathComparer());
        }

        private static bool CandidateMatches(
            string simpleName,
            string expectedVersion,
            string expectedToken,
            ResolverCatalogCandidate candidate)
        {
            if (!string.Equals(simpleName, candidate.SimpleName, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(expectedVersion) &&
                !string.Equals(expectedVersion, candidate.Version, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(expectedToken) &&
                !string.Equals(expectedToken, candidate.PublicKeyToken, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        private static string FormatPublicKeyToken(byte[] token)
        {
            if (token == null || token.Length == 0)
            {
                return string.Empty;
            }

            return BitConverter.ToString(token).Replace("-", string.Empty).ToLowerInvariant();
        }

        private static StringComparer GetPathComparer()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal;
        }
    }
}
