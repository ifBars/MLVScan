using System;
using System.Collections.Generic;
using System.Linq;
using MLVScan.Abstractions;
using MLVScan.Services.Diagnostics;
using Mono.Cecil;

namespace MLVScan.Services.Resolution
{
    public abstract class CatalogingAssemblyResolverProviderBase : IAssemblyResolverProvider, IResolverCatalogProvider
    {
        private readonly object _sync = new object();
        private readonly LoaderScanTelemetryHub _telemetry;
        private IndexedAssemblyResolver _resolver;

        protected CatalogingAssemblyResolverProviderBase()
        {
            _telemetry = new LoaderScanTelemetryHub();
            ContextFingerprint = ResolverCatalog.Empty.Fingerprint;
        }

        public string ContextFingerprint { get; private set; }

        public void BuildCatalog(IEnumerable<string> targetRoots)
        {
            var roots = GetStableRoots()
                .Concat((targetRoots ?? Array.Empty<string>())
                    .Where(static root => !string.IsNullOrWhiteSpace(root))
                    .Select(static root => new ResolverRoot(root, 20)))
                .ToArray();

            var catalog = AssemblyResolverCatalogBuilder.Build(roots);
            lock (_sync)
            {
                _resolver?.Dispose();
                _resolver = new IndexedAssemblyResolver(catalog, _telemetry);
                ContextFingerprint = catalog.Fingerprint;
            }
        }

        public IAssemblyResolver CreateResolver()
        {
            lock (_sync)
            {
                _resolver ??= new IndexedAssemblyResolver(
                    AssemblyResolverCatalogBuilder.Build(GetStableRoots()),
                    _telemetry);

                return _resolver;
            }
        }

        protected abstract IEnumerable<ResolverRoot> GetStableRoots();
    }
}
