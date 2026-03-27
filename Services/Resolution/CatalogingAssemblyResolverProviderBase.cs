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
        private ResolverCatalog _catalog;

        protected CatalogingAssemblyResolverProviderBase(LoaderScanTelemetryHub telemetry)
        {
            _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
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
                _catalog = catalog;
                ContextFingerprint = catalog.Fingerprint;
            }
        }

        public IAssemblyResolver CreateResolver()
        {
            ResolverCatalog catalog;
            lock (_sync)
            {
                if (_catalog == null)
                {
                    _catalog = AssemblyResolverCatalogBuilder.Build(GetStableRoots());
                    ContextFingerprint = _catalog.Fingerprint;
                }

                catalog = _catalog;
            }

            // Return a fresh resolver for each scan/read context so Cecil resolution state
            // cannot bleed between different plugins that bundle private assemblies with
            // the same identity.
            return new IndexedAssemblyResolver(catalog, _telemetry);
        }

        protected abstract IEnumerable<ResolverRoot> GetStableRoots();
    }
}
