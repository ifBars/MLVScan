using System.Collections.Generic;

namespace MLVScan.Services.Resolution
{
    internal interface IResolverCatalogProvider
    {
        string ContextFingerprint { get; }

        void BuildCatalog(IEnumerable<string> targetRoots);
    }
}
