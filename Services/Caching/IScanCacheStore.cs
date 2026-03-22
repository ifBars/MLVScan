namespace MLVScan.Services.Caching
{
    internal interface IScanCacheStore
    {
        bool CanTrustCleanEntries { get; }

        ScanCacheEntry TryGetByPath(string canonicalPath);

        ScanCacheEntry TryGetByHash(string sha256Hash);

        void Upsert(ScanCacheEntry entry);

        void Remove(string canonicalPath);

        void PruneMissingEntries(System.Collections.Generic.IReadOnlyCollection<string> activeCanonicalPaths);
    }
}
