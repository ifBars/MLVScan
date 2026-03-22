namespace MLVScan.Services.Caching
{
    internal interface IScanCacheSigner
    {
        bool CanTrustCleanEntries { get; }

        string Sign(string payloadJson);

        bool Verify(string payloadJson, string signature);
    }
}
