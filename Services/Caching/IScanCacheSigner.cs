namespace MLVScan.Services.Caching
{
    internal interface IScanCacheSigner
    {
        bool CanTrustCleanEntries { get; }

        string Sign(byte[] payloadBytes);

        bool Verify(byte[] payloadBytes, string signature);
    }
}
