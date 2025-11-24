namespace MLVScan.Models
{
    public class DisabledModInfo
    {
        public string OriginalPath { get; }
        public string DisabledPath { get; }
        public string FileHash { get; }

        public DisabledModInfo(string originalPath, string disabledPath, string fileHash)
        {
            OriginalPath = originalPath;
            DisabledPath = disabledPath;
            FileHash = fileHash;
        }
    }
}
