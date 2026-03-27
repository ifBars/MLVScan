using System.IO;

namespace MLVScan.Services.Caching
{
    internal interface IFileIdentityProvider
    {
        FileProbe OpenProbe(string path);
    }

    internal sealed class FileProbe : IDisposable
    {
        public FileProbe(
            string originalPath,
            string canonicalPath,
            FileStream stream,
            FileIdentitySnapshot identity,
            bool isSymlinkOrReparsePoint)
        {
            OriginalPath = originalPath;
            CanonicalPath = canonicalPath;
            Stream = stream;
            Identity = identity;
            IsSymlinkOrReparsePoint = isSymlinkOrReparsePoint;
        }

        public string OriginalPath { get; }

        public string CanonicalPath { get; }

        public FileStream Stream { get; }

        public FileIdentitySnapshot Identity { get; }

        public bool IsSymlinkOrReparsePoint { get; }

        public bool CanReuseByStrongIdentity =>
            !IsSymlinkOrReparsePoint &&
            Identity.HasStrongIdentity;

        public void Dispose()
        {
            Stream.Dispose();
        }
    }

    internal sealed class FileIdentitySnapshot
    {
        public string Platform { get; set; } = string.Empty;

        public bool HasStrongIdentity { get; set; }

        public string IdentityKey { get; set; } = string.Empty;

        public long Size { get; set; }

        public long LastWriteUtcTicks { get; set; }

        public long ChangeUtcTicks { get; set; }

        public bool IsSymlinkOrReparsePoint { get; set; }

        public bool MatchesStrongIdentity(FileIdentitySnapshot other)
        {
            if (other == null ||
                !HasStrongIdentity ||
                !other.HasStrongIdentity)
            {
                return false;
            }

            return string.Equals(Platform, other.Platform, System.StringComparison.Ordinal) &&
                   string.Equals(IdentityKey, other.IdentityKey, System.StringComparison.Ordinal) &&
                   Size == other.Size &&
                   LastWriteUtcTicks == other.LastWriteUtcTicks &&
                   ChangeUtcTicks == other.ChangeUtcTicks &&
                   IsSymlinkOrReparsePoint == other.IsSymlinkOrReparsePoint;
        }
    }
}
