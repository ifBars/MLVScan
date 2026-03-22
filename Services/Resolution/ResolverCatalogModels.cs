using System;
using System.Collections.Generic;
using System.Linq;

namespace MLVScan.Services.Resolution
{
    internal sealed class ResolverCatalog
    {
        public static readonly ResolverCatalog Empty = new ResolverCatalog
        {
            Fingerprint = "empty",
            CandidatesBySimpleName = new Dictionary<string, IReadOnlyList<ResolverCatalogCandidate>>(StringComparer.OrdinalIgnoreCase)
        };

        public string Fingerprint { get; set; } = "empty";

        public IReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>> CandidatesBySimpleName { get; set; } =
            new Dictionary<string, IReadOnlyList<ResolverCatalogCandidate>>(StringComparer.OrdinalIgnoreCase);
    }

    internal sealed class ResolverCatalogCandidate
    {
        public string SimpleName { get; set; } = string.Empty;

        public string FullName { get; set; } = string.Empty;

        public string Version { get; set; } = string.Empty;

        public string PublicKeyToken { get; set; } = string.Empty;

        public string Path { get; set; } = string.Empty;

        public int Priority { get; set; }
    }

    public readonly struct ResolverRoot
    {
        public ResolverRoot(string path, int priority)
        {
            Path = path;
            Priority = priority;
        }

        public string Path { get; }

        public int Priority { get; }
    }
}
