using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace MLVScan.Services.Resolution
{
    internal sealed class ResolverCatalog
    {
        private static readonly IReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>> EmptyCandidates =
            new ReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>>(
                new Dictionary<string, IReadOnlyList<ResolverCatalogCandidate>>(StringComparer.OrdinalIgnoreCase));

        private ResolverCatalog(
            string fingerprint,
            IReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>> candidatesBySimpleName)
        {
            Fingerprint = string.IsNullOrWhiteSpace(fingerprint) ? "empty" : fingerprint;
            CandidatesBySimpleName = candidatesBySimpleName ?? EmptyCandidates;
        }

        public static ResolverCatalog Empty { get; } = new ResolverCatalog("empty", EmptyCandidates);

        public string Fingerprint { get; }

        public IReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>> CandidatesBySimpleName { get; }

        public static ResolverCatalog Create(
            string fingerprint,
            IReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>> candidatesBySimpleName)
        {
            return new ResolverCatalog(
                fingerprint,
                candidatesBySimpleName == null
                    ? EmptyCandidates
                    : new ReadOnlyDictionary<string, IReadOnlyList<ResolverCatalogCandidate>>(
                        new Dictionary<string, IReadOnlyList<ResolverCatalogCandidate>>(candidatesBySimpleName, StringComparer.OrdinalIgnoreCase)));
        }
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
