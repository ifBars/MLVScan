using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace MLVScan.Services.Resolution
{
    internal static class AssemblyResolverCatalogBuilder
    {
        public static ResolverCatalog Build(IEnumerable<ResolverRoot> roots)
        {
            var candidates = new List<ResolverCatalogCandidate>();
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var fingerprintLines = new List<string>();

            foreach (var root in roots
                         .Where(static root => !string.IsNullOrWhiteSpace(root.Path) && Directory.Exists(root.Path))
                         .OrderBy(static root => root.Priority)
                         .ThenBy(static root => root.Path, StringComparer.OrdinalIgnoreCase))
            {
                foreach (var path in Directory.EnumerateFiles(root.Path, "*", SearchOption.AllDirectories)
                             .Where(IsAssemblyLike))
                {
                    var fullPath = Path.GetFullPath(path);
                    if (!seenPaths.Add(fullPath))
                    {
                        continue;
                    }

                    if (!TryReadAssemblyIdentity(fullPath, out var candidate))
                    {
                        continue;
                    }

                    candidate.Priority = root.Priority;
                    candidates.Add(candidate);

                    var fileInfo = new FileInfo(fullPath);
                    fingerprintLines.Add(
                        $"{candidate.SimpleName}|{candidate.Version}|{candidate.PublicKeyToken}|{root.Priority}|{fullPath}|{fileInfo.Length}|{fileInfo.LastWriteTimeUtc.Ticks}");
                }
            }

            var grouped = candidates
                .GroupBy(candidate => candidate.SimpleName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => (IReadOnlyList<ResolverCatalogCandidate>)group
                        .OrderBy(candidate => candidate.Priority)
                        .ThenBy(candidate => candidate.Path, StringComparer.OrdinalIgnoreCase)
                        .ToArray(),
                    StringComparer.OrdinalIgnoreCase);

            return new ResolverCatalog
            {
                Fingerprint = ComputeFingerprint(fingerprintLines),
                CandidatesBySimpleName = grouped
            };
        }

        private static bool TryReadAssemblyIdentity(string path, out ResolverCatalogCandidate candidate)
        {
            candidate = null;

            try
            {
                var assemblyName = AssemblyName.GetAssemblyName(path);
                candidate = new ResolverCatalogCandidate
                {
                    SimpleName = assemblyName.Name ?? string.Empty,
                    FullName = assemblyName.FullName ?? string.Empty,
                    Version = assemblyName.Version?.ToString() ?? string.Empty,
                    PublicKeyToken = FormatPublicKeyToken(assemblyName.GetPublicKeyToken()),
                    Path = path
                };

                return !string.IsNullOrWhiteSpace(candidate.SimpleName);
            }
            catch
            {
                return false;
            }
        }

        private static string ComputeFingerprint(IEnumerable<string> lines)
        {
            var payload = string.Join("\n", lines.OrderBy(static line => line, StringComparer.Ordinal));
            return Services.HashUtility.CalculateBytesHash(Encoding.UTF8.GetBytes(payload));
        }

        private static string FormatPublicKeyToken(byte[] token)
        {
            if (token == null || token.Length == 0)
            {
                return string.Empty;
            }

            return BitConverter.ToString(token).Replace("-", string.Empty).ToLowerInvariant();
        }

        private static bool IsAssemblyLike(string path)
        {
            var extension = Path.GetExtension(path);
            return extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                   || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                   || extension.Equals(".winmd", StringComparison.OrdinalIgnoreCase);
        }
    }
}
