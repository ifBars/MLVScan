using MLVScan.Models;

namespace MLVScan.Services.Scope;

/// <summary>
/// Shared scope filter for mod-loader host integrations.
/// Enforces target-only scan boundaries and excludes resolver/runtime locations.
/// </summary>
public sealed class TargetAssemblyScopeFilter
{
    private static readonly string[][] ResolverOnlySegmentSequences =
    [
        ["*_Data", "Managed"],
        ["MelonLoader", "Managed"],
        ["MelonLoader", "net35"],
        ["MelonLoader", "net6"],
        ["BepInEx", "core"],
        ["BepInEx", "cache"],
        ["BepInEx", "interop"],
        [".nuget", "packages"],
        ["dotnet", "shared"]
    ];

    public IReadOnlyList<string> BuildEffectiveRoots(IEnumerable<string> candidateRoots, MLVScanConfig config)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in candidateRoots.Concat(config.AdditionalTargetRoots))
        {
            if (string.IsNullOrWhiteSpace(root))
            {
                continue;
            }

            var normalized = Normalize(root);
            if (!Directory.Exists(normalized))
            {
                continue;
            }

            if (IsResolverOnlyRoot(normalized) || IsUnderAny(normalized, config.ExcludedTargetRoots))
            {
                continue;
            }

            roots.Add(normalized);
        }

        return roots.OrderBy(root => root, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public bool IsTargetAssembly(string assemblyPath, IReadOnlyCollection<string> effectiveRoots, MLVScanConfig config)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath))
        {
            return false;
        }

        if (!assemblyPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var fullPath = Normalize(assemblyPath);
        if (!File.Exists(fullPath))
        {
            return false;
        }

        if (IsResolverOnlyPath(fullPath, effectiveRoots) || IsUnderAny(fullPath, config.ExcludedTargetRoots))
        {
            return false;
        }

        return effectiveRoots.Any(root => IsUnderRoot(fullPath, root));
    }

    private static bool IsResolverOnlyRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var pathSegments = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        return ResolverOnlySegmentSequences.Any(sequence => EndsWithSegmentSequence(pathSegments, sequence));
    }

    private static bool IsResolverOnlyPath(string path, IEnumerable<string> effectiveRoots)
    {
        foreach (var root in effectiveRoots)
        {
            if (string.IsNullOrWhiteSpace(root))
            {
                continue;
            }

            var normalizedRoot = Normalize(root);
            if (!IsUnderRoot(path, normalizedRoot))
            {
                continue;
            }

            var rootSegments = normalizedRoot.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
            if (ResolverOnlySegmentSequences.Any(sequence => ContainsSegmentSequence(rootSegments, sequence)))
            {
                return true;
            }

            var relativePath = Path.GetRelativePath(normalizedRoot, path);
            var relativeSegments = relativePath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
            if (ResolverOnlySegmentSequences.Any(sequence => ContainsSegmentSequence(relativeSegments, sequence)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsSegmentSequence(IReadOnlyList<string> pathSegments, IReadOnlyList<string> candidateSegments)
    {
        if (pathSegments.Count < candidateSegments.Count)
        {
            return false;
        }

        for (var i = 0; i <= pathSegments.Count - candidateSegments.Count; i++)
        {
            var matched = true;

            for (var j = 0; j < candidateSegments.Count; j++)
            {
                if (!SegmentMatches(pathSegments[i + j], candidateSegments[j]))
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    private static bool EndsWithSegmentSequence(IReadOnlyList<string> pathSegments, IReadOnlyList<string> candidateSegments)
    {
        if (pathSegments.Count < candidateSegments.Count)
        {
            return false;
        }

        var startIndex = pathSegments.Count - candidateSegments.Count;
        for (var i = 0; i < candidateSegments.Count; i++)
        {
            if (!SegmentMatches(pathSegments[startIndex + i], candidateSegments[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SegmentMatches(string actualSegment, string candidateSegment)
    {
        if (candidateSegment.StartsWith("*", StringComparison.Ordinal))
        {
            return actualSegment.EndsWith(candidateSegment.Substring(1), StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(actualSegment, candidateSegment, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUnderAny(string fullPath, IEnumerable<string> roots)
    {
        foreach (var root in roots)
        {
            if (string.IsNullOrWhiteSpace(root))
            {
                continue;
            }

            if (IsUnderRoot(fullPath, Normalize(root)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsUnderRoot(string fullPath, string root)
    {
        var normalizedRoot = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;

        return fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase)
               || string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path)
    {
        return Path.GetFullPath(path);
    }
}
