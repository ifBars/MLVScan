using MLVScan.Models;
using MLVScan.Services.Caching;

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
        var roots = new HashSet<string>(GetPathComparer());

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

            if (IsResolverOnlyPath(normalized) || IsUnderAny(normalized, config.ExcludedTargetRoots))
            {
                continue;
            }

            roots.Add(normalized);
        }

        return roots.OrderBy(root => root, GetPathComparer()).ToList();
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

        if (IsResolverOnlyPath(fullPath) || IsUnderAny(fullPath, config.ExcludedTargetRoots))
        {
            return false;
        }

        return effectiveRoots.Any(root => IsUnderRoot(fullPath, root));
    }

    private static bool IsResolverOnlyPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var pathSegments = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        return ResolverOnlySegmentSequences.Any(sequence => ContainsSegmentSequence(pathSegments, sequence));
    }

    private static bool ContainsSegmentSequence(IReadOnlyList<string> pathSegments, IReadOnlyList<string> candidateSegments)
    {
        if (pathSegments.Count < candidateSegments.Count)
        {
            return false;
        }

        for (var startIndex = 0; startIndex <= pathSegments.Count - candidateSegments.Count; startIndex++)
        {
            var matches = true;
            for (var i = 0; i < candidateSegments.Count; i++)
            {
                if (!SegmentMatches(pathSegments[startIndex + i], candidateSegments[i]))
                {
                    matches = false;
                    break;
                }
            }

            if (matches)
            {
                return true;
            }
        }

        return false;
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

        var pathComparison = GetPathComparison();
        return fullPath.StartsWith(normalizedRoot, pathComparison)
               || string.Equals(fullPath, root, pathComparison);
    }

    private static string Normalize(string path)
    {
        return Path.GetFullPath(path);
    }

    private static StringComparer GetPathComparer()
    {
        return RuntimeInformationHelper.IsWindows || RuntimeInformationHelper.IsMacOs
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
    }

    private static StringComparison GetPathComparison()
    {
        return RuntimeInformationHelper.IsWindows || RuntimeInformationHelper.IsMacOs
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
    }
}
