using MLVScan.Models;

namespace MLVScan.Services.Scope;

/// <summary>
/// Shared scope filter for mod-loader host integrations.
/// Enforces target-only scan boundaries and excludes resolver/runtime locations.
/// </summary>
public sealed class TargetAssemblyScopeFilter
{
    private static readonly string[] ResolverOnlySegments =
    [
        "_Data\\Managed",
        "MelonLoader\\Managed",
        "MelonLoader\\net35",
        "MelonLoader\\net6",
        "BepInEx\\core",
        "BepInEx\\cache",
        "BepInEx\\interop",
        ".nuget\\packages",
        "dotnet\\shared"
    ];

    public IReadOnlyList<string> BuildEffectiveRoots(IEnumerable<string> candidateRoots, ScanScopeConfig scope)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in candidateRoots.Concat(scope.AdditionalTargetRoots))
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

            if (IsResolverOnlyPath(normalized) || IsUnderAny(normalized, scope.ExcludedTargetRoots))
            {
                continue;
            }

            roots.Add(normalized);
        }

        return roots.OrderBy(root => root, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public bool IsTargetAssembly(string assemblyPath, IReadOnlyCollection<string> effectiveRoots, ScanScopeConfig scope)
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

        if (IsResolverOnlyPath(fullPath) || IsUnderAny(fullPath, scope.ExcludedTargetRoots))
        {
            return false;
        }

        return effectiveRoots.Any(root => IsUnderRoot(fullPath, root));
    }

    private static bool IsResolverOnlyPath(string path)
    {
        return ResolverOnlySegments.Any(segment =>
            path.IndexOf(segment, StringComparison.OrdinalIgnoreCase) >= 0);
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
