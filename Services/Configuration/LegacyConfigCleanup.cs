using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MLVScan.Services.Configuration;

/// <summary>
/// Removes stale configuration keys that are no longer part of the runtime config contract.
/// </summary>
public static class LegacyConfigCleanup
{
    private static readonly string[] ObsoleteConfigKeys =
    [
        "DisableThreshold",
        "MinSeverityForDisable",
        "SuspiciousThreshold"
    ];

    public static bool TryRemoveObsoleteIniEntries(string filePath, string sectionName, out string[] removedKeys)
    {
        removedKeys = Array.Empty<string>();

        if (string.IsNullOrWhiteSpace(filePath) ||
            string.IsNullOrWhiteSpace(sectionName) ||
            !File.Exists(filePath))
        {
            return false;
        }

        var removed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var outputLines = new List<string>();
        var inTargetSection = false;
        var changed = false;

        foreach (var line in File.ReadAllLines(filePath))
        {
            var trimmed = line.Trim();
            if (TryGetSectionName(trimmed, out var currentSection))
            {
                inTargetSection = string.Equals(currentSection, sectionName, StringComparison.OrdinalIgnoreCase);
                outputLines.Add(line);
                continue;
            }

            if (inTargetSection &&
                TryGetIniKey(trimmed, out var key) &&
                ObsoleteConfigKeys.Contains(key, StringComparer.OrdinalIgnoreCase))
            {
                removed.Add(key);
                changed = true;
                continue;
            }

            outputLines.Add(line);
        }

        if (!changed)
        {
            return false;
        }

        File.WriteAllLines(filePath, outputLines);
        removedKeys = removed.OrderBy(static key => key, StringComparer.OrdinalIgnoreCase).ToArray();
        return true;
    }

    private static bool TryGetSectionName(string line, out string sectionName)
    {
        sectionName = string.Empty;
        if (line.Length < 3 || line[0] != '[' || line[^1] != ']')
        {
            return false;
        }

        sectionName = line[1..^1].Trim();
        return !string.IsNullOrWhiteSpace(sectionName);
    }

    private static bool TryGetIniKey(string line, out string key)
    {
        key = string.Empty;
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith(";") || line.StartsWith("#"))
        {
            return false;
        }

        var separatorIndex = line.IndexOf('=');
        if (separatorIndex <= 0)
        {
            return false;
        }

        key = line[..separatorIndex].Trim();
        return !string.IsNullOrWhiteSpace(key);
    }
}
