using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MLVScan.Services.Resolution
{
    internal static class AssemblyResolverCatalogBuilder
    {
        public static ResolverCatalog Build(IEnumerable<ResolverRoot> roots)
        {
            var candidates = new List<ResolverCatalogCandidate>();
            var seenPaths = new HashSet<string>(StringComparer.Ordinal);
            var fingerprintLines = new List<string>();

            foreach (var root in roots
                         .Where(static root => !string.IsNullOrWhiteSpace(root.Path) && Directory.Exists(root.Path))
                         .OrderBy(static root => root.Priority)
                         .ThenBy(root => GetComparisonKey(root.Path), StringComparer.Ordinal))
            {
                foreach (var path in EnumerateAssemblyPaths(root.Path))
                {
                    try
                    {
                        var fullPath = Path.GetFullPath(path);
                        var comparisonKey = GetComparisonKey(fullPath);
                        if (!seenPaths.Add(comparisonKey))
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
                        var contentFingerprint = ComputeContentFingerprint(fullPath);
                        fingerprintLines.Add(
                            $"{candidate.SimpleName}|{candidate.Version}|{candidate.PublicKeyToken}|{root.Priority}|{comparisonKey}|{fileInfo.Length}|{fileInfo.LastWriteTimeUtc.Ticks}|{contentFingerprint}");
                    }
                    catch (UnauthorizedAccessException)
                    {
                        continue;
                    }
                    catch (FileNotFoundException)
                    {
                        continue;
                    }
                    catch (DirectoryNotFoundException)
                    {
                        continue;
                    }
                    catch (IOException)
                    {
                        continue;
                    }
                }
            }

            var grouped = candidates
                .GroupBy(candidate => candidate.SimpleName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => (IReadOnlyList<ResolverCatalogCandidate>)group
                        .OrderBy(candidate => candidate.Priority)
                        .ThenBy(candidate => GetComparisonKey(candidate.Path), StringComparer.Ordinal)
                        .ToArray(),
                    StringComparer.OrdinalIgnoreCase);

            return ResolverCatalog.Create(ComputeFingerprint(fingerprintLines), grouped);
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

        private static string ComputeContentFingerprint(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
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

        private static IEnumerable<string> EnumerateAssemblyPaths(string rootPath)
        {
            IEnumerator<string> enumerator;
            try
            {
                enumerator = Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories).GetEnumerator();
            }
            catch (UnauthorizedAccessException)
            {
                yield break;
            }
            catch (FileNotFoundException)
            {
                yield break;
            }
            catch (DirectoryNotFoundException)
            {
                yield break;
            }
            catch (IOException)
            {
                yield break;
            }

            using (enumerator)
            {
                while (true)
                {
                    string current;
                    try
                    {
                        if (!enumerator.MoveNext())
                        {
                            yield break;
                        }

                        current = enumerator.Current;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        continue;
                    }
                    catch (FileNotFoundException)
                    {
                        continue;
                    }
                    catch (DirectoryNotFoundException)
                    {
                        continue;
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    if (IsAssemblyLike(current))
                    {
                        yield return current;
                    }
                }
            }
        }

        private static string GetComparisonKey(string path)
        {
            var fullPath = Path.GetFullPath(path);
            return GetPathComparerForRoot(fullPath) == StringComparer.OrdinalIgnoreCase
                ? fullPath.ToUpperInvariant()
                : fullPath;
        }

        private static StringComparer GetPathComparerForRoot(string pathRoot)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return StringComparer.OrdinalIgnoreCase;
            }

            var probePath = FindExistingPathForSensitivityProbe(pathRoot);
            if (string.IsNullOrWhiteSpace(probePath))
            {
                return StringComparer.Ordinal;
            }

            var alternateCasePath = GetAlternateCasePath(probePath);
            if (string.Equals(alternateCasePath, probePath, StringComparison.Ordinal))
            {
                return StringComparer.Ordinal;
            }

            return File.Exists(alternateCasePath) || Directory.Exists(alternateCasePath)
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal;
        }

        private static string FindExistingPathForSensitivityProbe(string path)
        {
            var current = Path.GetFullPath(path);
            while (!string.IsNullOrWhiteSpace(current))
            {
                if (File.Exists(current) || Directory.Exists(current))
                {
                    return current;
                }

                current = Path.GetDirectoryName(current);
            }

            return string.Empty;
        }

        private static string GetAlternateCasePath(string path)
        {
            var chars = path.ToCharArray();
            for (var i = 0; i < chars.Length; i++)
            {
                if (!char.IsLetter(chars[i]))
                {
                    continue;
                }

                chars[i] = char.IsUpper(chars[i])
                    ? char.ToLowerInvariant(chars[i])
                    : char.ToUpperInvariant(chars[i]);
                break;
            }

            return new string(chars);
        }
    }
}
