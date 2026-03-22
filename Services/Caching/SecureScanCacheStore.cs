using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace MLVScan.Services.Caching
{
    internal sealed class SecureScanCacheStore : IScanCacheStore
    {
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false
        };

        private readonly Dictionary<string, ScanCacheEntry> _entriesByPath = new Dictionary<string, ScanCacheEntry>(GetPathComparer());
        private readonly Dictionary<string, ScanCacheEntry> _entriesByHash = new Dictionary<string, ScanCacheEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly IScanCacheSigner _signer;
        private readonly string _entriesDirectory;

        public SecureScanCacheStore(string cacheDirectory, IScanCacheSigner signer)
        {
            _signer = signer ?? throw new ArgumentNullException(nameof(signer));
            _entriesDirectory = Path.Combine(cacheDirectory ?? throw new ArgumentNullException(nameof(cacheDirectory)), "entries");
            Directory.CreateDirectory(_entriesDirectory);
            LoadEntries();
        }

        public bool CanTrustCleanEntries => _signer.CanTrustCleanEntries;

        public ScanCacheEntry TryGetByPath(string canonicalPath)
        {
            if (string.IsNullOrWhiteSpace(canonicalPath))
            {
                return null;
            }

            _entriesByPath.TryGetValue(NormalizePathKey(canonicalPath), out var entry);
            return entry;
        }

        public ScanCacheEntry TryGetByHash(string sha256Hash)
        {
            if (string.IsNullOrWhiteSpace(sha256Hash))
            {
                return null;
            }

            _entriesByHash.TryGetValue(sha256Hash, out var entry);
            return entry;
        }

        public void Upsert(ScanCacheEntry entry)
        {
            if (entry == null || string.IsNullOrWhiteSpace(entry.CanonicalPath))
            {
                return;
            }

            entry.CreatedUtc = entry.CreatedUtc == default ? DateTime.UtcNow : entry.CreatedUtc;
            entry.VerifiedUtc = DateTime.UtcNow;

            var payload = ScanCacheEntryPayload.FromEntry(entry);
            var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
            var envelope = new ScanCacheEnvelope
            {
                Signature = _signer.Sign(payloadJson),
                Payload = payload
            };

            var envelopeJson = JsonSerializer.Serialize(envelope, JsonOptions);
            AtomicFileStorage.WriteAllText(GetEntryFilePath(entry.CanonicalPath), envelopeJson);

            var normalizedPath = NormalizePathKey(entry.CanonicalPath);
            _entriesByPath[normalizedPath] = entry;
            if (!string.IsNullOrWhiteSpace(entry.Sha256))
            {
                _entriesByHash[entry.Sha256] = entry;
            }
        }

        public void Remove(string canonicalPath)
        {
            if (string.IsNullOrWhiteSpace(canonicalPath))
            {
                return;
            }

            var normalizedPath = NormalizePathKey(canonicalPath);
            if (_entriesByPath.TryGetValue(normalizedPath, out var existing))
            {
                _entriesByPath.Remove(normalizedPath);
                if (!string.IsNullOrWhiteSpace(existing.Sha256) &&
                    _entriesByHash.TryGetValue(existing.Sha256, out var hashEntry) &&
                    ReferenceEquals(hashEntry, existing))
                {
                    _entriesByHash.Remove(existing.Sha256);
                }
            }

            try
            {
                var path = GetEntryFilePath(canonicalPath);
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // Ignore cache cleanup failures.
            }
        }

        public void PruneMissingEntries(IReadOnlyCollection<string> activeCanonicalPaths)
        {
            var normalizedActive = new HashSet<string>(
                activeCanonicalPaths?.Select(NormalizePathKey) ?? Enumerable.Empty<string>(),
                GetPathComparer());

            foreach (var entryPath in _entriesByPath.Keys.ToArray())
            {
                if (normalizedActive.Contains(entryPath))
                {
                    continue;
                }

                Remove(entryPath);
            }
        }

        private void LoadEntries()
        {
            foreach (var path in Directory.EnumerateFiles(_entriesDirectory, "*.json", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var json = File.ReadAllText(path);
                    var envelope = JsonSerializer.Deserialize<ScanCacheEnvelope>(json, JsonOptions);
                    if (envelope?.Payload == null || envelope.SchemaVersion != 1)
                    {
                        DeleteCorruptEntry(path);
                        continue;
                    }

                    var payloadJson = JsonSerializer.Serialize(envelope.Payload, JsonOptions);
                    if (!_signer.Verify(payloadJson, envelope.Signature))
                    {
                        DeleteCorruptEntry(path);
                        continue;
                    }

                    var entry = envelope.Payload.ToEntry();
                    var normalizedPath = NormalizePathKey(entry.CanonicalPath);
                    _entriesByPath[normalizedPath] = entry;
                    if (!string.IsNullOrWhiteSpace(entry.Sha256))
                    {
                        _entriesByHash[entry.Sha256] = entry;
                    }
                }
                catch
                {
                    DeleteCorruptEntry(path);
                }
            }
        }

        private void DeleteCorruptEntry(string path)
        {
            try
            {
                File.Delete(path);
            }
            catch
            {
                // Ignore corrupt cache cleanup failures.
            }
        }

        private string GetEntryFilePath(string canonicalPath)
        {
            var key = HashUtility.CalculateBytesHash(Encoding.UTF8.GetBytes(NormalizePathKey(canonicalPath)));
            return Path.Combine(_entriesDirectory, $"{key}.json");
        }

        private static string NormalizePathKey(string path)
        {
            var normalized = Path.GetFullPath(path);
            return RuntimeInformationHelper.IsWindows
                ? normalized.ToLowerInvariant()
                : normalized;
        }

        private static StringComparer GetPathComparer()
        {
            return RuntimeInformationHelper.IsWindows
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal;
        }
    }
}
