using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
#if MLVSCAN_PROFILING
using System.Text.Json;
#endif

namespace MLVScan.Services.Diagnostics
{
    internal sealed class LoaderScanTelemetryHub
    {
        private LoaderScanProfileSnapshot _lastSnapshot;

#if MLVSCAN_PROFILING
        private LoaderScanProfileSession _session;
#endif

        public void BeginRun(string runId)
        {
#if MLVSCAN_PROFILING
            _session = new LoaderScanProfileSession(runId);
#else
            _ = runId;
#endif
            _lastSnapshot = null;
        }

        public long StartTimestamp()
        {
#if MLVSCAN_PROFILING
            return Stopwatch.GetTimestamp();
#else
            return 0;
#endif
        }

        public void AddPhaseElapsed(string phaseName, long startTimestamp)
        {
#if MLVSCAN_PROFILING
            if (_session == null || startTimestamp == 0)
            {
                return;
            }

            _session.AddPhaseElapsed(phaseName, Stopwatch.GetTimestamp() - startTimestamp);
#else
            _ = phaseName;
            _ = startTimestamp;
#endif
        }

        public void IncrementCounter(string counterName, long delta = 1)
        {
#if MLVSCAN_PROFILING
            if (_session == null)
            {
                return;
            }

            _session.IncrementCounter(counterName, delta);
#else
            _ = counterName;
            _ = delta;
#endif
        }

        public void RecordFileSample(string filePath, long startTimestamp, string action, long bytesRead, int findingsCount)
        {
#if MLVSCAN_PROFILING
            if (_session == null || startTimestamp == 0)
            {
                return;
            }

            _session.AddFileSample(filePath, Stopwatch.GetTimestamp() - startTimestamp, action, bytesRead, findingsCount);
#else
            _ = filePath;
            _ = startTimestamp;
            _ = action;
            _ = bytesRead;
            _ = findingsCount;
#endif
        }

        public void CompleteRun(int rootsScanned, int candidateFiles, int flaggedFiles)
        {
#if MLVSCAN_PROFILING
            if (_session == null)
            {
                return;
            }

            _session.IncrementCounter("Roots.Scanned", rootsScanned);
            _session.IncrementCounter("Files.Candidates", candidateFiles);
            _session.IncrementCounter("Files.Flagged", flaggedFiles);
            _session.TotalElapsedTicks = Stopwatch.GetTimestamp() - _session.StartTimestamp;
            _lastSnapshot = _session.ToSnapshot();
            _session = null;
#else
            _ = rootsScanned;
            _ = candidateFiles;
            _ = flaggedFiles;
#endif
        }

        public LoaderScanProfileSnapshot GetLastSnapshot()
        {
            return _lastSnapshot;
        }

        public string TryWriteArtifact(string diagnosticsDirectory)
        {
#if MLVSCAN_PROFILING
            if (_lastSnapshot == null)
            {
                return null;
            }

            Directory.CreateDirectory(diagnosticsDirectory);
            var path = Path.Combine(diagnosticsDirectory, $"loader-scan-profile-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
            var json = JsonSerializer.Serialize(_lastSnapshot, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(path, json);
            return path;
#else
            _ = diagnosticsDirectory;
            return null;
#endif
        }
    }

    internal sealed class LoaderScanProfileSnapshot
    {
        public string RunId { get; set; } = string.Empty;

        public long TotalElapsedTicks { get; set; }

        public IReadOnlyList<LoaderScanPhaseTiming> Phases { get; set; } = Array.Empty<LoaderScanPhaseTiming>();

        public IReadOnlyDictionary<string, long> Counters { get; set; } = new Dictionary<string, long>(StringComparer.Ordinal);

        public IReadOnlyList<LoaderScanFileSample> SlowFiles { get; set; } = Array.Empty<LoaderScanFileSample>();
    }

    internal sealed class LoaderScanPhaseTiming
    {
        public string Name { get; set; } = string.Empty;

        public long ElapsedTicks { get; set; }

        public int Count { get; set; }
    }

    internal sealed class LoaderScanFileSample
    {
        public string FilePath { get; set; } = string.Empty;

        public long ElapsedTicks { get; set; }

        public string Action { get; set; } = string.Empty;

        public long BytesRead { get; set; }

        public int FindingsCount { get; set; }
    }

#if MLVSCAN_PROFILING
    internal sealed class LoaderScanProfileSession
    {
        private const int MaxSlowFiles = 20;

        private readonly Dictionary<string, LoaderPhaseAccumulator> _phases = new Dictionary<string, LoaderPhaseAccumulator>(StringComparer.Ordinal);
        private readonly Dictionary<string, long> _counters = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly List<LoaderScanFileSample> _files = new List<LoaderScanFileSample>();

        public LoaderScanProfileSession(string runId)
        {
            RunId = runId;
            StartTimestamp = Stopwatch.GetTimestamp();
        }

        public string RunId { get; }

        public long StartTimestamp { get; }

        public long TotalElapsedTicks { get; set; }

        public void AddPhaseElapsed(string phaseName, long elapsedTicks)
        {
            if (!_phases.TryGetValue(phaseName, out var accumulator))
            {
                accumulator = new LoaderPhaseAccumulator();
                _phases[phaseName] = accumulator;
            }

            accumulator.ElapsedTicks += elapsedTicks;
            accumulator.Count++;
        }

        public void IncrementCounter(string counterName, long delta)
        {
            _counters[counterName] = _counters.TryGetValue(counterName, out var current)
                ? current + delta
                : delta;
        }

        public void AddFileSample(string filePath, long elapsedTicks, string action, long bytesRead, int findingsCount)
        {
            _files.Add(new LoaderScanFileSample
            {
                FilePath = filePath,
                ElapsedTicks = elapsedTicks,
                Action = action,
                BytesRead = bytesRead,
                FindingsCount = findingsCount
            });
        }

        public LoaderScanProfileSnapshot ToSnapshot()
        {
            return new LoaderScanProfileSnapshot
            {
                RunId = RunId,
                TotalElapsedTicks = TotalElapsedTicks,
                Phases = _phases
                    .OrderByDescending(static pair => pair.Value.ElapsedTicks)
                    .Select(static pair => new LoaderScanPhaseTiming
                    {
                        Name = pair.Key,
                        ElapsedTicks = pair.Value.ElapsedTicks,
                        Count = pair.Value.Count
                    })
                    .ToArray(),
                Counters = new Dictionary<string, long>(_counters, StringComparer.Ordinal),
                SlowFiles = _files
                    .OrderByDescending(static sample => sample.ElapsedTicks)
                    .Take(MaxSlowFiles)
                    .ToArray()
            };
        }
    }

    internal sealed class LoaderPhaseAccumulator
    {
        public long ElapsedTicks { get; set; }

        public int Count { get; set; }
    }
#endif
}
