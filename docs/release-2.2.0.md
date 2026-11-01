# MLVScan 2.2.0

MLVScan can now share opt-in scan diagnostics to help identify false positives and incomplete analysis. Scanning remains local and works without sharing.

- A refreshed, one-time sharing prompt appears for both new users and people who answered the previous prompt. Basic diagnostics and optional private sample sharing are explained together; no data is sent before the new choice.
- Basic diagnostics report aggregate outcomes, allowlisted detection rules, threat families, and incomplete-analysis signals. They contain no filenames, file hashes, paths, evidence text, or persistent user identifier. Counts represent scan observations, not unique users.
- If file sharing is enabled, flagged and incomplete samples can be submitted privately for review. A returned reference links successful submissions to their receipt events. Samples are not published or redistributed. The loader currently accepts optional sample uploads up to 64 MiB; larger files stay local.
- Native local scans no longer have a file-size cutoff. Files are hashed and analyzed from the same open stream. Internal analysis safeguards remain; unrestricted file size is not a guarantee of bounded runtime or memory consumption.
- Includes Core 1.10.0, with shared telemetry projections and consistent incomplete-scan interpretation. Core itself sends no telemetry, and general API consumers are not enrolled.
- One MelonLoader DLL supports Mono and IL2CPP. BepInEx retains separate 5, 6 Mono, and 6 IL2CPP packages.

Sharing preferences are saved locally and can be changed later in configuration. Browser limits are unchanged.
