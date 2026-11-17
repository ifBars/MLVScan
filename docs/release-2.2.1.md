# MLVScan 2.2.1

- Includes Core 1.10.1, fixing incomplete scans with older Cecil runtimes and improving completion of large managed assemblies.
- Improves incomplete-scan diagnostics and reduces unrelated data-flow signals from assembly-name lookups and file timestamp getters.
- Adds consent-gated diagnostics for accepted, failed, and skipped private uploads using fixed outcome categories. These diagnostics do not include sample identities or server response bodies.
- Stops retrying permanent private-upload rejections and records when optional uploads are skipped during preparation.

Available for MelonLoader, BepInEx 5, BepInEx 6 Mono, and BepInEx 6 IL2CPP. Local scanning remains independent of optional sharing. The 64 MiB private-upload limit and internal analysis safeguards remain in place; very large assemblies may still require substantial memory and time.
