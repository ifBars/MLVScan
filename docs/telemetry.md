# Optional telemetry

MLVScan scans files locally. Optional telemetry sends bounded scan diagnostics to help improve MLVScan.
It is off by default. File uploads are a separate choice.

## What is sent

After a completed scan run, MLVScan can send the number of clean, suspicious, known-threat,
manual-review, failed, and unknown results to PostHog. The event includes an environment label,
the telemetry format version, Core/plugin/loader versions, and a new random identifier for that run.
Schema 3 includes fresh/cached and complete/incomplete counts; allowlisted rule/severity/visibility/outcome
groups; family match basis and family IDs; and structured data-flow pattern categories. The Core
projection is pure and capped at 192 groups plus an overflow counter. Missing counters mean zero
only when overflow is absent. Unknown identifiers map to fixed categories. Cached results count
as observations too. There is no lasting installation or user identifier.

Files, filenames, file hashes, paths, code, detailed findings, game names, and account details
are not included. The counts are selected locally before sending. Person-profile creation and
location enrichment are disabled. PostHog still receives the network connection's IP address,
as any directly contacted service does; the event's IP property is set to `0.0.0.0`.

## Your choice

`EnableAnonymousTelemetry` controls these counts and defaults to `false`. Turning it off stops
new telemetry. A request already sent cannot be recalled. Scanning continues when telemetry is
off, when you are offline, or when delivery fails. `EnableReportUpload` separately controls the
private-review upload flow; neither setting enables the other.

The first launch shows one combined sharing prompt with **No thanks**, **Allow sharing**, and
**Learn more**. An optional checkbox enables flagged-file uploads. New users start with that
checkbox off; existing users see their previous file-upload preference. No thanks turns both
choices off; Allow sharing enables basic diagnostics and enables uploads only when checked.

Consent version 3 is required for both outbound paths. Everyone with an older decision, including
previous acceptances and refusals, sees the revised prompt once. Until that decision is saved,
neither analytics nor files are sent. The decision and UTC timestamp are persisted. Later launches
do not ask again. The two configuration settings can still be changed independently afterward.

## Native UI verification

The shared prompt runs through each loader's Unity GUI callback. A fixed UI bridge resolves the
host Unity types at runtime, including IL2CPP proxy delegates. Release builds use public compile
references and published Core 1.10.0; no game-generated assemblies are needed or shipped.
The GUI background uses a style texture because `GUI.DrawTexture` can be stripped in IL2CPP games.
A rendering failure closes the prompt without granting consent and avoids repeated GUI exceptions.

## Development verification

One PostHog project serves all environments. Development and staging data stay labeled; production
reports must filter `environment=production`. An environment label is not an access boundary.

Copy `telemetry.development.example.json` to `telemetry.development.local.json`, supply the public
project token, and run `./scripts/test-posthog-development.ps1` from the loader repository.
This explicitly sends two development events through the real loader scan pipeline using a
generated benign assembly in a temporary directory, then runs once more after opting out.
No installed game settings are changed, and no sample upload is enabled.

The test records its time window in `telemetry.development.evidence.local.json`. Separately verify
two events in PostHog, each with `result_count=1` and `clean_count=1`, and no third event from the
opted-out run. Allow for ingestion delay and host/server clock skew when choosing the query window. A passing local scan test alone does not prove hosted ingestion. Normal test runs skip
this live test unless `MLVSCAN_POSTHOG_SMOKE_CONFIG` is explicitly set.

## Optional private review

With the file checkbox enabled, flagged files up to 64 MiB go only to `/files/private-review`.
There is no fallback to public uploads. Cloudflare stores the bytes and bounded original findings
report in a separate private R2 bucket. Reports include Core version, original loader verdict/status,
and available correlated evidence. Initial deferred BepInEx submissions may carry only the summary;
a full report larger than 180 KB is omitted. This does not run a second scan or execute the sample.
Reports receive location redaction, but evidence and sample bytes can still contain personal data.

Only authenticated MLVScan administrators can list/read/download/review/delete these submissions.
A receipt ID does not authorize access. This intake creates no public scan record, content-reuse
entry, scanner queue message, provider index or Discord notification. We do not publish or
redistribute these submissions, including false positives. Cloudflare processes stored evidence;
PostHog receives only basic diagnostics. This promise applies to this new intake, not prior uploads
through the old public-report flow.

Production and staging storage have public development access disabled, no custom domain or event notification,
and a 30-day object lifecycle expiration rule. Expiration is asynchronous; reviewing a record
updates its object age but does not extend the original sample's retention. Admin deletion removes
both immediately. If the private binding is unavailable, upload fails closed with HTTP 503 and files remain local.

Basic diagnostics indicate patterns worth investigating; they do not confirm false positives,
count unique affected users, or report actual blocking actions. There are no duration/size metrics
or full source/transform/sink details in basic sharing. Whitelisted files are excluded. The loader includes completeness status and allowlisted rule identifiers for analysis limits;
free-text reasons and evidence remain local.

## Rollout boundary

Release candidates target the MLVScan PostHog project in production, but both outbound paths
remain off until current consent is recorded. Tests explicitly select development or staging.
This rollout is limited to MelonLoader and BepInEx. Core remains a pure local projection;
general API, SDK, Nexus, enterprise, and attestation traffic is not enrolled in PostHog.
The existing website receipt event remains website-only. Consumer-specific API consent and
restricted data contracts require a separate rollout.

## Loader private-review correlation

With file sharing enabled, both threat detections and incomplete/manual-review results
qualify for automatic private review. Clean, complete files do not. The existing 64 MiB
loader upload cap still applies; oversized samples stay local. Before the first consent
choice, one eligible result is retained for deferred submission if file sharing is accepted.

After a successful upload, the server-issued UUID is logged and saved locally in
UploadedReviewReceipts with the local file hash. This local mapping never goes to PostHog.
When BOTH analytics and file sharing remain enabled, the loader sends a separate
mlvscan_private_review_uploaded event with submission_reference, allowlisted original_verdict
and scan_status, loader/Core/plugin versions and environment. No filename, hash, path,
evidence text or persistent user identifier is included. The reference identifies the
private record reviews/<reference>/record in R2; it does not grant access. It links the
receipt event to that private sample, not to an individual in aggregate scan events.
Invalid/missing receipts produce no receipt event. An analytics or local receipt-save
failure never retries an already accepted sample. Independent analytics opt-out remains
respected even when private file uploads are enabled. General API consumer telemetry
remains deferred; no server telemetry policy changes are required.

## Native file sizes

Native scans have no input file-size cutoff. The loader hashes and scans the same open file stream rather than buffering the whole file. Internal analysis budgets still apply, and incomplete scans require review. This does not provide process isolation or a hard memory/time guarantee. Optional uploads have a separate 64 MiB transport limit, checked before reading sample bytes. Browser limits are unchanged.
