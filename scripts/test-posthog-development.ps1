param([string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'telemetry.development.local.json'))
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($config.TelemetryEnvironment -ne 'development' -or $config.EnableAnonymousTelemetry -ne $true -or $config.EnableReportUpload -ne $false) {
    throw 'Live smoke requires explicit development telemetry consent and disabled file uploads.'
}
$previous = $env:MLVSCAN_POSTHOG_SMOKE_CONFIG
try {
    $env:MLVSCAN_POSTHOG_SMOKE_CONFIG = (Resolve-Path -LiteralPath $ConfigPath).Path
    & dotnet test (Join-Path (Split-Path $repo -Parent) 'MLVScan.Tests/MLVScan.Tests.csproj') `
        --filter 'FullyQualifiedName~PostHogDevelopmentSmokeTests' --verbosity quiet `
        -p:LoaderTestUseLocalCore=false -p:MelonPluginsPath= -p:BepInExPatchersPath= -p:MelonLoaderReleaseCopyDirectories= `
        -p:BepInEx5ReleaseCopyDirectories= -p:BepInEx6MonoReleaseCopyDirectories= -p:BepInEx6IL2CPPReleaseCopyDirectories=
    if ($LASTEXITCODE -ne 0) { throw "Development smoke failed ($LASTEXITCODE)." }
    Write-Output 'Scan smoke complete. Verify two development events and no event after opt-out in PostHog; HTTP delivery is not asserted by this test.'
} finally {
    $env:MLVSCAN_POSTHOG_SMOKE_CONFIG = $previous
}
