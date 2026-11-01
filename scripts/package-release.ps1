param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$project = Join-Path $repo 'MLVScan.csproj'
$version = ([xml](Get-Content -LiteralPath $project -Raw)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'Choose a new output directory so existing packages cannot be overwritten.' }
New-Item -ItemType Directory -Path $out | Out-Null
$targets = @(
    @{Configuration='MelonLoader'; Tfm='netstandard2.1'; Assembly='MLVScan.MelonLoader'; Folder='Plugins'},
    @{Configuration='BepInEx5'; Tfm='netstandard2.1'; Assembly='MLVScan.BepInEx5'; Folder='BepInEx/patchers'},
    @{Configuration='BepInEx6Mono'; Tfm='netstandard2.1'; Assembly='MLVScan.BepInEx6.Mono'; Folder='BepInEx/patchers'},
    @{Configuration='BepInEx6IL2CPP'; Tfm='net6.0'; Assembly='MLVScan.BepInEx6.IL2CPP'; Folder='BepInEx/patchers'}
)
# Override machine-local development and deployment hooks. Restore/build serially: obj is shared.
$properties = @('-p:UseLocalMLVScanCore=false', '-p:EnableMlvScanProfiling=false',
    '-p:UnityInteropPath=', '-p:MelonLoaderPath=', '-p:GameManagedPath=', '-p:BepInExCorePath=',
    '-p:MelonPluginsPath=', '-p:BepInExPatchersPath=', '-p:MelonLoaderReleaseCopyDirectories=',
    '-p:BepInEx5ReleaseCopyDirectories=', '-p:BepInEx6MonoReleaseCopyDirectories=', '-p:BepInEx6IL2CPPReleaseCopyDirectories=')
$manifest = foreach ($target in $targets) {
    $config = $target.Configuration
    & dotnet build $project -c $config @properties --verbosity quiet *> (Join-Path $out "$config-build.log")
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $config. See build log in $out." }
    $dll = Join-Path $repo "bin/$config/$($target.Tfm)/$($target.Assembly).dll"
    $actualVersion = [Reflection.AssemblyName]::GetAssemblyName($dll).Version.ToString()
    if ($actualVersion -ne "$version.0") { throw "Unexpected assembly version: $actualVersion" }
    $layout = Join-Path $out $config
    $destination = Join-Path $layout $target.Folder
    New-Item -ItemType Directory -Force $destination | Out-Null
    Copy-Item -LiteralPath $dll -Destination $destination
    $archive = Join-Path $out "$($target.Assembly)-v$version.zip"
    Compress-Archive -Path (Join-Path $layout '*') -DestinationPath $archive
    # Verify exact archive membership and hashes: no game, Core, framework, or probe DLLs shipped.
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entryName = "$($target.Folder)/$($target.Assembly).dll"
        $entries = @($zip.Entries | Where-Object { $_.Name })
        if ($entries.Count -ne 1 -or $entries[0].FullName.Replace('\','/') -ne $entryName) { throw "Unexpected archive contents: $archive" }
        $stream = $entries[0].Open()
        try { $sha = [Security.Cryptography.SHA256]::Create(); $entryHash = [Convert]::ToHexString($sha.ComputeHash($stream)); $sha.Dispose() }
        finally { $stream.Dispose() }
        if ($entryHash -ne (Get-FileHash -LiteralPath $dll).Hash) { throw "Archive hash mismatch: $archive" }
    } finally { $zip.Dispose() }
    [pscustomobject]@{ configuration=$config; version=$version; coreVersion='1.10.0'; archive=(Split-Path $archive -Leaf); sha256=(Get-FileHash -LiteralPath $archive).Hash; assemblySha256=$entryHash }
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $out 'manifest.json')
Write-Output "Built and verified four candidate packages in $out. Nothing was published or installed."
