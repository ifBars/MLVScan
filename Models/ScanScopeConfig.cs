namespace MLVScan.Models;

/// <summary>
/// Controls scan scope boundaries for mod-loader host integrations.
/// Scope enforcement is applied by host scanners to ensure only mod-ecosystem
/// assemblies are scanned as targets (mods/plugins/userlibs/patchers).
/// </summary>
public class ScanScopeConfig
{
    public bool IncludeMods { get; set; } = true;
    public bool IncludePlugins { get; set; } = true;
    public bool IncludeUserLibs { get; set; } = true;
    public bool IncludePatchers { get; set; } = true;
    public bool IncludeThunderstoreProfiles { get; set; } = true;

    public string[] AdditionalTargetRoots { get; set; } = [];
    public string[] ExcludedTargetRoots { get; set; } = [];
}
