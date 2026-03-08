using MLVScan.Models;

namespace MLVScan.Models;

/// <summary>
/// MLVScan integration configuration for Unity/MelonLoader/BepInEx contexts.
/// Combines core scanning settings from ScanConfig with platform-specific integration settings.
/// </summary>
public class MLVScanConfig
{
    /// <summary>
    /// Core scanning configuration - passed to the analysis engine.
    /// </summary>
    public ScanConfig Scan { get; set; } = new ScanConfig();

    // Integration settings - these control the MLVScan plugin behavior, not the analysis engine

    /// <summary>
    /// Enable/disable automatic scanning at startup.
    /// </summary>
    public bool EnableAutoScan { get; set; } = true;

    /// <summary>
    /// Enable/disable automatic disabling of suspicious mods.
    /// </summary>
    public bool EnableAutoDisable { get; set; } = true;

    /// <summary>
    /// Minimum severity level to trigger disabling.
    /// </summary>
    public Severity MinSeverityForDisable { get; set; } = Severity.Medium;

    /// <summary>
    /// Where to scan for mods.
    /// </summary>
    public string[] ScanDirectories { get; set; } = ["Mods", "Plugins"];

    /// <summary>
    /// How many suspicious findings before disabling a mod.
    /// </summary>
    public int SuspiciousThreshold { get; set; } = 1;

    /// <summary>
    /// Mods to whitelist (will be skipped during scanning).
    /// </summary>
    public string[] WhitelistedHashes { get; set; } = [];

    /// <summary>
    /// Save a full IL dump of each scanned mod to the reports directory.
    /// </summary>
    public bool DumpFullIlReports { get; set; } = false;

    /// <summary>
    /// Automated report upload: whether user has consented to send reports to the API.
    /// </summary>
    public bool EnableReportUpload { get; set; } = false;

    /// <summary>
    /// Whether we have shown the first-run consent prompt (so we don't prompt again).
    /// </summary>
    public bool ReportUploadConsentAsked { get; set; } = false;

    /// <summary>
    /// Whether a consent decision is pending and should be shown in a GUI popup.
    /// </summary>
    public bool ReportUploadConsentPending { get; set; } = false;

    /// <summary>
    /// Path to the first suspicious mod awaiting consent for upload.
    /// </summary>
    public string PendingReportUploadPath { get; set; } = string.Empty;

    /// <summary>
    /// API base URL for report uploads.
    /// </summary>
    public string ReportUploadApiBaseUrl { get; set; } = "https://api.mlvscan.com";

    // Scan scope settings

    /// <summary>
    /// Include game Mods folders in target scope.
    /// </summary>
    public bool IncludeMods { get; set; } = true;

    /// <summary>
    /// Include Plugins folders in target scope.
    /// </summary>
    public bool IncludePlugins { get; set; } = true;

    /// <summary>
    /// Include UserLibs folders in target scope.
    /// </summary>
    public bool IncludeUserLibs { get; set; } = true;

    /// <summary>
    /// Include patcher folders in target scope.
    /// </summary>
    public bool IncludePatchers { get; set; } = true;

    /// <summary>
    /// Include Thunderstore profile folders in target scope.
    /// </summary>
    public bool IncludeThunderstoreProfiles { get; set; } = true;

    /// <summary>
    /// Additional custom roots to include in target scope.
    /// </summary>
    public string[] AdditionalTargetRoots { get; set; } = [];

    /// <summary>
    /// Custom roots to exclude from target scope.
    /// </summary>
    public string[] ExcludedTargetRoots { get; set; } = [];
}
