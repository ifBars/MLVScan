namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction for platform-specific paths and environment info.
    /// MelonLoader uses MelonEnvironment, BepInEx uses BepInEx.Paths.
    /// </summary>
    public interface IPlatformEnvironment
    {
        /// <summary>
        /// Gets the game's root directory.
        /// </summary>
        string GameRootDirectory { get; }

        /// <summary>
        /// Gets the directory where plugins/mods are stored.
        /// MelonLoader: Mods/ and Plugins/
        /// BepInEx: BepInEx/plugins/
        /// </summary>
        string[] PluginDirectories { get; }

        /// <summary>
        /// Gets the directory for MLVScan's own data (reports, disabled info, etc.).
        /// </summary>
        string DataDirectory { get; }

        /// <summary>
        /// Gets the directory for scan reports.
        /// </summary>
        string ReportsDirectory { get; }

        /// <summary>
        /// Gets the managed assemblies directory (Unity DLLs, game code).
        /// </summary>
        string ManagedDirectory { get; }

        /// <summary>
        /// Gets the path to the MLVScan assembly itself (for self-exclusion).
        /// </summary>
        string SelfAssemblyPath { get; }

        /// <summary>
        /// Gets the platform name for display/logging.
        /// </summary>
        string PlatformName { get; }
    }
}
