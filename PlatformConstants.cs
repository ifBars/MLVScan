namespace MLVScan
{
    /// <summary>
    /// Version and build constants for MLVScan platform.
    /// Update this file when releasing new versions.
    /// Uses conditional compilation for platform-specific values.
    /// </summary>
    public static class PlatformConstants
    {
        /// <summary>
        /// Platform-specific version.
        /// </summary>
        public const string PlatformVersion = "1.6.1";

#if MELONLOADER
        /// <summary>
        /// Platform name identifier.
        /// </summary>
        public const string PlatformName = "MLVScan.MelonLoader";
#elif BEPINEX
        /// <summary>
        /// Platform name identifier.
        /// </summary>
        public const string PlatformName = "MLVScan.BepInEx";
#else
        /// <summary>
        /// Platform name identifier (fallback for IDE).
        /// </summary>
        public const string PlatformName = "MLVScan";
#endif

        /// <summary>
        /// Gets the full platform version string.
        /// </summary>
        public static string GetVersionString() => $"{PlatformName} v{PlatformVersion}";

        /// <summary>
        /// Gets the combined version info including core engine.
        /// </summary>
        public static string GetFullVersionInfo() =>
            $"Engine: {Constants.GetVersionString()}\nPlatform: {GetVersionString()}";
    }
}
