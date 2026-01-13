namespace MLVScan
{
    /// <summary>
    /// Version and build constants for MLVScan.MelonLoader platform.
    /// Update this file when releasing new versions.
    /// </summary>
    public static class PlatformConstants
    {
        /// <summary>
        /// Platform-specific version (MelonLoader implementation).
        /// </summary>
        public const string PlatformVersion = "1.6.1";
        
        /// <summary>
        /// Platform name identifier.
        /// </summary>
        public const string PlatformName = "MLVScan.MelonLoader";
        
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
