using System.Runtime.InteropServices;

namespace MLVScan.Services.Caching
{
    internal static class RuntimeInformationHelper
    {
        public static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static bool IsMacOs => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
    }
}
