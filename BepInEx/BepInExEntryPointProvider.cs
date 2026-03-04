using MLVScan.Abstractions;
using Mono.Cecil;

namespace MLVScan.BepInEx
{
    /// <summary>
    /// BepInEx-specific entry point detection.
    /// Identifies BepInEx plugin lifecycle methods and common entry points.
    /// </summary>
    public class BepInExEntryPointProvider : IEntryPointProvider
    {
        // BepInEx/BaseUnityPlugin lifecycle methods
        private static readonly HashSet<string> BepInExEntryPoints = new(StringComparer.OrdinalIgnoreCase)
        {
            "Awake",
            "Start",
            "Update",
            "LateUpdate",
            "FixedUpdate",
            "OnEnable",
            "OnDisable",
            "OnDestroy",
            "OnApplicationQuit",
            "OnApplicationPause",
            "OnApplicationFocus"
        };

        // Common plugin initialization patterns
        private static readonly string[] PluginPrefixes = new[]
        {
            "Initialize",
            "Init",
            "Setup",
            "Load",
            "Patch"
        };

        // Harmony patch method naming conventions
        private static readonly string[] HarmonyPrefixes = new[]
        {
            "Prefix",
            "Postfix",
            "Transpiler",
            "Finalizer"
        };

        public bool IsEntryPoint(MethodDefinition method)
        {
            var name = method.Name;

            // Check BepInEx/BaseUnityPlugin lifecycle methods
            if (BepInExEntryPoints.Contains(name))
                return true;

            // Check for plugin initialization patterns
            foreach (var prefix in PluginPrefixes)
            {
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check for Harmony patch methods
            foreach (var prefix in HarmonyPrefixes)
            {
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Static constructors are always entry points
            if (name == ".cctor")
                return true;

            return false;
        }

        public IEnumerable<string> GetKnownEntryPointNames()
        {
            var allEntryPoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            allEntryPoints.UnionWith(BepInExEntryPoints);
            allEntryPoints.Add(".cctor");
            return allEntryPoints.OrderBy(n => n);
        }
    }
}
