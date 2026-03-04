using MLVScan.Abstractions;
using Mono.Cecil;

namespace MLVScan.MelonLoader
{
    /// <summary>
    /// MelonLoader-specific entry point detection.
    /// Identifies MelonLoader lifecycle methods and common mod entry points.
    /// </summary>
    public class MelonLoaderEntryPointProvider : IEntryPointProvider
    {
        // MelonLoader-specific entry points
        private static readonly HashSet<string> MelonLoaderEntryPoints = new(StringComparer.OrdinalIgnoreCase)
        {
            "OnInitializeMelon",
            "OnLateInitializeMelon",
            "OnPreInitialization",
            "OnPreModsLoaded",
            "OnUpdate",
            "OnLateUpdate",
            "OnFixedUpdate",
            "OnGUI",
            "OnApplicationQuit",
            "OnApplicationPause",
            "OnApplicationFocus",
            "OnSceneWasLoaded",
            "OnSceneWasInitialized",
            "OnSceneWasUnloaded"
        };

        // Method name prefixes for MelonLoader
        private static readonly string[] MelonLoaderPrefixes = new[]
        {
            "OnMelon",
            "OnApplication",
            "OnScene"
        };

        // Common Unity MonoBehaviour entry points
        private static readonly HashSet<string> UnityEntryPoints = new(StringComparer.OrdinalIgnoreCase)
        {
            "Awake",
            "Start",
            "Update",
            "LateUpdate",
            "FixedUpdate",
            "OnEnable",
            "OnDisable",
            "OnDestroy"
        };

        public bool IsEntryPoint(MethodDefinition method)
        {
            var name = method.Name;

            // Check MelonLoader-specific entry points
            if (MelonLoaderEntryPoints.Contains(name))
                return true;

            // Check MelonLoader prefixes
            foreach (var prefix in MelonLoaderPrefixes)
            {
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check Unity MonoBehaviour entry points
            if (UnityEntryPoints.Contains(name))
                return true;

            // Static constructors are always entry points
            if (name == ".cctor")
                return true;

            return false;
        }

        public IEnumerable<string> GetKnownEntryPointNames()
        {
            var allEntryPoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            allEntryPoints.UnionWith(MelonLoaderEntryPoints);
            allEntryPoints.UnionWith(UnityEntryPoints);
            allEntryPoints.Add(".cctor");
            return allEntryPoints.OrderBy(n => n);
        }
    }
}
