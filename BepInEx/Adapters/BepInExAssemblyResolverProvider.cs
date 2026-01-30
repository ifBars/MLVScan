using System;
using System.IO;
using BepInEx;
using MLVScan.Abstractions;
using Mono.Cecil;

namespace MLVScan.BepInEx.Adapters
{
    /// <summary>
    /// Provides assembly resolution for scanning in BepInEx context.
    /// Adds all relevant BepInEx and game directories to search paths.
    /// </summary>
    public class BepInExAssemblyResolverProvider : IAssemblyResolverProvider
    {
        public IAssemblyResolver CreateResolver()
        {
            var resolver = new DefaultAssemblyResolver();

            try
            {
                // Game's managed assemblies (Unity DLLs, game code)
                if (Directory.Exists(Paths.ManagedPath))
                    resolver.AddSearchDirectory(Paths.ManagedPath);

                // BepInEx core assemblies
                if (Directory.Exists(Paths.BepInExAssemblyDirectory))
                    resolver.AddSearchDirectory(Paths.BepInExAssemblyDirectory);

                // Plugin directory (for plugin-to-plugin references)
                if (Directory.Exists(Paths.PluginPath))
                    resolver.AddSearchDirectory(Paths.PluginPath);

                // Patcher directory (where we are running from)
                if (Directory.Exists(Paths.PatcherPluginPath))
                    resolver.AddSearchDirectory(Paths.PatcherPluginPath);
            }
            catch (Exception)
            {
                // If path resolution fails, use default resolver behavior
            }

            return resolver;
        }
    }
}
