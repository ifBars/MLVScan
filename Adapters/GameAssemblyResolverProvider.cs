using MelonLoader.Utils;
using MLVScan.Abstractions;
using Mono.Cecil;

namespace MLVScan.Adapters
{
    /// <summary>
    /// Provides assembly resolution for game assemblies in MelonLoader context.
    /// Adds the game's Managed folder and MelonLoader folder to the search paths.
    /// </summary>
    public class GameAssemblyResolverProvider : IAssemblyResolverProvider
    {
        public IAssemblyResolver CreateResolver()
        {
            var resolver = new DefaultAssemblyResolver();

            try
            {
                // Add the game's Managed folder (contains Unity assemblies)
                var managedPath = Path.Combine(
                    MelonEnvironment.GameRootDirectory,
                    $"{Path.GetFileNameWithoutExtension(MelonEnvironment.GameExecutablePath)}_Data",
                    "Managed");

                if (Directory.Exists(managedPath))
                    resolver.AddSearchDirectory(managedPath);

                // Add MelonLoader's assembly folder
                var melonLoaderPath = Path.Combine(
                    MelonEnvironment.GameRootDirectory,
                    "MelonLoader",
                    "net35");

                if (Directory.Exists(melonLoaderPath))
                    resolver.AddSearchDirectory(melonLoaderPath);

                // Also check for net6 folder (for newer MelonLoader versions)
                var melonLoaderNet6Path = Path.Combine(
                    MelonEnvironment.GameRootDirectory,
                    "MelonLoader",
                    "net6");

                if (Directory.Exists(melonLoaderNet6Path))
                    resolver.AddSearchDirectory(melonLoaderNet6Path);
            }
            catch (Exception)
            {
                // If we can't set up the resolver, just use the default
            }

            return resolver;
        }
    }
}
