using System;
using System.Collections.Generic;
using System.IO;
using MelonLoader.Utils;
using MLVScan.Services.Diagnostics;
using MLVScan.Services.Resolution;

namespace MLVScan.Adapters
{
    /// <summary>
    /// Provides assembly resolution for game assemblies in MelonLoader context.
    /// Adds the game's Managed folder and MelonLoader folder to the search paths.
    /// </summary>
    public class GameAssemblyResolverProvider : CatalogingAssemblyResolverProviderBase
    {
        public GameAssemblyResolverProvider(LoaderScanTelemetryHub telemetry)
            : base(telemetry)
        {
        }

        protected override IEnumerable<ResolverRoot> GetStableRoots()
        {
            var roots = new List<ResolverRoot>();

            try
            {
                var managedPath = Path.Combine(
                    MelonEnvironment.GameRootDirectory,
                    $"{Path.GetFileNameWithoutExtension(MelonEnvironment.GameExecutablePath)}_Data",
                    "Managed");

                if (Directory.Exists(managedPath))
                {
                    roots.Add(new ResolverRoot(managedPath, 0));
                }

                var melonLoaderNet35Path = Path.Combine(
                    MelonEnvironment.GameRootDirectory,
                    "MelonLoader",
                    "net35");
                if (Directory.Exists(melonLoaderNet35Path))
                {
                    roots.Add(new ResolverRoot(melonLoaderNet35Path, 5));
                }

                var melonLoaderNet6Path = Path.Combine(
                    MelonEnvironment.GameRootDirectory,
                    "MelonLoader",
                    "net6");
                if (Directory.Exists(melonLoaderNet6Path))
                {
                    roots.Add(new ResolverRoot(melonLoaderNet6Path, 6));
                }
            }
            catch (Exception)
            {
                return roots;
            }

            return roots;
        }
    }
}
