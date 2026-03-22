using System;
using System.Collections.Generic;
using System.IO;
using BepInEx;
using MLVScan.Services.Diagnostics;
using MLVScan.Services.Resolution;

namespace MLVScan.BepInEx.Adapters
{
    /// <summary>
    /// Provides assembly resolution for scanning in BepInEx context.
    /// Adds all relevant BepInEx and game directories to search paths.
    /// </summary>
    public class BepInExAssemblyResolverProvider : CatalogingAssemblyResolverProviderBase
    {
        public BepInExAssemblyResolverProvider()
            : base()
        {
        }

        protected override IEnumerable<ResolverRoot> GetStableRoots()
        {
            var roots = new List<ResolverRoot>();

            try
            {
                if (Directory.Exists(Paths.ManagedPath))
                {
                    roots.Add(new ResolverRoot(Paths.ManagedPath, 0));
                }

                if (Directory.Exists(Paths.BepInExAssemblyDirectory))
                {
                    roots.Add(new ResolverRoot(Paths.BepInExAssemblyDirectory, 5));
                }

                if (Directory.Exists(Paths.PatcherPluginPath))
                {
                    roots.Add(new ResolverRoot(Paths.PatcherPluginPath, 10));
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
