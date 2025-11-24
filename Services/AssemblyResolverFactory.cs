using MelonLoader.Utils;
using Mono.Cecil;

namespace MLVScan.Services
{
    public class AssemblyResolverFactory
    {
        public static DefaultAssemblyResolver Create()
        {
            var resolver = new DefaultAssemblyResolver();

            var gameDir = MelonEnvironment.GameRootDirectory;
            var melonDir = Path.Combine(gameDir, "MelonLoader");

            resolver.AddSearchDirectory(gameDir);

            if (Directory.Exists(melonDir))
            {
                resolver.AddSearchDirectory(melonDir);

                var managedDir = Path.Combine(melonDir, "Managed");
                if (Directory.Exists(managedDir))
                {
                    resolver.AddSearchDirectory(managedDir);
                }

                var dependenciesDir = Path.Combine(melonDir, "Dependencies");
                if (Directory.Exists(dependenciesDir))
                {
                    resolver.AddSearchDirectory(dependenciesDir);

                    foreach (var dir in Directory.GetDirectories(dependenciesDir, "*", SearchOption.AllDirectories))
                    {
                        resolver.AddSearchDirectory(dir);
                    }
                }
            }

            var gameManagedDir = Path.Combine(gameDir, "Schedule I_Data", "Managed");
            if (Directory.Exists(gameManagedDir))
            {
                resolver.AddSearchDirectory(gameManagedDir);
            }

            return resolver;
        }
    }
}

