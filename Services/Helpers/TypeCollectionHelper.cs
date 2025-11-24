using Mono.Cecil;

namespace MLVScan.Services.Helpers
{
    public static class TypeCollectionHelper
    {
        public static IEnumerable<TypeDefinition> GetAllTypes(ModuleDefinition module)
        {
            var allTypes = new List<TypeDefinition>();

            try
            {
                // Add top-level types
                foreach (var type in module.Types)
                {
                    allTypes.Add(type);

                    // Add nested types
                    CollectNestedTypes(type, allTypes);
                }
            }
            catch (Exception)
            {
                // Ignore errors
            }

            return allTypes;
        }

        private static void CollectNestedTypes(TypeDefinition type, List<TypeDefinition> allTypes)
        {
            try
            {
                foreach (var nestedType in type.NestedTypes)
                {
                    allTypes.Add(nestedType);
                    CollectNestedTypes(nestedType, allTypes);
                }
            }
            catch (Exception)
            {
                // Ignore errors
            }
        }
    }
}

