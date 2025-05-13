using Mono.Cecil;

namespace MLVScan.Models
{
    public class RegistryRule : IScanRule
    {
        private static readonly string[] RegistryFunctions =
        [
            "regcreatekeyex",
            "regopenkey",
            "regopenkeya",
            "regopenkeyex",
            "regopenkeyexa",
            "regopenkeyexw",
            "regsetvalue",
            "regsetvaluea",
            "regsetvaluew",
            "regsetvalueex",
            "regsetvalueexa",
            "regsetvalueexw",
            "reggetvalue",
            "reggetvaluea",
            "reggetvaluew",
            "regdeletekey",
            "regdeletevalue",
            "regenumkey",
            "regenumvalue",
            "regqueryvalue",
            "regqueryvalueex",
            "regcreatekey",
            "regsetkeysecurity",
            "regloadkey",
            "regsavekey",
            "regnotifychangekeyvalue"
        ];

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name.ToLower();

            if (typeName.Contains("Microsoft.Win32.Registry") ||
                typeName.Contains("RegistryKey") ||
                typeName.Contains("RegistryHive"))
            {
                return true;
            }

            if (RegistryFunctions.Any(regFunction => methodName.Contains(regFunction)))
            {
                return true;
            }

            if (method.Resolve() is not { HasCustomAttributes: true } methodDef) return false;
            foreach (var attribute in methodDef.CustomAttributes)
            {
                if (attribute.AttributeType.Name != "DllImportAttribute") continue;
                foreach (var arg in attribute.ConstructorArguments)
                {
                    if (arg.Value is not string dllName ||
                        !dllName.ToLower().Contains("advapi32")) continue;
                    if (RegistryFunctions.Any(func => methodName.Contains(func)))
                        return true;

                    foreach (var prop in attribute.Properties)
                    {
                        if (prop.Name != "EntryPoint" ||
                            prop.Argument.Value is not string entryPoint) continue;
                        var entryPointLower = entryPoint.ToLower();
                        if (RegistryFunctions.Any(func =>
                                entryPointLower.Contains(func)))
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        public string Description => "Detected registry manipulation, which is suspicious for a MelonLoader mod. This could be used to persist malware or modify system settings.";

        public string Severity => "High";
    }
}