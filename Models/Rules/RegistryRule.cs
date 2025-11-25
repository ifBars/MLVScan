using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class RegistryRule : IScanRule
    {
        public string Description => "Detected registry manipulation, which is suspicious for a MelonLoader mod. This could be used to persist malware or modify system settings.";
        public Severity Severity => Severity.Critical;
        
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

            if (method.Resolve() is not { } methodDef) return false;
            
            // Check if this is a PInvoke method
            if ((methodDef.Attributes & MethodAttributes.PInvokeImpl) == 0)
                return false;

            if (methodDef.PInvokeInfo == null)
                return false;

            var dllName = methodDef.PInvokeInfo.Module.Name;
            var entryPoint = methodDef.PInvokeInfo.EntryPoint ?? method.Name;

            // Check if it's advapi32.dll (registry DLL)
            if (!dllName.ToLower().Contains("advapi32"))
                return false;

            // Check method name or entry point for registry functions
            if (RegistryFunctions.Any(func => methodName.Contains(func)))
                return true;

            var entryPointLower = entryPoint.ToLower();
            if (RegistryFunctions.Any(func => entryPointLower.Contains(func)))
                return true;

            return false;
        }
    }
}