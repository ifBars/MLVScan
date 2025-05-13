using Mono.Cecil;

namespace MLVScan.Models
{
    public class LoadFromStreamRule : IScanRule
    {
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            if (methodName == "LoadFromStream")
                return true;

            if (methodName.Contains("LoadFrom") &&
               (methodName.Contains("Stream") || methodName.Contains("Bytes") || methodName.Contains("Memory")))
                return true;

            return (typeName.Contains("Assembly") || typeName.Contains("AssemblyLoadContext")) &&
                   (methodName == "Load" || methodName.Contains("LoadFrom"));
        }

        public string Description => "Detected dynamic assembly loading which could be used to execute hidden code.";

        public string Severity => "Critical";
    }
}