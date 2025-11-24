using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class LoadFromStreamRule : IScanRule
    {
        public string Description => "Detected dynamic assembly loading which could be used to execute hidden code.";
        public Severity Severity => Severity.Critical;
        
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return (typeName.Contains("Assembly") || typeName.Contains("AssemblyLoadContext")) &&
                   (methodName == "Load" || methodName.Contains("LoadFrom"));
        }
    }
}