using Mono.Cecil;

namespace MLVScan.Models
{
    public class MemoryStreamRule : IScanRule
    {
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            if (typeName == "System.IO.MemoryStream" && methodName == ".ctor")
                return true;

            return typeName.Contains("MemoryStream");
        }

        public string Description => "Detected MemoryStream usage which may be used to load an assembly into memory.";

        public string Severity => "Critical";
    }
}