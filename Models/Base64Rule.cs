using Mono.Cecil;

namespace MLVScan.Models
{
    public class Base64Rule : IScanRule
    {
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return typeName.Contains("Convert") && methodName.Contains("FromBase64");
        }

        public string Description => "Detected FromBase64String call which decodes base64 encrypted strings.";

        public string Severity => "Medium";
    }
}