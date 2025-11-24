using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class Base64Rule : IScanRule
    {
        public string Description => "Detected FromBase64String call which decodes base64 encrypted strings.";
        public Severity Severity => Severity.Low;
        
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return typeName.Contains("Convert") && methodName.Contains("FromBase64");
        }
    }
}