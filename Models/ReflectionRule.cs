using Mono.Cecil;

namespace MLVScan.Models
{
    public class ReflectionRule : IScanRule
    {
        public string Description => "Detected reflection invocation without determinable target method (potential bypass).";
        public string Severity => "High";

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Detect reflection invoke methods
            bool isReflectionInvoke =
                (typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke");

            return isReflectionInvoke;
        }
    }
}
