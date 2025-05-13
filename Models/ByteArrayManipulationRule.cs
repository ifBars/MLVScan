using Mono.Cecil;

namespace MLVScan.Models
{
    public class ByteArrayManipulationRule : IScanRule
    {
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            switch (typeName)
            {
                // Common Base64 decoding pattern for hidden payloads
                case "System.Convert" when methodName is "FromBase64String" or "FromBase64CharArray":
                // Check for MemoryStream constructor with byte array parameter
                // The constructor pattern is caught here - when a MemoryStream is created with a byte array
                case "System.IO.MemoryStream" when methodName == ".ctor":
                    return true;
            }

            // Check for BitConverter methods often used to manipulate raw data
            return typeName.Contains("BitConverter") &&
                   (methodName.StartsWith("To") || methodName.StartsWith("GetBytes"));
        }

        public string Description => "Detected byte array manipulation commonly used to hide and load malicious code.";

        public string Severity => "High";
    }
}