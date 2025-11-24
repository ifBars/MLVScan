using Mono.Cecil;

namespace MLVScan.Models
{
    public class EncodedStringPipelineRule : IScanRule
    {
        public string Description => "Detected encoded string to char decoding pipeline (ASCII number parsing pattern).";
        public string Severity => "High";

        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze IL instruction patterns in methods
            return false;
        }
    }
}

