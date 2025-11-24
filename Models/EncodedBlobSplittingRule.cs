using Mono.Cecil;

namespace MLVScan.Models
{
    public class EncodedBlobSplittingRule : IScanRule
    {
        public string Description => "Detected structured encoded blob splitting pattern (backtick/dash separator in loop).";
        public string Severity => "High";

        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze IL instruction patterns in methods
            return false;
        }
    }
}

