namespace MLVScan.Models
{
    /// <summary>
    /// Tracks suspicious signals detected within a single method for multi-pattern analysis
    /// </summary>
    public class MethodSignals
    {
        public bool HasEncodedStrings { get; set; }
        public bool HasSuspiciousReflection { get; set; }
        public bool UsesSensitiveFolder { get; set; }
        public bool HasProcessLikeCall { get; set; }
        public bool HasBase64 { get; set; }
        public bool HasNetworkCall { get; set; }
        public bool HasFileWrite { get; set; }

        public int SignalCount
        {
            get
            {
                int count = 0;
                if (HasEncodedStrings) count++;
                if (HasSuspiciousReflection) count++;
                if (UsesSensitiveFolder) count++;
                if (HasProcessLikeCall) count++;
                if (HasBase64) count++;
                if (HasNetworkCall) count++;
                if (HasFileWrite) count++;
                return count;
            }
        }

        public bool IsCriticalCombination()
        {
            // Critical: Reflection + Encoded data
            if (HasSuspiciousReflection && HasEncodedStrings)
                return true;

            // Critical: Reflection + Sensitive path
            if (HasSuspiciousReflection && UsesSensitiveFolder)
                return true;

            // Critical: Encoded strings + Process execution
            if (HasEncodedStrings && HasProcessLikeCall)
                return true;

            // Critical: Sensitive path + File write + Process call
            if (UsesSensitiveFolder && HasFileWrite && HasProcessLikeCall)
                return true;

            // High: Network + Sensitive path + File write
            if (HasNetworkCall && UsesSensitiveFolder && HasFileWrite)
                return true;

            return false;
        }

        public bool IsHighRiskCombination()
        {
            // High risk: Any 2+ signals (but not critical combinations)
            return SignalCount >= 2 && !IsCriticalCombination();
        }

        public string GetCombinationDescription()
        {
            var signals = new List<string>();
            if (HasEncodedStrings) signals.Add("encoded strings");
            if (HasSuspiciousReflection) signals.Add("suspicious reflection");
            if (UsesSensitiveFolder) signals.Add("sensitive folder access");
            if (HasProcessLikeCall) signals.Add("process execution");
            if (HasBase64) signals.Add("Base64 decoding");
            if (HasNetworkCall) signals.Add("network call");
            if (HasFileWrite) signals.Add("file write");

            return string.Join(" + ", signals);
        }
    }
}
