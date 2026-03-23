using System;
using MLVScan.Models;

namespace MLVScan.BepInEx
{
    internal static class ConsentMessageHelper
    {
        public static string GetUploadConsentMessage(string modName, string verdictKind)
        {
            var label = string.IsNullOrWhiteSpace(modName) ? "this mod" : modName;
            if (string.Equals(verdictKind, ThreatVerdictKind.KnownMaliciousSample.ToString(), StringComparison.Ordinal) ||
                string.Equals(verdictKind, ThreatVerdictKind.KnownMalwareFamily.ToString(), StringComparison.Ordinal))
            {
                return $"MLVScan identified {label} as likely malware and disabled it.";
            }

            return $"MLVScan blocked {label} because it triggered suspicious behavior. It may still be a false positive.";
        }
    }
}
