using System;
using MLVScan.Models;

namespace MLVScan.Services
{
    internal static class ConsentMessageHelper
    {
        public static string GetUploadConsentMessage(string modName, string verdictKind, bool wasBlocked = true)
        {
            var label = string.IsNullOrWhiteSpace(modName) ? "this mod" : modName;
            if (string.Equals(verdictKind, ThreatVerdictKind.KnownMaliciousSample.ToString(), StringComparison.Ordinal) ||
                string.Equals(verdictKind, ThreatVerdictKind.KnownMalwareFamily.ToString(), StringComparison.Ordinal))
            {
                return wasBlocked
                    ? $"MLVScan identified {label} as likely malware and disabled it."
                    : $"MLVScan identified {label} as likely malware, but it was not blocked by the current configuration.";
            }

            if (string.IsNullOrWhiteSpace(verdictKind) ||
                string.Equals(verdictKind, ThreatVerdictKind.None.ToString(), StringComparison.Ordinal))
            {
                return wasBlocked
                    ? $"MLVScan blocked {label} because it could not complete full analysis and manual review is required."
                    : $"MLVScan could not complete full analysis of {label}, so manual review is required before you trust it.";
            }

            return wasBlocked
                ? $"MLVScan blocked {label} because it triggered suspicious behavior. It may still be a false positive."
                : $"MLVScan flagged {label} because it triggered suspicious behavior, but it was not blocked by the current configuration. It may still be a false positive.";
        }
    }
}
