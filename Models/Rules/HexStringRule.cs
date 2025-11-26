using MLVScan.Models;
using Mono.Cecil;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace MLVScan.Models.Rules
{
    public class HexStringRule : IScanRule
    {
        public string Description => "Detected hexadecimal encoded string (potential obfuscated payload).";
        public Severity Severity => Severity.Medium;

        // Regex for continuous hex strings (even length, min 16 chars)
        // We look for a sequence of hex digits that is at least 16 characters long.
        private static readonly Regex HexPattern = new Regex(@"^[0-9A-Fa-f]{16,}$", RegexOptions.Compiled);

        public bool IsSuspicious(MethodReference method)
        {
            // This rule focuses on string literals, but we could also look for Convert.FromHexString in the future.
            if (method.Name == "FromHexString" && method.DeclaringType.Name == "Convert")
            {
                return true;
            }
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method, int instructionIndex)
        {
            if (string.IsNullOrWhiteSpace(literal)) yield break;

            // Check if it looks like a hex string (must be even length for byte decoding)
            if (literal.Length % 2 == 0 && HexPattern.IsMatch(literal))
            {
                // Attempt to decode
                var decoded = DecodeHexString(literal);
                
                // Check if the decoded content is suspicious
                if (decoded != null && EncodedStringLiteralRule.ContainsSuspiciousContent(decoded))
                {
                    yield return new ScanFinding(
                        $"{method.DeclaringType.FullName}.{method.Name}:{instructionIndex}",
                        $"Hex-encoded string with suspicious content detected. Decoded: {decoded}",
                        Severity.High,
                        $"Encoded: {literal}\nDecoded: {decoded}");
                }
            }
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference calledMethod, Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int index, MethodSignals signals)
        {
            // No specific contextual pattern analysis for now, relying on string literal analysis
            yield break;
        }

        private string DecodeHexString(string hex)
        {
            try
            {
                var bytes = new byte[hex.Length / 2];
                for (int i = 0; i < hex.Length; i += 2)
                {
                    bytes[i / 2] = byte.Parse(hex.Substring(i, 2), NumberStyles.HexNumber);
                }
                // Try UTF8 first, fallback to ASCII if needed, but for now let's stick to a safe encoding that won't throw easily
                // Using ASCII or UTF8 is fine.
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return null;
            }
        }
    }
}
