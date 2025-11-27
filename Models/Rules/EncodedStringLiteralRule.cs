using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Text.RegularExpressions;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class EncodedStringLiteralRule : IScanRule
    {
        public string Description => "Detected numeric-encoded string literals (potential obfuscated payload).";
        public Severity Severity => Severity.High;
        public string RuleId => "EncodedStringLiteralRule";
        public bool RequiresCompanionFinding => false;

        private static readonly Regex DashSeparatedPattern = new Regex(@"^\d{2,3}(-\d{2,3}){10,}$", RegexOptions.Compiled);
        private static readonly Regex DotSeparatedPattern = new Regex(@"^\d{2,3}(\.\d{2,3}){10,}$", RegexOptions.Compiled);
        private static readonly Regex BacktickSeparatedPattern = new Regex(@"^\d{2,3}(`\d{2,3}){10,}$", RegexOptions.Compiled);

        private static readonly string[] SuspiciousKeywords =
        {
            "Process", "ProcessStartInfo", "powershell", "cmd.exe", "Start",
            "Execute", "Shell", ".ps1", ".bat", ".exe", "WindowStyle",
            "Hidden", "ExecutionPolicy", "Invoke-WebRequest", "DownloadFile",
            "FromBase64String", "Assembly.Load", "Reflection", "GetMethod",
            "CreateInstance", "Activator", "AppData", "Startup", "Registry",
            "RunOnce", "CurrentVersion\\Run"
        };

        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze string literals in IL code
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method, int instructionIndex)
        {
            if (string.IsNullOrWhiteSpace(literal))
                yield break;

            if (IsEncodedString(literal))
            {
                var decoded = DecodeNumericString(literal);
                if (decoded != null && ContainsSuspiciousContent(decoded))
                {
                    yield return new ScanFinding(
                        $"{method.DeclaringType.FullName}.{method.Name}:{instructionIndex}",
                        $"Numeric-encoded string with suspicious content detected. Decoded: {decoded}",
                        Severity.High,
                        $"Encoded: {literal}\nDecoded: {decoded}");
                }
            }
        }

        public IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            var findings = new List<ScanFinding>();
            
            try
            {
                foreach (var attr in assembly.CustomAttributes)
                {
                    if (attr.AttributeType.Name == "AssemblyMetadataAttribute" && attr.HasConstructorArguments)
                    {
                        foreach (var arg in attr.ConstructorArguments)
                        {
                            if (arg.Value is string strValue && !string.IsNullOrWhiteSpace(strValue))
                            {
                                // Check for numeric encoding patterns
                                if (IsEncodedString(strValue))
                                {
                                    var decoded = DecodeNumericString(strValue);
                                    if (decoded != null && ContainsSuspiciousContent(decoded))
                                    {
                                        findings.Add(new ScanFinding(
                                            $"Assembly Metadata: {attr.AttributeType.Name}",
                                            $"Hidden payload in assembly metadata attribute. Decoded content: {decoded}",
                                            Severity.Critical,
                                            $"Encoded: {strValue}\nDecoded: {decoded}"));
                                    }
                                }
                                // Also check for dot-separated encoding used in metadata
                                else if (strValue.Contains('.') && strValue.Split('.').Length >= 10)
                                {
                                    var decoded = DecodeNumericString(strValue);
                                    if (decoded != null && ContainsSuspiciousContent(decoded))
                                    {
                                        findings.Add(new ScanFinding(
                                            $"Assembly Metadata: {attr.AttributeType.Name}",
                                            $"Hidden payload in assembly metadata attribute. Decoded content: {decoded}",
                                            Severity.Critical,
                                            $"Encoded: {strValue}\nDecoded: {decoded}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                // Skip metadata scanning if it fails
            }
            
            return findings;
        }

        public static bool IsEncodedString(string literal)
        {
            if (string.IsNullOrWhiteSpace(literal))
                return false;

            return DashSeparatedPattern.IsMatch(literal) ||
                   DotSeparatedPattern.IsMatch(literal) ||
                   BacktickSeparatedPattern.IsMatch(literal);
        }

        public static string DecodeNumericString(string encoded)
        {
            try
            {
                char delimiter = '-';
                if (encoded.Contains('.')) delimiter = '.';
                else if (encoded.Contains('`')) delimiter = '`';

                var parts = encoded.Split(delimiter);
                var decoded = new char[parts.Length];

                for (int i = 0; i < parts.Length; i++)
                {
                    if (int.TryParse(parts[i], out int charCode) && charCode >= 0 && charCode <= 127)
                    {
                        decoded[i] = (char)charCode;
                    }
                    else
                    {
                        return null; // Invalid encoding
                    }
                }

                return new string(decoded);
            }
            catch
            {
                return null;
            }
        }

        public static bool ContainsSuspiciousContent(string decodedText)
        {
            if (string.IsNullOrWhiteSpace(decodedText))
                return false;

            foreach (var keyword in SuspiciousKeywords)
            {
                if (decodedText.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}

