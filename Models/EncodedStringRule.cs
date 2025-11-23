using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Text.RegularExpressions;

namespace MLVScan.Models
{
    public class EncodedStringRule : IScanRule
    {
        public string Description => "Detected numeric-encoded strings (potential obfuscated payload).";
        public string Severity => "High";

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
