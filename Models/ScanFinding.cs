namespace MLVScan.Models
{
    public class ScanFinding(string location, string description, string severity = "Low", string codeSnippet = null)
    {
        public string Location { get; set; } = location;
        public string Description { get; set; } = description;
        public string Severity { get; set; } = severity;
        public string CodeSnippet { get; set; } = codeSnippet;

        public override string ToString()
        {
            var logMessage = $"[{Severity}] {Description} at {Location}";
            if (!string.IsNullOrEmpty(CodeSnippet))
            {
                logMessage += $"\n   Snippet: {CodeSnippet}";
            }
            return logMessage;
        }
    }
}
