namespace MLVScan.Models
{
    public class ScanFinding(string location, string description, string severity = "Warning")
    {
        public string Location { get; set; } = location;
        public string Description { get; set; } = description;
        public string Severity { get; set; } = severity;

        public override string ToString()
        {
            return $"[{Severity}] {Description} at {Location}";
        }
    }
}
