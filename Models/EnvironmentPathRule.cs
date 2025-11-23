using Mono.Cecil;

namespace MLVScan.Models
{
    public class EnvironmentPathRule : IScanRule
    {
        public string Description => "Detected Environment.GetFolderPath access to sensitive directories (AppData, Startup, etc.).";
        public string Severity => "Medium";

        // Map of SpecialFolder enum values to names
        private static readonly Dictionary<int, string> SensitiveFolders = new Dictionary<int, string>
        {
            { 26, "ApplicationData" },      // %APPDATA%
            { 7, "Startup" },               // Startup folder
            { 28, "LocalApplicationData" }, // %LOCALAPPDATA%
            { 35, "CommonApplicationData" }, // %PROGRAMDATA%
            { 44, "CommonStartup" },        // All Users Startup
            { 5, "MyDocuments" },           // Documents (sometimes used for persistence)
            { 38, "ProgramFiles" },         // Program Files
            { 43, "Windows" },              // Windows directory
            { 37, "System" },               // System32
        };

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Detect Environment.GetFolderPath
            return typeName == "System.Environment" && methodName == "GetFolderPath";
        }

        public static bool IsSensitiveFolder(int folderValue)
        {
            return SensitiveFolders.ContainsKey(folderValue);
        }

        public static string GetFolderName(int folderValue)
        {
            return SensitiveFolders.TryGetValue(folderValue, out string name) ? name : $"Folder({folderValue})";
        }
    }
}
