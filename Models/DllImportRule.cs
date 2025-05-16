using Mono.Cecil;

namespace MLVScan.Models
{
    public class DllImportRule : IScanRule
    {
        // List of DLLs that are often misused for malicious purposes
        private static readonly string[] HighRiskDlls =
        [
            "kernel32.dll",
            "user32.dll",
            "advapi32.dll",
            "ntdll.dll",
            "wininet.dll",
            "urlmon.dll",
            "winsock.dll",
            "ws2_32.dll",
            "psapi.dll",
            "dbghelp.dll",
            "shell32.dll"
        ];

        // List of DLLs that are less commonly used for malicious purposes but worth noting
        private static readonly string[] MediumRiskDlls =
        [
            "gdi32.dll",
            "ole32.dll",
            "oleaut32.dll",
            "comctl32.dll",
            "comdlg32.dll",
            "version.dll",
            "winmm.dll"
        ];

        // List of function names that might indicate malicious behavior
        private static readonly string[] HighRiskFunctions =
        [
            "createprocess",
            "virtualalloc",
            "virtualallocex",
            "virtualprotect",
            "writeprocessmemory",
            "readprocessmemory",
            "createremotethread",
            "openprocess",
            "internetopen",
            "internetconnect",
            "internetreadfile",
            "httpopen",
            "urldownload",
            "createthread",
            "loadlibrary",
            "getprocaddress",
            "createmutex",
            "openthread",
            "suspendthread",
            "resumethread",
            "inject",
            "memcpy",
            "strcpy",
            "shellexecute"
        ];

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            if (method.Resolve() is not { } methodDef) return false;
            foreach (var attribute in methodDef.CustomAttributes)
            {
                if (attribute.AttributeType.Name != "DllImportAttribute") continue;
                foreach (var arg in attribute.ConstructorArguments)
                {
                    if (arg.Value is not string dllName) continue;
                    var lowerDllName = dllName.ToLower();

                    // Check for high-risk DLLs
                    if (HighRiskDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
                    {
                        var methodNameLower = method.Name.ToLower();
                        // If it's also using a high-risk function, mark as Critical
                        if (HighRiskFunctions.Any(func => methodNameLower.Contains(func)))
                        {
                            _severity = "Critical";
                            _description = $"Detected high-risk DllImport of {dllName} with suspicious function {method.Name}";
                            return true;
                        }
                        // Otherwise, mark as High risk
                        _severity = "High";
                        _description = $"Detected high-risk DllImport of {dllName}";
                        return true;
                    }

                    // Check for medium-risk DLLs
                    if (MediumRiskDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
                    {
                        _severity = "Medium";
                        _description = $"Detected medium-risk DllImport of {dllName}";
                        return true;
                    }

                    // Any other DLL import is considered Medium risk
                    _severity = "Medium";
                    _description = $"Detected DllImport of {dllName}";
                    return true;
                }

                // Check EntryPoint property for high-risk functions
                foreach (var prop in attribute.Properties)
                {
                    if (prop.Name != "EntryPoint" || prop.Argument.Value is not string entryPoint) continue;
                    var entryPointLower = entryPoint.ToLower();
                    if (HighRiskFunctions.Any(func => entryPointLower.Contains(func)))
                    {
                        _severity = "Critical";
                        _description = $"Detected high-risk function {entryPoint} in DllImport";
                        return true;
                    }
                }
            }

            return false;
        }

        private string _severity = "Medium";
        private string _description = "Detected DLL import";

        public string Description => _description;
        public string Severity => _severity;
    }
}