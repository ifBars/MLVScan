using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class DllImportRule : IScanRule
    {
        private Severity _severity = Severity.Medium;
        private string _description = "Detected DLL import";
        
        public string Description => _description;
        public Severity Severity => _severity;
        public string RuleId => "DllImportRule";
        public bool RequiresCompanionFinding => false;
        
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
            
            // Check if this is a PInvoke method
            if ((methodDef.Attributes & MethodAttributes.PInvokeImpl) == 0)
                return false;

            // Get PInvoke information
            if (methodDef.PInvokeInfo == null)
                return false;

            var dllName = methodDef.PInvokeInfo.Module.Name;
            var entryPoint = methodDef.PInvokeInfo.EntryPoint ?? method.Name;
            
            var lowerDllName = dllName.ToLower();
            var entryPointLower = entryPoint.ToLower();

            // Check for high-risk DLLs
            if (HighRiskDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
            {
                // If it's also using a high-risk function, mark as Critical
                if (HighRiskFunctions.Any(func => entryPointLower.Contains(func)))
                {
                    _severity = Severity.Critical;
                    _description = $"Detected high-risk DllImport of {dllName} with suspicious function {entryPoint}";
                    return true;
                }
                // Otherwise, mark as High risk
                _severity = Severity.High;
                _description = $"Detected high-risk DllImport of {dllName}";
                return true;
            }

            // Check EntryPoint for high-risk functions (even if DLL isn't high-risk)
            if (HighRiskFunctions.Any(func => entryPointLower.Contains(func)))
            {
                _severity = Severity.Critical;
                _description = $"Detected high-risk function {entryPoint} in DllImport from {dllName}";
                return true;
            }

            // Check for medium-risk DLLs
            if (MediumRiskDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
            {
                _severity = Severity.Medium;
                _description = $"Detected medium-risk DllImport of {dllName}";
                return true;
            }

            // Any other DLL import is considered Medium risk
            _severity = Severity.Medium;
            _description = $"Detected DllImport of {dllName}";
            return true;
        }
    }
}