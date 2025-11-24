using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class Shell32Rule : IScanRule
    {
        public string Description => "Potential system shell execution detected";
        public Severity Severity => Severity.Critical;

        public bool IsSuspicious(MethodReference method)
        {
            if (method == null || method.DeclaringType == null)
                return false;
                
            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;
            
            // Direct Shell.Application method calls
            if (typeName.Contains("Shell.Application") || typeName.Contains("Shell32"))
                return true;
                
            // Shell Execute via COM
            if (methodName == "ShellExecute" || methodName == "ShellExec")
                return true;
                
            // Type.GetTypeFromProgID with Shell.Application
            if (methodName == "GetTypeFromProgID")
            {
                // Check parameters for Shell.Application
                foreach (var param in method.Parameters)
                {
                    if (param.Name.Contains("Shell") || param.Name.Contains("shell32"))
                        return true;
                }
            }
            
            // COM Type activation related to shell
            if (methodName == "GetTypeFromProgID" && 
                method.Parameters.Count > 0 && 
                method.Parameters[0].Name.Contains("Shell"))
                return true;
                
            // InvokeMember calls to ShellExecute
            if (methodName == "InvokeMember")
            {
                if (method.Parameters.Count > 0)
                {
                    // Look for "ShellExecute" as first parameter
                    var firstParam = method.Parameters[0];
                    if (firstParam.Name.Contains("ShellExecute") || firstParam.Name.Contains("Execute"))
                        return true;
                }
            }
            
            // Check for cmd.exe execution
            if (methodName == "Start" || methodName == "Process" || methodName == "Execute")
            {
                foreach (var param in method.Parameters)
                {
                    if (param.Name.Contains("cmd") || param.Name.Contains("powershell") || param.Name.Contains(".exe"))
                        return true;
                }
            }
                
            return false;
        }
    }
}