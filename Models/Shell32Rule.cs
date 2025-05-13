using Mono.Cecil;

namespace MLVScan.Models
{
    public class Shell32Rule : IScanRule
    {
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            if (typeName.Contains("Shell32") ||
                typeName.Contains("shell32") ||
                method.Name.Contains("ShellExecute"))
                return true;

            if (method.Resolve() is not { } methodDef) return false;
            foreach (var attribute in methodDef.CustomAttributes.Where(attribute => attribute.AttributeType.Name == "DllImportAttribute"))
            {
                foreach (var arg in attribute.ConstructorArguments)
                {
                    if (arg.Value is string dllName &&
                        (dllName.ToLower().Contains("shell32") ||
                         dllName.ToLower() == "shell32.dll"))
                    {
                        return true;
                    }
                }

                foreach (var arg in attribute.Properties.Where(arg => arg.Name == "EntryPoint" || arg.Name == "ModuleName"))
                {
                    if (arg.Argument.Value is string value &&
                        (value.ToLower().Contains("shell32") ||
                         value.ToLower() == "shell32.dll"))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public string Description => "Detected Shell32 API usage. This could be used to execute arbitrary commands.";

        public string Severity => "Critical";
    }
}