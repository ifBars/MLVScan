using Mono.Cecil;

namespace MLVScan.Models
{
    public class ReflectionRule : IScanRule
    {
        private readonly bool _paranoidMode;

        public ReflectionRule(bool paranoidMode = false)
        {
            _paranoidMode = paranoidMode;
        }

        public string Description => "Detected reflection invocation without determinable target method (potential bypass).";
        public string Severity => _paranoidMode ? "High" : "Medium";

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Detect reflection invoke methods
            bool isReflectionInvoke =
                (typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke");

            return isReflectionInvoke;
        }

        public static bool IsInLegitimateContext(MethodDefinition methodDef)
        {
            if (methodDef?.DeclaringType == null)
                return true;

            // Check typical patterns for legitimate mod reflection usage
            var typeName = methodDef.DeclaringType.FullName;
            var methodNameStr = methodDef.Name;
            var namespaceStr = methodDef.DeclaringType.Namespace ?? string.Empty;

            // 1. Harmony/MonoMod patching context (including Prefix, Postfix, Transpiler, Finalizer)
            if (typeName.Contains("Patch") || typeName.Contains("Harmony") ||
                methodNameStr.Contains("Patch") || typeName.Contains("MonoMod") ||
                methodNameStr.Contains("Prefix") || methodNameStr.Contains("Postfix") ||
                methodNameStr.Contains("Transpiler") || methodNameStr.Contains("Finalizer"))
                return true;

            // 2. MelonLoader or Unity framework context
            if (typeName.Contains("MelonLoader") || namespaceStr.Contains("MelonLoader") ||
                namespaceStr.Contains("UnityEngine") || namespaceStr.StartsWith("Il2Cpp") ||
                typeName.Contains("Melon") || methodNameStr.Contains("Melon"))
                return true;

            // 3. Il2Cpp interop - legitimate reflection for Unity IL2CPP games
            if (typeName.Contains("Il2Cpp") || namespaceStr.Contains("Il2Cpp") ||
                methodNameStr.Contains("Il2Cpp"))
                return true;

            // 4. Internal/API namespaces - typically legitimate mod frameworks
            // Check for .Internal, .API anywhere in namespace or type name (not just with surrounding dots)
            if (namespaceStr.Contains("Internal") || namespaceStr.Contains("API") ||
                typeName.Contains("Internal") || typeName.Contains("API"))
                return true;

            // 4a. Helpers/Extensions classes - typically legitimate utility classes
            if (typeName.Contains("Helpers") || typeName.Contains("Extensions") ||
                namespaceStr.Contains("Helpers") || namespaceStr.Contains("Extensions"))
                return true;

            // 4b. Entities/Patches/Cartel/Vehicles namespaces - common mod structure patterns
            if (namespaceStr.Contains("Entities") || namespaceStr.Contains("Patches") ||
                namespaceStr.Contains("Cartel") || namespaceStr.Contains("Vehicles") ||
                namespaceStr.Contains("Map") || namespaceStr.Contains("Abstraction"))
                return true;

            // 5. Typical mod initialization and lifecycle methods
            if (methodNameStr == "OnInitializeMelon" || methodNameStr == "OnApplicationStart" ||
                methodNameStr == "OnSceneWasLoaded" || methodNameStr == "OnSceneWasInitialized" ||
                methodNameStr == "OnUpdate" || methodNameStr == "OnFixedUpdate" ||
                methodNameStr == "OnLateUpdate" || methodNameStr == "OnGUI" ||
                methodNameStr.StartsWith("On") || methodNameStr.Contains("Initialize") ||
                methodNameStr.Contains("Setup"))
                return true;

            // 6. Compiler-generated methods (state machines, lambda closures, etc.)
            if (typeName.Contains("<") || typeName.Contains(">") ||
                methodNameStr == "MoveNext" || methodNameStr.StartsWith("<"))
                return true;

            return false;
        }
    }
}
