using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    public class SignalTracker
    {
        private readonly Dictionary<string, MethodSignals> _typeSignals;
        private readonly ScanConfig _config;

        public SignalTracker(ScanConfig config)
        {
            _config = config ?? new ScanConfig();
            _typeSignals = new Dictionary<string, MethodSignals>();
        }

        public MethodSignals CreateMethodSignals()
        {
            return _config.EnableMultiSignalDetection ? new MethodSignals() : null;
        }

        public MethodSignals GetOrCreateTypeSignals(string typeFullName)
        {
            if (!_config.EnableMultiSignalDetection)
                return null;

            if (!_typeSignals.TryGetValue(typeFullName, out var typeSignal))
            {
                typeSignal = new MethodSignals();
                _typeSignals[typeFullName] = typeSignal;
            }

            return typeSignal;
        }

        public MethodSignals GetTypeSignals(string typeFullName)
        {
            return _typeSignals.TryGetValue(typeFullName, out var typeSignal) ? typeSignal : null;
        }

        public void ClearTypeSignals(string typeFullName)
        {
            _typeSignals.Remove(typeFullName);
        }

        public void UpdateMethodSignals(MethodSignals signals, MethodReference method, TypeDefinition declaringType)
        {
            if (method?.DeclaringType == null || signals == null)
                return;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Check for Base64
            if (typeName.Contains("Convert") && methodName.Contains("FromBase64"))
            {
                signals.HasBase64 = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasBase64 = true;
                    }
                }
            }

            // Check for Process.Start
            if (typeName.Contains("System.Diagnostics.Process") && methodName == "Start")
            {
                signals.HasProcessLikeCall = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasProcessLikeCall = true;
                    }
                }
            }

            // Check for reflection invocation
            if ((typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke"))
            {
                signals.HasSuspiciousReflection = true;
            }

            // Check for network calls
            if (typeName.StartsWith("System.Net") || typeName.Contains("WebRequest") ||
                typeName.Contains("HttpClient") || typeName.Contains("WebClient"))
            {
                signals.HasNetworkCall = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasNetworkCall = true;
                    }
                }
            }

            // Check for file writes
            if ((typeName.StartsWith("System.IO.File") && (methodName.Contains("Write") || methodName.Contains("Create"))) ||
                (typeName.StartsWith("System.IO.Stream") && methodName.Contains("Write")))
            {
                signals.HasFileWrite = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasFileWrite = true;
                    }
                }
            }
        }

        public void MarkEncodedStrings(MethodSignals methodSignals, TypeDefinition declaringType)
        {
            if (methodSignals == null)
                return;

            methodSignals.HasEncodedStrings = true;
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.HasEncodedStrings = true;
                }
            }
        }

        public void MarkSensitiveFolder(MethodSignals methodSignals, TypeDefinition declaringType)
        {
            if (methodSignals == null)
                return;

            methodSignals.UsesSensitiveFolder = true;
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.UsesSensitiveFolder = true;
                }
            }
        }

        /// <summary>
        /// Marks a rule as having been triggered in the given method and type signals
        /// </summary>
        public void MarkRuleTriggered(MethodSignals methodSignals, TypeDefinition declaringType, string ruleId)
        {
            if (methodSignals == null || string.IsNullOrEmpty(ruleId))
                return;

            methodSignals.MarkRuleTriggered(ruleId);
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.MarkRuleTriggered(ruleId);
                }
            }
        }
    }
}

