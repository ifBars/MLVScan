using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using MelonLoader;
using MelonLoader.Utils;

namespace MLVScan.Runtime
{
    public class RuntimeProtectionService
    {
        private readonly MelonLogger.Instance _logger;
        private readonly bool _enableRuntimeProtection;
        private readonly bool _blockRiskyOperations;
        private readonly string[] _allowedModPaths;

        public RuntimeProtectionService(MelonLogger.Instance logger, bool enableRuntimeProtection, bool blockRiskyOperations)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _enableRuntimeProtection = enableRuntimeProtection;
            _blockRiskyOperations = blockRiskyOperations;

            // Get allowed mod paths (game directory and MelonLoader paths)
            var gameRoot = MelonEnvironment.GameRootDirectory;
            _allowedModPaths = new[]
            {
                gameRoot,
                Path.Combine(gameRoot, "MelonLoader"),
                Path.Combine(gameRoot, "Mods"),
                Path.Combine(gameRoot, "Plugins")
            };
        }

        public bool HandleRiskyOperation(string operationName, string details)
        {
            if (!_enableRuntimeProtection)
            {
                return true; // Allow operation if runtime protection is disabled
            }

            var callingMod = GetCallingMod();
            var stackTrace = GetFilteredStackTrace();

            _logger.Warning($"🚨 RISKY OPERATION DETECTED 🚨");
            _logger.Warning($"Operation: {operationName}");
            _logger.Warning($"Details: {details}");
            
            if (!string.IsNullOrEmpty(callingMod))
            {
                _logger.Warning($"Calling Mod: {callingMod}");
            }
            else
            {
                _logger.Warning("Calling Mod: Unknown (may be game code or system code)");
            }

            if (!string.IsNullOrEmpty(stackTrace))
            {
                _logger.Msg($"Stack Trace:\n{stackTrace}");
            }

            if (_blockRiskyOperations)
            {
                _logger.Error($"BLOCKED: {operationName} - Runtime protection is blocking this operation");
                return false; // Block the operation
            }
            else
            {
                _logger.Warning($"ALLOWED: {operationName} - Logging only mode (not blocking)");
                return true; // Allow but log
            }
        }

        public void LogRiskyOperation(string operationName, string details)
        {
            if (!_enableRuntimeProtection)
            {
                return;
            }

            var callingMod = GetCallingMod();
            _logger.Warning($"⚠️ Risky operation logged: {operationName} - {details}");
            if (!string.IsNullOrEmpty(callingMod))
            {
                _logger.Msg($"Called by: {callingMod}");
            }
        }

        private string GetCallingMod()
        {
            try
            {
                var stackTrace = new StackTrace(2, false); // Skip 2 frames (this method and HandleRiskyOperation)
                var frames = stackTrace.GetFrames();

                if (frames == null || frames.Length == 0)
                    return null;

                foreach (var frame in frames)
                {
                    var method = frame.GetMethod();
                    if (method == null)
                        continue;

                    var assembly = method.DeclaringType?.Assembly;
                    if (assembly == null)
                        continue;

                    var assemblyLocation = assembly.Location;
                    if (string.IsNullOrEmpty(assemblyLocation))
                        continue;

                    // Skip system assemblies
                    if (IsSystemAssembly(assemblyLocation))
                        continue;

                    // Skip MLVScan itself
                    if (assemblyLocation.Contains("MLVScan", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Check if it's from a mod directory
                    var modName = GetModNameFromPath(assemblyLocation);
                    if (!string.IsNullOrEmpty(modName))
                        return modName;

                    // Return assembly name as fallback
                    return Path.GetFileName(assemblyLocation);
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error identifying calling mod: {ex.Message}");
            }

            return null;
        }

        private string GetModNameFromPath(string assemblyPath)
        {
            try
            {
                var normalizedPath = Path.GetFullPath(assemblyPath);
                
                // Check if it's in a mod directory
                foreach (var allowedPath in _allowedModPaths)
                {
                    if (normalizedPath.StartsWith(allowedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        var relativePath = normalizedPath.Substring(allowedPath.Length).TrimStart(Path.DirectorySeparatorChar);
                        var parts = relativePath.Split(Path.DirectorySeparatorChar);
                        
                        if (parts.Length > 0)
                        {
                            return parts[0]; // Return first directory name after mod path
                        }
                    }
                }

                // Check common mod locations
                var modsPath = Path.Combine(MelonEnvironment.GameRootDirectory, "Mods");
                if (normalizedPath.StartsWith(modsPath, StringComparison.OrdinalIgnoreCase))
                {
                    var relativePath = normalizedPath.Substring(modsPath.Length).TrimStart(Path.DirectorySeparatorChar);
                    var parts = relativePath.Split(Path.DirectorySeparatorChar);
                    if (parts.Length > 0)
                    {
                        return parts[0];
                    }
                }

                var pluginsPath = Path.Combine(MelonEnvironment.GameRootDirectory, "Plugins");
                if (normalizedPath.StartsWith(pluginsPath, StringComparison.OrdinalIgnoreCase))
                {
                    var relativePath = normalizedPath.Substring(pluginsPath.Length).TrimStart(Path.DirectorySeparatorChar);
                    var parts = relativePath.Split(Path.DirectorySeparatorChar);
                    if (parts.Length > 0)
                    {
                        return parts[0];
                    }
                }
            }
            catch
            {
                // Ignore errors in path parsing
            }

            return null;
        }

        private bool IsSystemAssembly(string assemblyPath)
        {
            if (string.IsNullOrEmpty(assemblyPath))
                return true;

            var normalizedPath = assemblyPath.ToLowerInvariant();
            
            // Common system assembly locations
            return normalizedPath.Contains("\\windows\\") ||
                   normalizedPath.Contains("\\microsoft.net\\") ||
                   normalizedPath.Contains("\\gac\\") ||
                   normalizedPath.Contains("\\reference assemblies\\") ||
                   normalizedPath.Contains("\\mono\\") ||
                   normalizedPath.Contains("\\unity\\") ||
                   normalizedPath.Contains("unityengine") ||
                   normalizedPath.Contains("system.") ||
                   normalizedPath.Contains("mscorlib") ||
                   normalizedPath.Contains("netstandard");
        }

        private string GetFilteredStackTrace()
        {
            try
            {
                var stackTrace = new StackTrace(2, true); // Skip 2 frames, include file info
                var frames = stackTrace.GetFrames();
                
                if (frames == null || frames.Length == 0)
                    return null;

                var relevantFrames = frames
                    .Where(f =>
                    {
                        var method = f.GetMethod();
                        if (method == null)
                            return false;

                        var assembly = method.DeclaringType?.Assembly;
                        if (assembly == null)
                            return false;

                        var location = assembly.Location;
                        if (string.IsNullOrEmpty(location))
                            return false;

                        // Skip system assemblies and MLVScan itself
                        return !IsSystemAssembly(location) && 
                               !location.Contains("MLVScan", StringComparison.OrdinalIgnoreCase);
                    })
                    .Take(10) // Limit to 10 frames
                    .Select(f =>
                    {
                        var method = f.GetMethod();
                        var fileName = f.GetFileName();
                        var lineNumber = f.GetFileLineNumber();
                        
                        var methodName = method?.ToString() ?? "Unknown";
                        var location = !string.IsNullOrEmpty(fileName) 
                            ? $"{Path.GetFileName(fileName)}:{lineNumber}" 
                            : "Unknown location";
                        
                        return $"  at {methodName} in {location}";
                    })
                    .ToArray();

                return string.Join("\n", relevantFrames);
            }
            catch
            {
                return null;
            }
        }
    }
}

