using HarmonyLib;
using MelonLoader;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace MLVScan.Runtime
{
    public static class HarmonyPatches
    {
        private static MelonLogger.Instance _logger;
        private static RuntimeProtectionService _protectionService;

        public static void Initialize(MelonLogger.Instance logger, RuntimeProtectionService protectionService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _protectionService = protectionService ?? throw new ArgumentNullException(nameof(protectionService));

            try
            {
                var harmony = new HarmonyLib.Harmony("MLVScan.RuntimeProtection");

                // 1) Explicitly patch Process.Start overloads (PatchAll can miss/skip without throwing)
                var processType = typeof(Process);

                TryPatchPrefix(
                    harmony,
                    processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null),
                    nameof(ProcessStartPrefix),
                    logger,
                    "Process.Start() instance");

                TryPatchPrefix(
                    harmony,
                    processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(ProcessStartInfo) }, null),
                    nameof(ProcessStartWithInfoPrefix),
                    logger,
                    "Process.Start(ProcessStartInfo) static");

                TryPatchPrefix(
                    harmony,
                    processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(string) }, null),
                    nameof(ProcessStartStringPrefix),
                    logger,
                    "Process.Start(string) static");

                TryPatchPrefix(
                    harmony,
                    processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(string), typeof(string) }, null),
                    nameof(ProcessStartStringStringPrefix),
                    logger,
                    "Process.Start(string, string) static");

                // 2) Patch everything else via attributes
                harmony.PatchAll(typeof(HarmonyPatches).Assembly);
                logger.Msg("Harmony PatchAll applied for MLVScan runtime protection");

                // 3) Summary of what THIS harmony instance actually patched
                var patchedByThis = harmony.GetPatchedMethods().ToList();
                logger.Msg($"Harmony '{harmony.Id}' patched {patchedByThis.Count} method(s) total");

                // 4) Verify Process.Start patches were applied (this is the #1 reason 'it doesn't work')
                var startInstance = processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null);
                var startWithInfo = processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(ProcessStartInfo) }, null);
                var startString = processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(string) }, null);
                var startStringString = processType.GetMethod("Start", BindingFlags.Public | BindingFlags.Static, null, new[] { typeof(string), typeof(string) }, null);

                LogPatchStatus(logger, startInstance, "Process.Start() instance");
                LogPatchStatus(logger, startWithInfo, "Process.Start(ProcessStartInfo) static");
                LogPatchStatus(logger, startString, "Process.Start(string) static");
                LogPatchStatus(logger, startStringString, "Process.Start(string, string) static");
            }
            catch (Exception ex)
            {
                logger.Error($"Failed to initialize runtime protection patches: {ex.Message}");
                logger.Error(ex.StackTrace);
            }
        }

        private static void TryPatchPrefix(
            HarmonyLib.Harmony harmony,
            MethodBase original,
            string prefixMethodName,
            MelonLogger.Instance logger,
            string label)
        {
            if (original == null)
            {
                logger.Warning($"Runtime protection: could not resolve {label} method (not patchable on this runtime?)");
                return;
            }

            try
            {
                var prefix = typeof(HarmonyPatches).GetMethod(prefixMethodName, BindingFlags.Public | BindingFlags.Static);
                if (prefix == null)
                {
                    logger.Error($"Runtime protection: internal error - missing prefix method {prefixMethodName} for {label}");
                    return;
                }

                harmony.Patch(original, prefix: new HarmonyMethod(prefix));
                logger.Msg($"Runtime protection: explicitly patched {label}");
            }
            catch (Exception ex)
            {
                logger.Error($"Runtime protection: failed to patch {label}: {ex.Message}");
            }
        }

        private static void LogPatchStatus(MelonLogger.Instance logger, MethodBase method, string label)
        {
            if (method == null)
            {
                logger.Warning($"Runtime protection: could not resolve {label} method (not patchable on this runtime?)");
                return;
            }

            try
            {
                var info = HarmonyLib.Harmony.GetPatchInfo(method);
                if (info == null)
                {
                    logger.Warning($"Runtime protection: {label} has NO Harmony patch info (patch not applied)");
                    return;
                }

                var owners = info.Owners != null ? string.Join(", ", info.Owners) : "<none>";
                var prefixCount = info.Prefixes?.Count ?? 0;
                logger.Msg($"Runtime protection: {label} patched. owners=[{owners}] prefixes={prefixCount}");
            }
            catch (Exception ex)
            {
                logger.Warning($"Runtime protection: failed to query patch info for {label}: {ex.Message}");
            }
        }

        #region Process Operations

        [HarmonyPatch(typeof(Process), nameof(Process.Start), new Type[] { })]
        [HarmonyPrefix]
        public static bool ProcessStartPrefix(Process __instance, ref bool __result)
        {
            var processInfo = __instance.StartInfo?.FileName ?? "Unknown";
            _logger.Msg($"Process.Start called with process info: {processInfo}");

            var allow = _protectionService.HandleRiskyOperation("Process.Start", $"Process: {processInfo}");
            if (!allow)
            {
                __result = false;
                return false;
            }

            return true;
        }

        [HarmonyPatch(typeof(Process), nameof(Process.Start), new Type[] { typeof(ProcessStartInfo) })]
        [HarmonyPrefix]
        public static bool ProcessStartWithInfoPrefix(ProcessStartInfo startInfo, ref Process __result)
        {
            var processInfo = startInfo?.FileName ?? "Unknown";
            var arguments = startInfo?.Arguments ?? "";
            _logger.Msg($"Process.Start called with process info: {processInfo}, arguments: {arguments}");

            var allow = _protectionService.HandleRiskyOperation("Process.Start", $"Process: {processInfo}, Arguments: {arguments}");
            if (!allow)
            {
                __result = null;
                return false;
            }

            return true;
        }

        // Patch static method Process.Start(string fileName)
        [HarmonyPatch(typeof(Process), nameof(Process.Start), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool ProcessStartStringPrefix(string fileName, ref Process __result)
        {
            _logger.Msg($"Process.Start called with file name: {fileName}");

            var allow = _protectionService.HandleRiskyOperation("Process.Start", $"Process: {fileName}");
            if (!allow)
            {
                __result = null;
                return false;
            }

            return true;
        }

        // Patch static method Process.Start(string fileName, string arguments)
        [HarmonyPatch(typeof(Process), nameof(Process.Start), new Type[] { typeof(string), typeof(string) })]
        [HarmonyPrefix]
        public static bool ProcessStartStringStringPrefix(string fileName, string arguments, ref Process __result)
        {
            _logger.Msg($"Process.Start called with file name: {fileName}, arguments: {arguments}");

            var allow = _protectionService.HandleRiskyOperation("Process.Start", $"Process: {fileName}, Arguments: {arguments}");
            if (!allow)
            {
                __result = null;
                return false;
            }

            return true;
        }

        [HarmonyPatch(typeof(ProcessStartInfo), nameof(ProcessStartInfo.FileName), MethodType.Setter)]
        [HarmonyPrefix]
        public static void ProcessStartInfoFileNameSetter(ProcessStartInfo __instance, ref string value)
        {
            _logger.Msg($"ProcessStartInfo.FileName setter called with value: {value}");
            _protectionService.LogRiskyOperation("ProcessStartInfo.FileName", $"Setting process name: {value}");
        }

        #endregion

        #region Network Operations

        [HarmonyPatch(typeof(HttpWebRequest), nameof(HttpWebRequest.GetResponse))]
        [HarmonyPrefix]
        public static bool HttpWebRequestGetResponsePrefix(HttpWebRequest __instance)
        {
            var uri = __instance?.RequestUri?.ToString() ?? "Unknown";
            return _protectionService.HandleRiskyOperation("HttpWebRequest.GetResponse", $"URI: {uri}");
        }

        [HarmonyPatch(typeof(WebClient), nameof(WebClient.DownloadString), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool WebClientDownloadStringPrefix(WebClient __instance, string address)
        {
            return _protectionService.HandleRiskyOperation("WebClient.DownloadString", $"URI: {address}");
        }

        [HarmonyPatch(typeof(WebClient), nameof(WebClient.DownloadData), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool WebClientDownloadDataPrefix(WebClient __instance, string address)
        {
            return _protectionService.HandleRiskyOperation("WebClient.DownloadData", $"URI: {address}");
        }

        [HarmonyPatch(typeof(WebClient), nameof(WebClient.UploadString), new Type[] { typeof(string), typeof(string) })]
        [HarmonyPrefix]
        public static bool WebClientUploadStringPrefix(WebClient __instance, string address, string data)
        {
            return _protectionService.HandleRiskyOperation("WebClient.UploadString", $"URI: {address}");
        }

        [HarmonyPatch(typeof(WebClient), nameof(WebClient.UploadData), new Type[] { typeof(string), typeof(byte[]) })]
        [HarmonyPrefix]
        public static bool WebClientUploadDataPrefix(WebClient __instance, string address, byte[] data)
        {
            return _protectionService.HandleRiskyOperation("WebClient.UploadData", $"URI: {address}");
        }

        [HarmonyPatch(typeof(HttpClient), nameof(HttpClient.GetAsync), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool HttpClientGetAsyncPrefix(HttpClient __instance, string requestUri)
        {
            return _protectionService.HandleRiskyOperation("HttpClient.GetAsync", $"URI: {requestUri}");
        }

        [HarmonyPatch(typeof(HttpClient), nameof(HttpClient.PostAsync), new Type[] { typeof(string), typeof(HttpContent) })]
        [HarmonyPrefix]
        public static bool HttpClientPostAsyncPrefix(HttpClient __instance, string requestUri, HttpContent content)
        {
            return _protectionService.HandleRiskyOperation("HttpClient.PostAsync", $"URI: {requestUri}");
        }

        [HarmonyPatch(typeof(Socket), nameof(Socket.Connect), new Type[] { typeof(string), typeof(int) })]
        [HarmonyPrefix]
        public static bool SocketConnectPrefix(Socket __instance, string host, int port)
        {
            return _protectionService.HandleRiskyOperation("Socket.Connect", $"Host: {host}, Port: {port}");
        }

        [HarmonyPatch(typeof(Socket), nameof(Socket.Connect), new Type[] { typeof(IPEndPoint) })]
        [HarmonyPrefix]
        public static bool SocketConnectEndPointPrefix(Socket __instance, IPEndPoint remoteEP)
        {
            var endpoint = remoteEP?.ToString() ?? "Unknown";
            return _protectionService.HandleRiskyOperation("Socket.Connect", $"Endpoint: {endpoint}");
        }

        [HarmonyPatch(typeof(TcpClient), nameof(TcpClient.Connect), new Type[] { typeof(string), typeof(int) })]
        [HarmonyPrefix]
        public static bool TcpClientConnectPrefix(TcpClient __instance, string hostname, int port)
        {
            return _protectionService.HandleRiskyOperation("TcpClient.Connect", $"Host: {hostname}, Port: {port}");
        }

        [HarmonyPatch(typeof(UdpClient), nameof(UdpClient.Connect), new Type[] { typeof(string), typeof(int) })]
        [HarmonyPrefix]
        public static bool UdpClientConnectPrefix(UdpClient __instance, string hostname, int port)
        {
            return _protectionService.HandleRiskyOperation("UdpClient.Connect", $"Host: {hostname}, Port: {port}");
        }

        #endregion

        #region File System Operations

        [HarmonyPatch(typeof(File), nameof(File.Delete), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool FileDeletePrefix(string path)
        {
            return _protectionService.HandleRiskyOperation("File.Delete", $"Path: {path}");
        }

        [HarmonyPatch(typeof(File), nameof(File.WriteAllText), new Type[] { typeof(string), typeof(string) })]
        [HarmonyPrefix]
        public static bool FileWriteAllTextPrefix(string path, string contents)
        {
            return _protectionService.HandleRiskyOperation("File.WriteAllText", $"Path: {path}");
        }

        [HarmonyPatch(typeof(File), nameof(File.WriteAllBytes), new Type[] { typeof(string), typeof(byte[]) })]
        [HarmonyPrefix]
        public static bool FileWriteAllBytesPrefix(string path, byte[] bytes)
        {
            return _protectionService.HandleRiskyOperation("File.WriteAllBytes", $"Path: {path}");
        }

        [HarmonyPatch(typeof(File), nameof(File.Copy), new Type[] { typeof(string), typeof(string), typeof(bool) })]
        [HarmonyPrefix]
        public static bool FileCopyPrefix(string sourceFileName, string destFileName, bool overwrite)
        {
            return _protectionService.HandleRiskyOperation("File.Copy", $"Source: {sourceFileName}, Dest: {destFileName}");
        }

        [HarmonyPatch(typeof(File), nameof(File.Move), new Type[] { typeof(string), typeof(string) })]
        [HarmonyPrefix]
        public static bool FileMovePrefix(string sourceFileName, string destFileName)
        {
            return _protectionService.HandleRiskyOperation("File.Move", $"Source: {sourceFileName}, Dest: {destFileName}");
        }

        [HarmonyPatch(typeof(Directory), nameof(Directory.Delete), new Type[] { typeof(string), typeof(bool) })]
        [HarmonyPrefix]
        public static bool DirectoryDeletePrefix(string path, bool recursive)
        {
            return _protectionService.HandleRiskyOperation("Directory.Delete", $"Path: {path}, Recursive: {recursive}");
        }

        [HarmonyPatch(typeof(Directory), nameof(Directory.CreateDirectory), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool DirectoryCreateDirectoryPrefix(string path)
        {
            return _protectionService.HandleRiskyOperation("Directory.CreateDirectory", $"Path: {path}");
        }

        #endregion

        #region Environment Variable Operations

        [HarmonyPatch(typeof(Environment), nameof(Environment.SetEnvironmentVariable), new Type[] { typeof(string), typeof(string) })]
        [HarmonyPrefix]
        public static bool EnvironmentSetEnvironmentVariablePrefix(string variable, string value)
        {
            return _protectionService.HandleRiskyOperation("Environment.SetEnvironmentVariable", $"Variable: {variable}");
        }

        [HarmonyPatch(typeof(Environment), nameof(Environment.SetEnvironmentVariable), new Type[] { typeof(string), typeof(string), typeof(EnvironmentVariableTarget) })]
        [HarmonyPrefix]
        public static bool EnvironmentSetEnvironmentVariableTargetPrefix(string variable, string value, EnvironmentVariableTarget target)
        {
            return _protectionService.HandleRiskyOperation("Environment.SetEnvironmentVariable", $"Variable: {variable}, Target: {target}");
        }

        #endregion

        #region Reflection Operations (High Risk)

        [HarmonyPatch(typeof(Assembly), nameof(Assembly.LoadFrom), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool AssemblyLoadFromPrefix(string assemblyFile)
        {
            return _protectionService.HandleRiskyOperation("Assembly.LoadFrom", $"File: {assemblyFile}");
        }

        [HarmonyPatch(typeof(Assembly), nameof(Assembly.LoadFile), new Type[] { typeof(string) })]
        [HarmonyPrefix]
        public static bool AssemblyLoadFilePrefix(string path)
        {
            return _protectionService.HandleRiskyOperation("Assembly.LoadFile", $"Path: {path}");
        }

        [HarmonyPatch(typeof(Assembly), nameof(Assembly.Load), new Type[] { typeof(byte[]) })]
        [HarmonyPrefix]
        public static bool AssemblyLoadBytesPrefix(byte[] rawAssembly)
        {
            return _protectionService.HandleRiskyOperation("Assembly.Load", "Loading assembly from byte array");
        }

        #endregion
    }
}