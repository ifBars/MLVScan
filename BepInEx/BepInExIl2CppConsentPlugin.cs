using System;
using System.Collections.Generic;
using System.IO;
using BepInEx;
using BepInEx.Unity.IL2CPP;
using Il2CppInterop.Runtime.Injection;
using MLVScan.Models;
using MLVScan.Services;
using UnityEngine;

namespace MLVScan.BepInEx
{
    [BepInPlugin("com.bars.mlvscan.consent.il2cpp", "MLVScan Consent IL2CPP", PlatformConstants.PlatformVersion)]
    public class BepInExIl2CppConsentPlugin : BasePlugin
    {
        private static ConsentPopupState _state;

        public override void Load()
        {
            _state = ConsentPopupState.Create(Log);
            if (_state == null || !_state.ShouldShowPopup)
            {
                return;
            }

            ClassInjector.RegisterTypeInIl2Cpp<ConsentPopupBehaviour>();
            IL2CPPChainloader.AddUnityComponent(typeof(ConsentPopupBehaviour));
            Log.LogInfo("MLVScan IL2CPP upload consent popup is ready.");
        }

        private sealed class ConsentPopupBehaviour : MonoBehaviour
        {
            private void OnGUI()
            {
                _state?.DrawGui();
            }
        }

        private sealed class ConsentPopupState
        {
            private readonly BepInExConfigManager _configManager;
            private readonly global::BepInEx.Logging.ManualLogSource _logger;
            private readonly ReportUploadService _reportUploadService;
            private string _pendingUploadPath = string.Empty;
            private string _pendingUploadName = string.Empty;
            private string _pendingUploadVerdictKind = string.Empty;

            public bool ShouldShowPopup { get; private set; }

            private ConsentPopupState(global::BepInEx.Logging.ManualLogSource logger)
            {
                _logger = logger;
                _configManager = new BepInExConfigManager(_logger);
                _reportUploadService = new ReportUploadService(
                    _configManager,
                    msg => _logger.LogInfo(msg),
                    msg => _logger.LogWarning(msg),
                    msg => _logger.LogError(msg));
            }

            public static ConsentPopupState Create(global::BepInEx.Logging.ManualLogSource logger)
            {
                try
                {
                    var state = new ConsentPopupState(logger);
                    state.Initialize();
                    return state;
                }
                catch (Exception ex)
                {
                    logger?.LogWarning($"Failed to initialize IL2CPP consent popup: {ex.Message}");
                    return null;
                }
            }

            private void Initialize()
            {
                var config = _configManager.LoadConfig();
                ShouldShowPopup = config.ReportUploadConsentPending && !config.ReportUploadConsentAsked;

                if (!ShouldShowPopup)
                {
                    return;
                }

                _pendingUploadPath = config.PendingReportUploadPath ?? string.Empty;
                _pendingUploadName = string.IsNullOrWhiteSpace(_pendingUploadPath)
                    ? "flagged mod"
                    : Path.GetFileName(_pendingUploadPath);
                _pendingUploadVerdictKind = config.PendingReportUploadVerdictKind ?? string.Empty;
            }

            public void DrawGui()
            {
                if (!ShouldShowPopup)
                {
                    return;
                }

                var width = Math.Min(620f, Screen.width - 40f);
                var height = 280f;
                var x = (Screen.width - width) / 2f;
                var y = (Screen.height - height) / 2f;

                GUI.Box(new Rect(0f, 0f, Screen.width, Screen.height), string.Empty);
                GUI.Box(new Rect(x, y, width, height), "MLVScan Upload Consent");
                GUI.Label(new Rect(x + 20f, y + 40f, width - 40f, 140f),
                    GetUploadConsentMessage(_pendingUploadName, _pendingUploadVerdictKind) + "\n\n" +
                    "Would you like to upload this file to the MLVScan API for human review?\n\n" +
                    "Yes: upload this mod now and enable automatic uploads for future detections.\n" +
                    "No: do not upload and do not show this prompt again.");

                if (GUI.Button(new Rect(x + 20f, y + height - 60f, (width - 60f) / 2f, 36f), "Yes, upload"))
                {
                    HandleDecision(true);
                }

                if (GUI.Button(new Rect(x + 40f + (width - 60f) / 2f, y + height - 60f, (width - 60f) / 2f, 36f), "No thanks"))
                {
                    HandleDecision(false);
                }
            }

            private void HandleDecision(bool approved)
            {
                ShouldShowPopup = false;

                var config = _configManager.LoadConfig();
                config.ReportUploadConsentAsked = true;
                config.ReportUploadConsentPending = false;
                config.PendingReportUploadPath = string.Empty;
                config.PendingReportUploadVerdictKind = string.Empty;
                config.EnableReportUpload = approved;
                _configManager.SaveConfig(config);

                if (!approved)
                {
                    _logger.LogInfo("MLVScan report upload declined. You will not be prompted again.");
                    return;
                }

                TryUploadPendingFile();
            }

            private void TryUploadPendingFile()
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(_pendingUploadPath) || !File.Exists(_pendingUploadPath))
                    {
                        _logger.LogWarning("MLVScan could not find the pending file to upload.");
                        return;
                    }

                    var apiBaseUrl = _configManager.GetReportUploadApiBaseUrl();
                    if (string.IsNullOrWhiteSpace(apiBaseUrl))
                    {
                        _logger.LogWarning("MLVScan report upload API URL is empty.");
                        return;
                    }

                    var modName = string.IsNullOrWhiteSpace(_pendingUploadName)
                        ? Path.GetFileName(_pendingUploadPath)
                        : _pendingUploadName;

                    var bytes = File.ReadAllBytes(_pendingUploadPath);
                    var metadata = new SubmissionMetadata
                    {
                        LoaderType = "BepInEx6IL2CPP",
                        LoaderVersion = null,
                        PluginVersion = PlatformConstants.PlatformVersion,
                        ModName = RedactionHelper.RedactFilename(modName),
                        FindingSummary = new List<FindingSummaryItem>(),
                        ConsentVersion = "1",
                        ConsentTimestamp = DateTime.UtcNow.ToString("o")
                    };

                    _reportUploadService.UploadReportNonBlocking(bytes, modName, metadata, apiBaseUrl);
                    _logger.LogInfo("MLVScan report upload enabled and initial mod upload queued.");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"MLVScan upload failed: {ex.Message}");
                }
            }

            private static string GetUploadConsentMessage(string modName, string verdictKind)
            {
                var label = string.IsNullOrWhiteSpace(modName) ? "this mod" : modName;
                if (string.Equals(verdictKind, ThreatVerdictKind.KnownMaliciousSample.ToString(), StringComparison.Ordinal) ||
                    string.Equals(verdictKind, ThreatVerdictKind.KnownMalwareFamily.ToString(), StringComparison.Ordinal))
                {
                    return $"MLVScan identified {label} as likely malware and disabled it.";
                }

                return $"MLVScan blocked {label} because it triggered suspicious behavior. It may still be a false positive.";
            }
        }
    }
}
