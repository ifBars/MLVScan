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
            Log.LogInfo("MLVScan IL2CPP sharing consent prompt is ready.");
        }

        private sealed class ConsentPopupBehaviour : MonoBehaviour
        {
            public ConsentPopupBehaviour(IntPtr pointer) : base(pointer) { }

            private void OnDestroy() => _state?.Dispose();

            private void OnGUI()
            {
                _state?.DrawGui();
            }
        }

        private sealed class ConsentPopupState
        {
            private SharingConsentView _sharingConsentView;
            private readonly BepInExConfigManager _configManager;
            private readonly global::BepInEx.Logging.ManualLogSource _logger;
            private readonly ReportUploadService _reportUploadService;
            private string _pendingUploadPath = string.Empty;
            private string _pendingUploadName = string.Empty;
            private string _pendingUploadVerdictKind = string.Empty;
            private string _pendingUploadScanStatus = string.Empty;

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
                ShouldShowPopup = SharingConsentPolicy.NeedsDecision(config);

                if (!ShouldShowPopup)
                {
                    return;
                }

                _sharingConsentView = new SharingConsentView(SharingConsentPolicy.InitialFileChoice(config), HandleDecision);
                _pendingUploadPath = config.PendingReportUploadPath ?? string.Empty;
                _pendingUploadName = string.IsNullOrWhiteSpace(_pendingUploadPath)
                    ? "flagged mod"
                    : Path.GetFileName(_pendingUploadPath);
                _pendingUploadVerdictKind = config.PendingReportUploadVerdictKind ?? string.Empty;
                _pendingUploadScanStatus = config.PendingReportUploadScanStatusKind ?? string.Empty;
            }

            public void DrawGui() => _sharingConsentView?.Draw();
            public void Dispose() => _sharingConsentView?.Dispose();

            private void HandleDecision(bool approved, bool shareFiles)
            {
                ShouldShowPopup = false;

                var config = _configManager.LoadConfig();
                SharingConsentPolicy.ApplyDecision(config, approved, shareFiles, DateTimeOffset.UtcNow);
                _configManager.SaveConfig(config);

                if (!SharingConsentPolicy.CanUploadFiles(config))
                {
                    _logger.LogInfo("MLVScan sharing preferences saved. File uploads are off.");
                    return;
                }

                if (!string.IsNullOrWhiteSpace(_pendingUploadPath)) TryUploadPendingFile();
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

                    var bytes = ReportUploadService.ReadPrivateSampleBytes(_pendingUploadPath, _reportUploadService.RecordPreparationFailure);
                    var metadata = new SubmissionMetadata
                    {
                        LoaderType = "BepInEx6IL2CPP",
                        LoaderVersion = null,
                        PluginVersion = PlatformConstants.PlatformVersion,
                        ModName = RedactionHelper.RedactFilename(modName),
                        FindingSummary = new List<FindingSummaryItem>(),
                        OriginalVerdict = _pendingUploadVerdictKind,
                        OriginalScanStatus = _pendingUploadScanStatus,
                        ConsentVersion = SharingConsentPolicy.CurrentVersion.ToString(),
                        ConsentTimestamp = _configManager.Config.SharingConsentTimestamp
                    };

                    _reportUploadService.UploadReportNonBlocking(bytes, modName, metadata, apiBaseUrl);
                    _logger.LogInfo("MLVScan report upload enabled and initial mod upload queued.");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"MLVScan upload failed: {ex.Message}");
                }
            }
        }
    }
}
