using System;
using System.Collections.Generic;
using System.IO;
using BepInEx;
using MLVScan.Models;
using MLVScan.Services;
using UnityEngine;
#if BEPINEX6_MONO
using BepInEx.Unity.Mono;
#endif

namespace MLVScan.BepInEx
{
    [BepInPlugin("com.bars.mlvscan.consent", "MLVScan Consent", PlatformConstants.PlatformVersion)]
    public class BepInExConsentPlugin : BaseUnityPlugin
    {
        private BepInExConfigManager _configManager;
        private ReportUploadService _reportUploadService;
        private SharingConsentView _sharingConsentView;
        private string _pendingUploadPath = string.Empty;
        private string _pendingUploadName = string.Empty;
        private string _pendingUploadVerdictKind = string.Empty;
        private string _pendingUploadScanStatus = string.Empty;

        private void Awake()
        {
            try
            {
                _configManager = new BepInExConfigManager(Logger);
                var config = _configManager.LoadConfig();

                _reportUploadService = new ReportUploadService(
                    _configManager,
                    msg => Logger.LogInfo(msg),
                    msg => Logger.LogWarning(msg),
                    msg => Logger.LogError(msg));

                if (SharingConsentPolicy.NeedsDecision(config))
                {
                    _pendingUploadPath = config.PendingReportUploadPath ?? string.Empty;
                    _pendingUploadName = string.IsNullOrWhiteSpace(_pendingUploadPath)
                        ? "flagged mod"
                        : Path.GetFileName(_pendingUploadPath);
                    _pendingUploadVerdictKind = config.PendingReportUploadVerdictKind ?? string.Empty;
                    _pendingUploadScanStatus = config.PendingReportUploadScanStatusKind ?? string.Empty;
                    _sharingConsentView = new SharingConsentView(SharingConsentPolicy.InitialFileChoice(config), HandleDecision);
                    Logger.LogInfo("MLVScan upload consent popup is ready.");
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"Failed to initialize consent popup: {ex.Message}");
            }
        }

        private void OnGUI() => _sharingConsentView?.Draw();
        private void OnDestroy() => _sharingConsentView?.Dispose();

        private void HandleDecision(bool approved, bool shareFiles)
        {
            if (_configManager == null)
            {
                return;
            }

            var config = _configManager.LoadConfig();
            SharingConsentPolicy.ApplyDecision(config, approved, shareFiles, DateTimeOffset.UtcNow);
            _configManager.SaveConfig(config);

            if (!SharingConsentPolicy.CanUploadFiles(config))
            {
                Logger.LogInfo("MLVScan sharing preferences saved. File uploads are off.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(_pendingUploadPath)) TryUploadPendingFile();
        }

        private void TryUploadPendingFile()
        {
            try
            {
                if (_reportUploadService == null || string.IsNullOrWhiteSpace(_pendingUploadPath) || !File.Exists(_pendingUploadPath))
                {
                    Logger.LogWarning("MLVScan could not find the pending file to upload.");
                    return;
                }

                var apiBaseUrl = _configManager.GetReportUploadApiBaseUrl();
                if (string.IsNullOrWhiteSpace(apiBaseUrl))
                {
                    Logger.LogWarning("MLVScan report upload API URL is empty.");
                    return;
                }

                var modName = string.IsNullOrWhiteSpace(_pendingUploadName)
                    ? Path.GetFileName(_pendingUploadPath)
                    : _pendingUploadName;

                var bytes = ReportUploadService.ReadPrivateSampleBytes(_pendingUploadPath);
                var metadata = BuildSubmissionMetadata(modName);
                _reportUploadService.UploadReportNonBlocking(bytes, modName, metadata, apiBaseUrl);
                Logger.LogInfo("MLVScan report upload enabled and initial mod upload queued.");
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"MLVScan upload failed: {ex.Message}");
            }
        }

        private SubmissionMetadata BuildSubmissionMetadata(string modName)
        {
            return new SubmissionMetadata
            {
#if BEPINEX6_MONO
                LoaderType = "BepInEx6Mono",
#else
                LoaderType = "BepInEx5",
#endif
                LoaderVersion = null,
                PluginVersion = PlatformConstants.PlatformVersion,
                ModName = RedactionHelper.RedactFilename(modName),
                FindingSummary = new List<FindingSummaryItem>(),
                OriginalVerdict = _pendingUploadVerdictKind,
                OriginalScanStatus = _pendingUploadScanStatus,
                ConsentVersion = SharingConsentPolicy.CurrentVersion.ToString(),
                ConsentTimestamp = _configManager.Config.SharingConsentTimestamp
            };
        }

    }
}
