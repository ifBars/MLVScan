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
        private bool _showConsentPopup;
        private string _pendingUploadPath = string.Empty;
        private string _pendingUploadName = string.Empty;
        private string _pendingUploadVerdictKind = string.Empty;

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

                if (config.ReportUploadConsentPending && !config.ReportUploadConsentAsked)
                {
                    _pendingUploadPath = config.PendingReportUploadPath ?? string.Empty;
                    _pendingUploadName = string.IsNullOrWhiteSpace(_pendingUploadPath)
                        ? "flagged mod"
                        : Path.GetFileName(_pendingUploadPath);
                    _pendingUploadVerdictKind = config.PendingReportUploadVerdictKind ?? string.Empty;
                    _showConsentPopup = true;
                    Logger.LogInfo("MLVScan upload consent popup is ready.");
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"Failed to initialize consent popup: {ex.Message}");
            }
        }

        private void OnGUI()
        {
            if (!_showConsentPopup)
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
                ConsentMessageHelper.GetUploadConsentMessage(_pendingUploadName, _pendingUploadVerdictKind) + "\n\n" +
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
            _showConsentPopup = false;

            if (_configManager == null)
            {
                return;
            }

            var config = _configManager.LoadConfig();
            config.ReportUploadConsentAsked = true;
            config.ReportUploadConsentPending = false;
            config.PendingReportUploadPath = string.Empty;
            config.PendingReportUploadVerdictKind = string.Empty;
            config.EnableReportUpload = approved;
            _configManager.SaveConfig(config);

            if (!approved)
            {
                Logger.LogInfo("MLVScan report upload declined. You will not be prompted again.");
                return;
            }

            TryUploadPendingFile();
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

                var bytes = File.ReadAllBytes(_pendingUploadPath);
                var metadata = BuildSubmissionMetadata(modName);
                _reportUploadService.UploadReportNonBlocking(bytes, modName, metadata, apiBaseUrl);
                Logger.LogInfo("MLVScan report upload enabled and initial mod upload queued.");
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"MLVScan upload failed: {ex.Message}");
            }
        }

        private static SubmissionMetadata BuildSubmissionMetadata(string modName)
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
                ConsentVersion = "1",
                ConsentTimestamp = DateTime.UtcNow.ToString("o")
            };
        }

    }
}
