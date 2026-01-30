using System;
using BepInEx.Logging;
using MLVScan.Abstractions;

namespace MLVScan.BepInEx.Adapters
{
    /// <summary>
    /// Adapter that wraps BepInEx's logging system to implement IScanLogger.
    /// </summary>
    public class BepInExScanLogger : IScanLogger
    {
        private readonly ManualLogSource _logger;

        public BepInExScanLogger(ManualLogSource logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public void Debug(string message) => _logger.LogDebug(message);
        public void Info(string message) => _logger.LogInfo(message);
        public void Warning(string message) => _logger.LogWarning(message);
        public void Error(string message) => _logger.LogError(message);
        public void Error(string message, Exception exception) => _logger.LogError($"{message}: {exception}");
    }
}
