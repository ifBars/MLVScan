using MelonLoader;
using MLVScan.Abstractions;

namespace MLVScan.Adapters
{
    /// <summary>
    /// Adapter that wraps MelonLoader's logging system to implement IScanLogger.
    /// </summary>
    public class MelonScanLogger : IScanLogger
    {
        private readonly MelonLogger.Instance _logger;

        public MelonScanLogger(MelonLogger.Instance logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public void Debug(string message) => _logger.Msg($"[DEBUG] {message}");
        public void Info(string message) => _logger.Msg(message);
        public void Warning(string message) => _logger.Warning(message);
        public void Error(string message) => _logger.Error(message);
        public void Error(string message, Exception exception) => _logger.Error($"{message}: {exception}");
    }
}
