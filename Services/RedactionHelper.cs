using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MLVScan.Services
{
    /// <summary>
    /// Redacts sensitive local data (paths, etc.) before sending to the API.
    /// Per privacy plan: send basename + optional hashed path fingerprint, not raw absolute paths.
    /// </summary>
    public static class RedactionHelper
    {
        /// <summary>
        /// Returns a safe filename for upload: basename only, no path.
        /// </summary>
        public static string RedactFilename(string pathOrFilename)
        {
            if (string.IsNullOrWhiteSpace(pathOrFilename))
                return "unknown.bin";
            var basename = Path.GetFileName(pathOrFilename);
            var sanitized = new StringBuilder();
            foreach (var c in basename)
            {
                if (char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-')
                    sanitized.Append(c);
            }
            return sanitized.Length > 0 ? sanitized.ToString() : "unknown.bin";
        }

        /// <summary>
        /// Redacts a location string that might contain file paths.
        /// If it looks like a path, returns basename + optional fingerprint; otherwise returns as-is.
        /// </summary>
        public static string RedactLocation(string location)
        {
            if (string.IsNullOrWhiteSpace(location))
                return location;

            if (LooksLikeAbsolutePath(location))
            {
                var basename = Path.GetFileName(location);
                if (!string.IsNullOrEmpty(basename))
                    return basename + " [path redacted]";
                return "[path redacted]";
            }

            return location;
        }

        /// <summary>
        /// Returns a short hash fingerprint for a path (for deduplication without exposing the path).
        /// </summary>
        public static string GetPathFingerprint(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;
            try
            {
                var bytes = Encoding.UTF8.GetBytes(path.ToLowerInvariant());
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(bytes);
                var hex = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                return hex.Length >= 12 ? hex.Substring(0, 12) : hex;
            }
            catch
            {
                return null;
            }
        }

        private static bool LooksLikeAbsolutePath(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 3)
                return false;
            if (s[0] == '/' || s[0] == '\\')
                return true;
            if (s.Length >= 3 && char.IsLetter(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))
                return true;
            if (s.Contains(":\\") || s.Contains(":/"))
                return true;
            return false;
        }
    }
}
