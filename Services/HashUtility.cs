using System;
using System.IO;
using System.Security.Cryptography;

namespace MLVScan.Services
{
    /// <summary>
    /// Utility class for computing file hashes.
    /// Used for whitelisting and tracking disabled mods.
    /// </summary>
    public static class HashUtility
    {
        /// <summary>
        /// Calculates the SHA256 hash of a file.
        /// </summary>
        /// <param name="filePath">Path to the file to hash.</param>
        /// <returns>Lowercase hex string of the hash, or error message on failure.</returns>
        public static string CalculateFileHash(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return $"File not found: {filePath}";

                using var sha256 = SHA256.Create();
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch (UnauthorizedAccessException)
            {
                return "Access denied";
            }
            catch (IOException ex)
            {
                return $"IO Error: {ex.Message}";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }

        /// <summary>
        /// Validates that a string looks like a valid SHA256 hash.
        /// </summary>
        public static bool IsValidHash(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return false;

            // SHA256 produces 64 hex characters
            if (hash.Length != 64)
                return false;

            foreach (char c in hash)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            }

            return true;
        }
    }
}
