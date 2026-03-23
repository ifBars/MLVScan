using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Mono.Unix.Native;

namespace MLVScan.Services.Caching
{
    internal sealed class ScanCacheSigner : IScanCacheSigner
    {
        private readonly byte[] _secret;

        public ScanCacheSigner(string cacheDirectory)
        {
            var secretPath = Path.Combine(cacheDirectory, "secret.bin");
            _secret = LoadOrCreateSecret(secretPath, out var canTrustCleanEntries);
            CanTrustCleanEntries = canTrustCleanEntries && _secret.Length > 0;
        }

        public bool CanTrustCleanEntries { get; }

        public string Sign(string payloadJson)
        {
            if (string.IsNullOrEmpty(payloadJson) || _secret.Length == 0)
            {
                return string.Empty;
            }

            using var hmac = new HMACSHA256(_secret);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payloadJson));
            return Convert.ToBase64String(hash);
        }

        public bool Verify(string payloadJson, string signature)
        {
            if (string.IsNullOrEmpty(payloadJson) ||
                string.IsNullOrEmpty(signature) ||
                _secret.Length == 0)
            {
                return false;
            }

            var expected = Sign(payloadJson);
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected),
                Encoding.UTF8.GetBytes(signature));
        }

        private static byte[] LoadOrCreateSecret(string secretPath, out bool canTrustCleanEntries)
        {
            canTrustCleanEntries = false;

            try
            {
                if (RuntimeInformationHelper.IsWindows)
                {
                    return LoadOrCreateWindowsSecret(secretPath, out canTrustCleanEntries);
                }

                return LoadOrCreateUnixSecret(secretPath, out canTrustCleanEntries);
            }
            catch
            {
                canTrustCleanEntries = false;
                return Array.Empty<byte>();
            }
        }

        private static byte[] LoadOrCreateWindowsSecret(string secretPath, out bool canTrustCleanEntries)
        {
            canTrustCleanEntries = true;
#pragma warning disable CA1416
            if (File.Exists(secretPath))
            {
                var existingSecret = File.ReadAllBytes(secretPath);
                try
                {
                    return ProtectedData.Unprotect(existingSecret, null, DataProtectionScope.CurrentUser);
                }
                catch
                {
                    if (existingSecret.Length == 32)
                    {
                        canTrustCleanEntries = false;
                        return existingSecret;
                    }

                    throw;
                }
            }

            Directory.CreateDirectory(Path.GetDirectoryName(secretPath)!);
            var secret = CreateRandomSecret();
            try
            {
                var protectedSecret = ProtectedData.Protect(secret, null, DataProtectionScope.CurrentUser);
                AtomicFileStorage.WriteAllBytes(secretPath, protectedSecret);
            }
            catch
            {
                canTrustCleanEntries = false;
                AtomicFileStorage.WriteAllBytes(secretPath, secret);
            }

            return secret;
#pragma warning restore CA1416
        }

        private static byte[] LoadOrCreateUnixSecret(string secretPath, out bool canTrustCleanEntries)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(secretPath)!);
            if (!File.Exists(secretPath))
            {
                CreateUnixSecret(secretPath, CreateRandomSecret());
            }

            canTrustCleanEntries = HasOwnerOnlyPermissions(secretPath);
            return File.ReadAllBytes(secretPath);
        }

        private static void CreateUnixSecret(string secretPath, byte[] secret)
        {
            const FilePermissions OwnerOnlyPermissions = FilePermissions.S_IRUSR | FilePermissions.S_IWUSR;
            var fd = Syscall.open(secretPath, OpenFlags.O_CREAT | OpenFlags.O_EXCL | OpenFlags.O_WRONLY, OwnerOnlyPermissions);
            if (fd < 0)
            {
                var errno = Stdlib.GetLastError();
                if (errno == Errno.EEXIST)
                {
                    return;
                }

                throw CreateUnixIoException("open", secretPath, errno);
            }

            var success = false;
            try
            {
                if (Syscall.fchmod(fd, OwnerOnlyPermissions) != 0)
                {
                    throw CreateUnixIoException("fchmod", secretPath);
                }

                using (var stream = new FileStream(new SafeFileHandle((IntPtr)fd, ownsHandle: false), FileAccess.Write))
                {
                    stream.Write(secret, 0, secret.Length);
                    stream.Flush(true);
                }

                if (Syscall.fsync(fd) != 0)
                {
                    throw CreateUnixIoException("fsync", secretPath);
                }

                success = true;
            }
            finally
            {
                Syscall.close(fd);

                if (!success && File.Exists(secretPath))
                {
                    try
                    {
                        File.Delete(secretPath);
                    }
                    catch
                    {
                        // Preserve the original failure if cleanup also fails.
                    }
                }
            }
        }

        private static bool HasOwnerOnlyPermissions(string secretPath)
        {
            if (Syscall.stat(secretPath, out var stat) != 0)
            {
                return false;
            }

            var forbidden = FilePermissions.S_IRWXG | FilePermissions.S_IRWXO;
            return (stat.st_mode & forbidden) == 0;
        }

        private static byte[] CreateRandomSecret()
        {
            var bytes = new byte[32];
            using var random = RandomNumberGenerator.Create();
            random.GetBytes(bytes);
            return bytes;
        }

        private static IOException CreateUnixIoException(string operation, string path, Errno? errno = null)
        {
            return new IOException($"{operation} failed for {path}: {errno ?? Stdlib.GetLastError()}");
        }
    }
}
