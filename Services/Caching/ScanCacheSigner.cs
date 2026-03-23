using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MLVScan.Services.Caching
{
    internal sealed class ScanCacheSigner : IScanCacheSigner
    {
        private const int CryptProtectUiForbidden = 0x1;

        private readonly byte[] _secret;

        public ScanCacheSigner(string cacheDirectory)
        {
            var secretPath = Path.Combine(cacheDirectory, "secret.bin");
            _secret = LoadOrCreateSecret(secretPath, out var canTrustCleanEntries);
            CanTrustCleanEntries = canTrustCleanEntries && _secret.Length > 0;
        }

        public bool CanTrustCleanEntries { get; }

        public string Sign(byte[] payloadBytes)
        {
            if (payloadBytes == null || payloadBytes.Length == 0 || _secret.Length == 0)
            {
                return string.Empty;
            }

            using var hmac = new HMACSHA256(_secret);
            return Convert.ToBase64String(hmac.ComputeHash(payloadBytes));
        }

        public bool Verify(byte[] payloadBytes, string signature)
        {
            if (payloadBytes == null ||
                payloadBytes.Length == 0 ||
                string.IsNullOrEmpty(signature) ||
                _secret.Length == 0)
            {
                return false;
            }

            var expectedBytes = Encoding.UTF8.GetBytes(Sign(payloadBytes));
            var actualBytes = Encoding.UTF8.GetBytes(signature);
            return expectedBytes.Length == actualBytes.Length &&
                   CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        private static byte[] LoadOrCreateSecret(string secretPath, out bool canTrustCleanEntries)
        {
            canTrustCleanEntries = false;

            try
            {
                return RuntimeInformationHelper.IsWindows
                    ? LoadOrCreateWindowsSecret(secretPath, out canTrustCleanEntries)
                    : LoadOrCreatePortableSecret(secretPath, out canTrustCleanEntries);
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

            if (File.Exists(secretPath))
            {
                var existingSecret = File.ReadAllBytes(secretPath);
                try
                {
                    var unprotectedSecret = UnprotectForCurrentUser(existingSecret);
                    if (IsValidSecret(unprotectedSecret))
                    {
                        return unprotectedSecret;
                    }
                }
                catch
                {
                    if (IsValidSecret(existingSecret))
                    {
                        canTrustCleanEntries = false;
                        return existingSecret;
                    }
                }

                DeleteInvalidSecret(secretPath);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(secretPath)!);
            var secret = CreateRandomSecret();
            try
            {
                var protectedSecret = ProtectForCurrentUser(secret);
                AtomicFileStorage.WriteAllBytes(secretPath, protectedSecret);
            }
            catch
            {
                canTrustCleanEntries = false;
                AtomicFileStorage.WriteAllBytes(secretPath, secret);
            }

            return secret;
        }

        private static byte[] LoadOrCreatePortableSecret(string secretPath, out bool canTrustCleanEntries)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(secretPath)!);
            canTrustCleanEntries = false;

            if (File.Exists(secretPath))
            {
                var existingSecret = File.ReadAllBytes(secretPath);
                if (IsValidSecret(existingSecret))
                {
                    return existingSecret;
                }

                DeleteInvalidSecret(secretPath);
            }

            var secret = CreateRandomSecret();
            AtomicFileStorage.WriteAllBytes(secretPath, secret);
            return secret;
        }

        private static byte[] ProtectForCurrentUser(byte[] data)
        {
            var inputHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                var input = new DataBlob
                {
                    cbData = data.Length,
                    pbData = inputHandle.AddrOfPinnedObject()
                };

                if (!CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out var output))
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }

                try
                {
                    return CopyOutputBlob(output);
                }
                finally
                {
                    FreeOutputBlob(output);
                }
            }
            finally
            {
                inputHandle.Free();
            }
        }

        private static byte[] UnprotectForCurrentUser(byte[] data)
        {
            var inputHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                var input = new DataBlob
                {
                    cbData = data.Length,
                    pbData = inputHandle.AddrOfPinnedObject()
                };

                if (!CryptUnprotectData(ref input, out var description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out var output))
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }

                try
                {
                    return CopyOutputBlob(output);
                }
                finally
                {
                    if (description != IntPtr.Zero)
                    {
                        LocalFree(description);
                    }

                    FreeOutputBlob(output);
                }
            }
            finally
            {
                inputHandle.Free();
            }
        }

        private static byte[] CopyOutputBlob(DataBlob blob)
        {
            if (blob.cbData <= 0 || blob.pbData == IntPtr.Zero)
            {
                return Array.Empty<byte>();
            }

            var bytes = new byte[blob.cbData];
            Marshal.Copy(blob.pbData, bytes, 0, blob.cbData);
            return bytes;
        }

        private static void FreeOutputBlob(DataBlob blob)
        {
            if (blob.pbData != IntPtr.Zero)
            {
                LocalFree(blob.pbData);
            }
        }

        private static byte[] CreateRandomSecret()
        {
            var bytes = new byte[32];
            using var random = RandomNumberGenerator.Create();
            random.GetBytes(bytes);
            return bytes;
        }

        private static bool IsValidSecret(byte[] secret)
        {
            return secret != null && secret.Length == 32;
        }

        private static void DeleteInvalidSecret(string secretPath)
        {
            try
            {
                if (File.Exists(secretPath))
                {
                    File.Delete(secretPath);
                }
            }
            catch
            {
                // Ignore invalid secret cleanup failures and fall back to untrusted/no cache.
            }
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptProtectData(
            ref DataBlob pDataIn,
            string szDataDescr,
            IntPtr pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            int dwFlags,
            out DataBlob pDataOut);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptUnprotectData(
            ref DataBlob pDataIn,
            out IntPtr ppszDataDescr,
            IntPtr pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            int dwFlags,
            out DataBlob pDataOut);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob
        {
            public int cbData;
            public IntPtr pbData;
        }
    }
}
