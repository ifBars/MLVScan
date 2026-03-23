using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace MLVScan.Services.Caching
{
    internal sealed class CrossPlatformFileIdentityProvider : IFileIdentityProvider
    {
        public FileProbe OpenProbe(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Path is required.", nameof(path));
            }

            var fullPath = Path.GetFullPath(path);
            var isLink = IsSymlinkOrReparsePoint(fullPath);
            var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            try
            {
                var canonicalPath = GetCanonicalPath(fullPath, stream.SafeFileHandle);
                var identity = RuntimeInformationHelper.IsWindows
                    ? CreateWindowsIdentity(fullPath, stream.SafeFileHandle, isLink)
                    : CreateUnixIdentity(fullPath, stream.SafeFileHandle, isLink);

                return new FileProbe(fullPath, canonicalPath, stream, identity, isLink);
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        private static bool IsSymlinkOrReparsePoint(string path)
        {
            try
            {
                return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint);
            }
            catch
            {
                return false;
            }
        }

        private static string GetCanonicalPath(string path, SafeFileHandle handle)
        {
            if (!RuntimeInformationHelper.IsWindows)
            {
                return path;
            }

            var builder = new StringBuilder(1024);
            while (true)
            {
                var result = GetFinalPathNameByHandle(handle, builder, builder.Capacity, 0);
                if (result == 0)
                {
                    return path;
                }

                if (result >= builder.Capacity)
                {
                    if (result >= int.MaxValue)
                    {
                        return path;
                    }

                    builder = new StringBuilder((int)result + 1);
                    continue;
                }

                return NormalizeWindowsDevicePath(builder.ToString(0, (int)result));
            }
        }

        private static FileIdentitySnapshot CreateWindowsIdentity(string path, SafeFileHandle handle, bool isLink)
        {
            if (!GetFileInformationByHandle(handle, out var info))
            {
                throw new IOException($"GetFileInformationByHandle failed for {path}");
            }

            var lastWriteUtcTicks = DateTime.FromFileTimeUtc((((long)info.ftLastWriteTime.dwHighDateTime) << 32) |
                (uint)info.ftLastWriteTime.dwLowDateTime).Ticks;
            var size = (((long)info.nFileSizeHigh) << 32) | (uint)info.nFileSizeLow;
            var fileId = $"{info.dwVolumeSerialNumber:x8}:{info.nFileIndexHigh:x8}{info.nFileIndexLow:x8}";

            return new FileIdentitySnapshot
            {
                Platform = "windows",
                HasStrongIdentity = true,
                IdentityKey = fileId,
                Size = size,
                LastWriteUtcTicks = lastWriteUtcTicks,
                ChangeUtcTicks = lastWriteUtcTicks,
                IsSymlinkOrReparsePoint = isLink
            };
        }

        private static FileIdentitySnapshot CreateUnixIdentity(string path, SafeFileHandle handle, bool isLink)
        {
            _ = handle;

            var info = new FileInfo(path);
            var lastWriteUtcTicks = info.LastWriteTimeUtc.Ticks;

            return new FileIdentitySnapshot
            {
                Platform = RuntimeInformationHelper.IsMacOs ? "macos" : "linux",
                // Keep Unix cache reuse on the hash path only so shared loader builds
                // do not need native helper assemblies just to read inode metadata.
                HasStrongIdentity = false,
                IdentityKey = Path.GetFullPath(path),
                Size = info.Exists ? info.Length : 0L,
                LastWriteUtcTicks = lastWriteUtcTicks,
                ChangeUtcTicks = lastWriteUtcTicks,
                IsSymlinkOrReparsePoint = isLink
            };
        }

        private static string NormalizeWindowsDevicePath(string path)
        {
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + path.Substring(8);
            }

            if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                return path.Substring(4);
            }

            return path;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle hFile,
            StringBuilder lpszFilePath,
            int cchFilePath,
            uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle hFile,
            out ByHandleFileInformation lpFileInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint dwFileAttributes;
            public FileTime ftCreationTime;
            public FileTime ftLastAccessTime;
            public FileTime ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }
    }
}
