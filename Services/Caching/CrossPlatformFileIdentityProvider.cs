using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Mono.Unix;
using Mono.Unix.Native;

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
            if (RuntimeInformationHelper.IsWindows)
            {
                return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint);
            }

            if (Syscall.lstat(path, out var stat) != 0)
            {
                return false;
            }

            return (stat.st_mode & FilePermissions.S_IFMT) == FilePermissions.S_IFLNK;
        }

        private static string GetCanonicalPath(string path, SafeFileHandle handle)
        {
            if (RuntimeInformationHelper.IsWindows)
            {
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

            try
            {
                var realPath = GetUnixCanonicalPath(handle, path);
                return string.IsNullOrWhiteSpace(realPath)
                    ? path
                    : Path.GetFullPath(realPath);
            }
            catch
            {
                return path;
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
            var fd = GetUnixFileDescriptor(handle, path);
            if (Syscall.fstat(fd, out var stat) != 0)
            {
                throw new IOException($"fstat failed for {path}");
            }

            return new FileIdentitySnapshot
            {
                Platform = RuntimeInformationHelper.IsMacOs ? "macos" : "linux",
                HasStrongIdentity = true,
                IdentityKey = $"{stat.st_dev}:{stat.st_ino}",
                Size = stat.st_size,
                LastWriteUtcTicks = ConvertUnixTimeToUtcTicks(stat.st_mtime, stat.st_mtime_nsec),
                ChangeUtcTicks = ConvertUnixTimeToUtcTicks(stat.st_ctime, stat.st_ctime_nsec),
                IsSymlinkOrReparsePoint = isLink
            };
        }

        private static long ConvertUnixTimeToUtcTicks(long seconds, long nanoseconds)
        {
            return checked(DateTime.UnixEpoch.Ticks +
                (seconds * TimeSpan.TicksPerSecond) +
                (nanoseconds / 100));
        }

        private static int GetUnixFileDescriptor(SafeFileHandle handle, string path)
        {
            var rawHandle = handle.DangerousGetHandle().ToInt64();
            if (rawHandle < 0 || rawHandle > int.MaxValue)
            {
                throw new IOException($"File descriptor out of range for {path}");
            }

            return (int)rawHandle;
        }

        private static string GetUnixCanonicalPath(SafeFileHandle handle, string path)
        {
            var fd = GetUnixFileDescriptor(handle, path);
            var descriptorPath = RuntimeInformationHelper.IsLinux
                ? $"/proc/self/fd/{fd}"
                : $"/dev/fd/{fd}";

            var realPath = UnixPath.GetRealPath(descriptorPath);
            return string.IsNullOrWhiteSpace(realPath)
                ? path
                : realPath;
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
