using System.IO;

namespace MLVScan.Services.Caching
{
    internal static class AtomicFileStorage
    {
        public static void WriteAllBytes(string path, byte[] contents)
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = path + ".tmp";
            using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(contents, 0, contents.Length);
                stream.Flush(true);
            }

            try
            {
                Replace(tempPath, path);
            }
            catch
            {
                if (File.Exists(tempPath))
                {
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch
                    {
                        // Preserve the original replace failure if cleanup also fails.
                    }
                }

                throw;
            }
        }

        public static void WriteAllText(string path, string contents)
        {
            WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes(contents));
        }

        private static void Replace(string tempPath, string path)
        {
            if (File.Exists(path))
            {
                File.Replace(tempPath, path, null, true);
                return;
            }

            File.Move(tempPath, path);
        }
    }
}
