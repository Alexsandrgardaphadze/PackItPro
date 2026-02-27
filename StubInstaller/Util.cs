// StubInstaller/Util.cs
// Small utilities that don't belong to any specific domain class.
namespace StubInstaller
{
    internal static class Util
    {
        private static readonly string[] SizeUnits = { "B", "KB", "MB", "GB", "TB" };

        internal static string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";
            double v = bytes;
            int order = 0;
            while (v >= 1024 && order < SizeUnits.Length - 1) { v /= 1024; order++; }
            return $"{v:0.##} {SizeUnits[order]}";
        }
    }
}