// StubInstaller/PathHelper.cs - v1.0
// Single canonical implementation of the path traversal guard.
// Previously duplicated in both Program.cs (TryResolveSafePath) and
// InstallerRunner.cs (TryResolveSafePath) — now both reference this one.
//
// SECURITY: prevents CWE-22 (Path Traversal) attacks where a crafted
// manifest could specify "../../../Windows/System32/cmd.exe" as a file name.
using System;
using System.IO;

namespace StubInstaller
{
    internal static class PathHelper
    {
        /// <summary>
        /// Resolves <paramref name="fileName"/> relative to <paramref name="baseDir"/>
        /// and verifies the result is strictly inside <paramref name="baseDir"/>.
        ///
        /// Returns true and sets <paramref name="fullPath"/> on success.
        /// Returns false and sets <paramref name="error"/> on path traversal or invalid input.
        /// </summary>
        internal static bool TryResolveSafe(
            string baseDir,
            string fileName,
            out string fullPath,
            out string? error)
        {
            try
            {
                // Normalise: ensure the base dir always ends with a separator
                // so "StartsWith" can't be fooled by prefix matches like
                //   base = C:\Temp\PackItPro_abc
                //   full = C:\Temp\PackItPro_abcevil\payload.exe  ← would pass without separator
                string safeBase = Path.GetFullPath(baseDir).TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;

                fullPath = Path.GetFullPath(Path.Combine(baseDir, fileName));

                if (!fullPath.StartsWith(safeBase, StringComparison.OrdinalIgnoreCase))
                {
                    error = $"'{fileName}' resolves outside base directory (possible path traversal). " +
                            $"Resolved: '{fullPath}', Base: '{safeBase}'";
                    return false;
                }

                error = null;
                return true;
            }
            catch (Exception ex)
            {
                fullPath = string.Empty;
                error = $"invalid path '{fileName}': {ex.Message}";
                return false;
            }
        }
    }
}