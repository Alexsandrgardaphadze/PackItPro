// StubInstaller/AmsiScanner.cs - v1.0
// Raw P/Invoke AMSI integration — no external dependencies.
// AMSI (Antimalware Scan Interface) lets us ask whatever AV engine is installed
// on the machine (Defender, ESET, Kaspersky, BitDefender, etc.) to scan bytes
// before we execute them, without going to the internet.
//
// How it works:
//   1. AmsiInitialize()  — open a handle to the AMSI subsystem
//   2. AmsiOpenSession() — group related scans together (one session per installer)
//   3. AmsiScanBuffer()  — ask the AV engine to evaluate a byte array
//   4. AmsiCloseSession / AmsiUninitialize — always clean up
//
// Result codes:
//   AMSI_RESULT_CLEAN          (0)     — safe
//   AMSI_RESULT_NOT_DETECTED   (1)     — safe
//   AMSI_RESULT_BLOCKED_BY_ADMIN_START (16384) — blocked by policy
//   AMSI_RESULT_DETECTED       (32768) — detected as malware
//   Any value ≥ 32768 is considered malicious by AmsiResultIsMalware().
//
// Failure modes that are safe to ignore:
//   - amsi.dll not present (Windows 8.1 or earlier) → skip
//   - Access denied (process not elevated enough) → skip with warning
//   - AV engine not registered → skip with warning
//   All of the above are non-fatal: we log and continue installation.
//   Only a positive DETECTED result blocks installation.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace StubInstaller
{
    /// <summary>
    /// Result of an AMSI scan.
    /// </summary>
    internal sealed class AmsiScanResult
    {
        /// <summary>Whether the scan was actually executed (false = skipped/unavailable).</summary>
        public bool Executed { get; init; }

        /// <summary>Whether the AV engine flagged the content as malicious.</summary>
        public bool IsMalicious { get; init; }

        /// <summary>Human-readable outcome for the log.</summary>
        public string Message { get; init; } = string.Empty;

        /// <summary>Raw AMSI result code (0 if scan was skipped).</summary>
        public int RawResult { get; init; }

        internal static AmsiScanResult Skipped(string reason) => new()
        {
            Executed = false,
            IsMalicious = false,
            Message = $"AMSI skipped: {reason}",
        };

        internal static AmsiScanResult Clean(int rawResult) => new()
        {
            Executed = true,
            IsMalicious = false,
            RawResult = rawResult,
            Message = $"AMSI clean (result={rawResult})",
        };

        internal static AmsiScanResult Detected(int rawResult) => new()
        {
            Executed = true,
            IsMalicious = true,
            RawResult = rawResult,
            Message = $"⚠️ AMSI DETECTED MALWARE (result={rawResult})",
        };
    }

    /// <summary>
    /// Wraps the Windows AMSI API via P/Invoke.
    /// Thread-safe for concurrent scans — each scan creates its own session.
    /// Automatically skips on unsupported OS or unavailable AV engine.
    /// </summary>
    internal static class AmsiScanner
    {
        // ── P/Invoke declarations ─────────────────────────────────────────────

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int AmsiScanBuffer(
            IntPtr amsiContext,
            byte[] buffer,
            uint length,
            string contentName,
            IntPtr session,
            out int result);

        // AMSI_RESULT_DETECTED = 32768. Anything ≥ this is malicious.
        private const int AMSI_RESULT_DETECTED = 32768;

        // Chunk size for scanning large files in pieces.
        // 8 MB balances memory use against scan latency.
        private const int ScanChunkSize = 8 * 1024 * 1024;

        // amsi.dll availability — checked once, cached.
        // null = not yet checked, true/false = result.
        private static bool? _amsiAvailable;
        private static readonly object _availLock = new();

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Scans a byte array (an extracted installer) using the local AV engine via AMSI.
        /// Safe to call on any Windows version — returns Skipped on unsupported platforms.
        /// </summary>
        /// <param name="content">Raw bytes to scan (the installer file contents).</param>
        /// <param name="contentName">Display name used in AV engine logs (e.g. "setup.exe").</param>
        internal static AmsiScanResult ScanBuffer(byte[] content, string contentName)
        {
            if (!IsAmsiAvailable())
                return AmsiScanResult.Skipped("amsi.dll not available on this OS");

            if (content == null || content.Length == 0)
                return AmsiScanResult.Skipped("empty buffer");

            IntPtr amsiContext = IntPtr.Zero;
            IntPtr session = IntPtr.Zero;

            try
            {
                int hr = AmsiInitialize("PackItPro", out amsiContext);
                if (hr != 0)
                    return AmsiScanResult.Skipped($"AmsiInitialize failed (HRESULT=0x{hr:X8})");

                hr = AmsiOpenSession(amsiContext, out session);
                if (hr != 0)
                    return AmsiScanResult.Skipped($"AmsiOpenSession failed (HRESULT=0x{hr:X8})");

                // Scan in chunks so we don't hit AMSI's internal buffer limits
                // on very large installers, and so the AV engine sees all bytes.
                int highestResult = 0;
                int offset = 0;

                while (offset < content.Length)
                {
                    int chunkLen = Math.Min(ScanChunkSize, content.Length - offset);
                    byte[] chunk = new byte[chunkLen];
                    Buffer.BlockCopy(content, offset, chunk, 0, chunkLen);

                    string chunkName = content.Length > ScanChunkSize
                        ? $"{contentName}[{offset}..{offset + chunkLen - 1}]"
                        : contentName;

                    hr = AmsiScanBuffer(amsiContext, chunk, (uint)chunkLen,
                        chunkName, session, out int chunkResult);

                    if (hr != 0)
                        return AmsiScanResult.Skipped($"AmsiScanBuffer failed (HRESULT=0x{hr:X8})");

                    if (chunkResult > highestResult)
                        highestResult = chunkResult;

                    // Short-circuit: no need to scan more once malware is detected
                    if (highestResult >= AMSI_RESULT_DETECTED)
                        return AmsiScanResult.Detected(highestResult);

                    offset += chunkLen;
                }

                return AmsiScanResult.Clean(highestResult);
            }
            catch (DllNotFoundException)
            {
                // Can happen if amsi.dll is present but fails to load properly
                lock (_availLock) { _amsiAvailable = false; }
                return AmsiScanResult.Skipped("amsi.dll failed to load");
            }
            catch (Exception ex)
            {
                return AmsiScanResult.Skipped($"unexpected exception: {ex.Message}");
            }
            finally
            {
                // Always close session and context — AMSI leaks handles otherwise
                if (session != IntPtr.Zero && amsiContext != IntPtr.Zero)
                    AmsiCloseSession(amsiContext, session);
                if (amsiContext != IntPtr.Zero)
                    AmsiUninitialize(amsiContext);
            }
        }

        /// <summary>
        /// Convenience overload: reads file bytes and scans them.
        /// Useful for scanning before execution when you have a path, not bytes.
        /// Returns Skipped if the file cannot be read.
        /// </summary>
        internal static AmsiScanResult ScanFile(string filePath)
        {
            try
            {
                byte[] bytes = System.IO.File.ReadAllBytes(filePath);
                string name = System.IO.Path.GetFileName(filePath);
                return ScanBuffer(bytes, name);
            }
            catch (Exception ex)
            {
                return AmsiScanResult.Skipped($"could not read file for scan: {ex.Message}");
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /// <summary>
        /// Checks once whether amsi.dll is loadable on this machine.
        /// Windows 10+ always has it; Windows 8.1 and earlier do not.
        /// Result is cached after the first check.
        /// </summary>
        private static bool IsAmsiAvailable()
        {
            lock (_availLock)
            {
                if (_amsiAvailable.HasValue)
                    return _amsiAvailable.Value;

                try
                {
                    // Probe by trying to load the DLL
                    IntPtr handle = NativeLoadLibrary("amsi.dll");
                    if (handle == IntPtr.Zero)
                    {
                        _amsiAvailable = false;
                        return false;
                    }
                    NativeFreeLibrary(handle);
                    _amsiAvailable = true;
                    return true;
                }
                catch
                {
                    _amsiAvailable = false;
                    return false;
                }
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        private static IntPtr NativeLoadLibrary(string name) => LoadLibrary(name);
        private static void NativeFreeLibrary(IntPtr h) => FreeLibrary(h);
    }
}