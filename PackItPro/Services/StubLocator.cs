using System;
using System.IO;
using System.Linq;

namespace PackItPro.Services
{
    /// <summary>
    /// Locates and validates the self-contained StubInstaller.exe.
    /// Raises clear, actionable exceptions when the stub is missing or wrong build type.
    /// </summary>
    public static class StubLocator
    {
        // A framework-dependent stub is ~100–200 KB.
        // A self-contained single-file stub is typically 60–150 MB.
        // 10 MB threshold is well above framework-dependent and well below self-contained.
        private const long MIN_SELF_CONTAINED_BYTES = 10L * 1024 * 1024;
        private const long WARN_SIZE_MIN_BYTES = 50L * 1024 * 1024;
        private const long WARN_SIZE_MAX_BYTES = 200L * 1024 * 1024;

        /// <summary>
        /// Finds the StubInstaller.exe, validates it is self-contained, returns its full path.
        /// </summary>
        public static string FindStubInstaller(ILogService? log = null)
        {
            log ??= NullLogService.Instance;

            var baseDir = AppContext.BaseDirectory;
            log.Debug($"[StubLocator] BaseDirectory: {baseDir}");

            var searchPaths = new[]
            {
                // Installed / published app
                Path.Combine(baseDir, "Resources", "StubInstaller.exe"),
                Path.Combine(baseDir, "StubInstaller.exe"),

                // Development: running from bin\Debug or bin\Release
                Path.Combine(baseDir, "..", "..", "..", "Resources", "StubInstaller.exe"),

                // Solution root layout: PackItPro\bin\..\ → solution root → Resources
                Path.Combine(baseDir, "..", "..", "..", "..", "PackItPro", "Resources", "StubInstaller.exe"),

                // Dev convenience: StubInstaller publish output sitting next to solution
                Path.Combine(baseDir, "..", "..", "..", "..", "StubInstaller", "publish", "StubInstaller.exe"),
                Path.Combine(baseDir, "..", "StubInstaller", "publish", "StubInstaller.exe"),
            };

            foreach (var rawPath in searchPaths)
            {
                string fullPath;
                try { fullPath = Path.GetFullPath(rawPath); }
                catch { continue; }

                log.Debug($"[StubLocator] Checking: {fullPath}");

                if (!File.Exists(fullPath))
                {
                    log.Debug("[StubLocator]   Not found.");
                    continue;
                }

                var info = new FileInfo(fullPath);
                double mb = info.Length / (1024.0 * 1024.0);

                log.Info($"[StubLocator] Found stub: {fullPath} ({mb:F2} MB)");

                if (info.Length < MIN_SELF_CONTAINED_BYTES)
                {
                    throw new InvalidOperationException(
                        $"StubInstaller.exe at '{fullPath}' is only {mb:F2} MB — this is a framework-dependent build.\n\n" +
                        "Fix:\n" +
                        "  cd StubInstaller\n" +
                        "  dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true\n" +
                        "  copy publish\\StubInstaller.exe ..\\PackItPro\\Resources\\StubInstaller.exe\n" +
                        "  (then rebuild PackItPro)");
                }

                if (info.Length < WARN_SIZE_MIN_BYTES)
                    log.Warning($"[StubLocator] Stub is smaller than expected ({mb:F2} MB < 50 MB). Verify --self-contained publish.");

                if (info.Length > WARN_SIZE_MAX_BYTES)
                    log.Warning($"[StubLocator] Stub is unusually large ({mb:F2} MB > 200 MB). Consider trimming the publish.");

                log.Info("[StubLocator] Stub validated ✓");
                return fullPath;
            }

            var searched = string.Join("\n  ", searchPaths.Select(p =>
            {
                try { return Path.GetFullPath(p); } catch { return p; }
            }));

            throw new FileNotFoundException(
                $"StubInstaller.exe not found in any of:\n  {searched}\n\n" +
                "Publish it first:\n" +
                "  cd StubInstaller\n" +
                "  dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true\n" +
                "  copy publish\\StubInstaller.exe PackItPro\\Resources\\StubInstaller.exe");
        }

        public static bool IsStubSelfContained(string stubPath) =>
            File.Exists(stubPath) && new FileInfo(stubPath).Length >= MIN_SELF_CONTAINED_BYTES;

        public static string GetStubDescription(string stubPath)
        {
            if (!File.Exists(stubPath)) return "Not found";
            double mb = new FileInfo(stubPath).Length / (1024.0 * 1024.0);
            return $"{mb:F2} MB — {(IsStubSelfContained(stubPath) ? "Self-contained ✓" : "Framework-dependent ✗")}";
        }
    }
}