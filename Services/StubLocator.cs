// PackItPro/Services/StubLocator.cs
using System;
using System.IO;
using System.Linq;

namespace PackItPro.Services
{
    /// <summary>
    /// Locates and validates the StubInstaller.exe
    /// </summary>
    public static class StubLocator
    {
        private const long MIN_SELF_CONTAINED_SIZE = 10 * 1024 * 1024; // 10 MB minimum
        private const long EXPECTED_SIZE_MIN = 25 * 1024 * 1024; // 25 MB
        private const long EXPECTED_SIZE_MAX = 100 * 1024 * 1024; // 100 MB

        /// <summary>
        /// Finds and validates the StubInstaller.exe
        /// </summary>
        /// <returns>Full path to validated stub</returns>
        /// <exception cref="FileNotFoundException">If stub not found</exception>
        /// <exception cref="InvalidOperationException">If stub is framework-dependent</exception>
        public static string FindStubInstaller()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("SEARCHING FOR STUB INSTALLER");
            Console.WriteLine("========================================");

            // Define search paths (in priority order)
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;

            string[] searchPaths = new[]
            {
                // Priority 1: Resources subfolder (recommended location)
                Path.Combine(baseDir, "Resources", "StubInstaller.exe"),
                
                // Priority 2: Same directory as PackItPro.exe
                Path.Combine(baseDir, "StubInstaller.exe"),
                
                // Priority 3: One level up (for development)
                Path.Combine(baseDir, "..", "StubInstaller.exe"),
                
                // Priority 4: Project Resources folder (design-time)
                Path.Combine(baseDir, "..", "..", "..", "Resources", "StubInstaller.exe")
            };

            Console.WriteLine($"Base directory: {baseDir}");
            Console.WriteLine($"Searching {searchPaths.Length} locations...");
            Console.WriteLine();

            // Search for stub
            foreach (var searchPath in searchPaths)
            {
                var fullPath = Path.GetFullPath(searchPath);
                Console.WriteLine($"Checking: {fullPath}");

                if (File.Exists(fullPath))
                {
                    var fileInfo = new FileInfo(fullPath);
                    var sizeMB = fileInfo.Length / (1024.0 * 1024.0);

                    Console.WriteLine($"  ✓ Found! Size: {sizeMB:F2} MB");

                    // CRITICAL: Validate it's self-contained
                    if (fileInfo.Length < MIN_SELF_CONTAINED_SIZE)
                    {
                        var error = $"StubInstaller.exe is TOO SMALL ({sizeMB:F2} MB).\n\n" +
                                   $"This is a FRAMEWORK-DEPENDENT build and WILL NOT WORK!\n\n" +
                                   $"Expected: {EXPECTED_SIZE_MIN / (1024.0 * 1024.0):F0}-{EXPECTED_SIZE_MAX / (1024.0 * 1024.0):F0} MB (self-contained)\n" +
                                   $"Found: {sizeMB:F2} MB\n\n" +
                                   $"Location: {fullPath}\n\n" +
                                   $"To fix this:\n" +
                                   $"1. Open PowerShell in StubInstaller directory\n" +
                                   $"2. Run: dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true\n" +
                                   $"3. Copy: StubInstaller\\publish\\StubInstaller.exe\n" +
                                   $"4. To: PackItPro\\Resources\\StubInstaller.exe\n" +
                                   $"5. Rebuild PackItPro";

                        Console.WriteLine($"  ❌ VALIDATION FAILED!");
                        Console.WriteLine(error);

                        throw new InvalidOperationException(error);
                    }

                    // Warn if size seems unusual
                    if (fileInfo.Length < EXPECTED_SIZE_MIN || fileInfo.Length > EXPECTED_SIZE_MAX)
                    {
                        Console.WriteLine($"  ⚠️  WARNING: Unusual size ({sizeMB:F2} MB)");
                        Console.WriteLine($"      Expected: {EXPECTED_SIZE_MIN / (1024.0 * 1024.0):F0}-{EXPECTED_SIZE_MAX / (1024.0 * 1024.0):F0} MB");
                    }

                    Console.WriteLine($"  ✅ Validation passed - Self-contained stub");
                    Console.WriteLine("========================================");
                    Console.WriteLine();

                    return fullPath;
                }
                else
                {
                    Console.WriteLine($"  ✗ Not found");
                }
            }

            // Not found in any location
            var notFoundError = "StubInstaller.exe NOT FOUND in any search location!\n\n" +
                               "Searched locations:\n" +
                               string.Join("\n", searchPaths.Select((p, i) => $"  {i + 1}. {Path.GetFullPath(p)}")) + "\n\n" +
                               "To fix this:\n" +
                               "1. Publish StubInstaller as self-contained:\n" +
                               "   cd StubInstaller\n" +
                               "   dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true\n\n" +
                               "2. Copy the published stub:\n" +
                               "   copy StubInstaller\\publish\\StubInstaller.exe PackItPro\\Resources\\StubInstaller.exe\n\n" +
                               "3. Rebuild PackItPro";

            Console.WriteLine("❌ STUB NOT FOUND!");
            Console.WriteLine(notFoundError);
            Console.WriteLine("========================================");

            throw new FileNotFoundException(notFoundError);
        }

        /// <summary>
        /// Validates that a stub file is self-contained
        /// </summary>
        public static bool IsStubSelfContained(string stubPath)
        {
            if (!File.Exists(stubPath))
                return false;

            var fileInfo = new FileInfo(stubPath);
            return fileInfo.Length >= MIN_SELF_CONTAINED_SIZE;
        }

        /// <summary>
        /// Gets a human-readable description of the stub
        /// </summary>
        public static string GetStubInfo(string stubPath)
        {
            if (!File.Exists(stubPath))
                return "Not found";

            var fileInfo = new FileInfo(stubPath);
            var sizeMB = fileInfo.Length / (1024.0 * 1024.0);
            var isSelfContained = fileInfo.Length >= MIN_SELF_CONTAINED_SIZE;

            return $"{sizeMB:F2} MB - {(isSelfContained ? "Self-contained ✓" : "Framework-dependent ✗")}";
        }
    }
}