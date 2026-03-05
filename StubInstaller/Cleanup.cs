// StubInstaller.Cleanup.cs
using System; // For Action<T> delegate
using System.IO; // For Directory, Path, IOException
using System.Threading.Tasks; // For async/await

namespace StubInstaller
{
    public static class Cleanup
    {
        // ✅ FIX: Made async to avoid blocking thread pool during retries
        // Changed from: public static void CleanupTempDirectory(...)
        public static async Task CleanupTempDirectoryAsync(string tempDirectoryPath, bool shouldCleanup, Action<string> logInfo, Action<string> logError)
        {
            if (!shouldCleanup)
            {
                logInfo($"[CLEANUP] Cleanup disabled by manifest. Temporary directory left at: {tempDirectoryPath}");
                return;
            }

            if (string.IsNullOrEmpty(tempDirectoryPath) || !Directory.Exists(tempDirectoryPath))
            {
                logInfo("[CLEANUP] Temporary directory path is null or does not exist. Nothing to clean up.");
                return;
            }

            logInfo($"[CLEANUP] Attempting to delete temporary directory: {tempDirectoryPath}");

            // Exponential backoff for cleanup retries
            int[] delays = { 1000, 2000, 4000, 8000 }; // 1s, 2s, 4s, 8s
            bool success = false;

            for (int i = 0; i < delays.Length; i++)
            {
                try
                {
                    Directory.Delete(tempDirectoryPath, true); // true = recursive delete
                    logInfo("[CLEANUP] Temporary directory deleted successfully.");
                    success = true;
                    break; // Exit loop on success
                }
                catch (UnauthorizedAccessException)
                {
                    logError($"[CLEANUP] Access denied deleting temp directory. Attempt {i + 1}/{delays.Length}. Retrying...");
                }
                catch (IOException ex) when (ex.Message.Contains("being used by another process"))
                {
                    logError($"[CLEANUP] Temp directory is locked. Attempt {i + 1}/{delays.Length}. Retrying... Details: {ex.Message}");
                }
                catch (Exception ex)
                {
                    logError($"[CLEANUP] Unexpected error deleting temp directory: {ex.Message}. Attempt {i + 1}/{delays.Length}.");
                }

                if (!success && i < delays.Length - 1) // Don't sleep after the last attempt
                {
                    // ✅ FIX: Use async Task.Delay instead of blocking Thread.Sleep
                    await Task.Delay(delays[i]);
                }
            }

            if (!success)
            {
                // If retries fail, log the error and optionally schedule for reboot deletion
                logError($"[CLEANUP] Failed to delete temporary directory after {delays.Length} attempts: {tempDirectoryPath}");
                logInfo("[CLEANUP] Consider deleting manually or scheduling for next reboot.");
            }
        }
    }
}