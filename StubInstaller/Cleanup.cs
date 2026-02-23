// StubInstaller.Cleanup.cs
using System; // For Action<T> delegate
using System.IO; // For Directory, Path, IOException
using System.Security.Principal; // For WindowsPrincipal (though not used directly here)

namespace StubInstaller
{
    public static class Cleanup
    {
        // NEW: Method to clean up the temporary extraction directory
        // NEW: Accepts logging delegates for flexibility
        public static void CleanupTempDirectory(string tempDirectoryPath, bool shouldCleanup, Action<string> logInfo, Action<string> logError)
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

            // NEW: Exponential backoff for cleanup retries
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
                    System.Threading.Thread.Sleep(delays[i]); // Wait with increasing delay
                }
            }

            if (!success)
            {
                // NEW: If retries fail, log the error and optionally schedule for reboot deletion
                logError($"[CLEANUP] Failed to delete temporary directory after {delays.Length} attempts: {tempDirectoryPath}");
                logInfo("[CLEANUP] Consider deleting manually or scheduling for next reboot.");
                // Scheduling for reboot deletion is possible but requires registry manipulation (e.g., MoveFileEx via P/Invoke)
                // This is more complex and might not be necessary for all cases initially.
            }
        }

        // NEW: Helper methods for logging (can be shared)
        // REMOVED: LogInfo and LogError methods as they are now passed as delegates
    }
}