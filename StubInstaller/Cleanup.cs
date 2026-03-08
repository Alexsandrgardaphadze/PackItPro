using System;
using System.IO;
using System.Threading.Tasks;

namespace StubInstaller
{
    public static class Cleanup
    {
        public static async Task CleanupTempDirectoryAsync(
            string tempDirectoryPath,
            bool shouldCleanup,
            Action<string> logInfo,
            Action<string> logError)
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

            // Exponential backoff: 1s, 2s, 4s, 8s
            int[] delays = { 1000, 2000, 4000, 8000 };
            bool success = false;

            for (int i = 0; i < delays.Length; i++)
            {
                try
                {
                    Directory.Delete(tempDirectoryPath, true);
                    logInfo("[CLEANUP] Temporary directory deleted successfully.");
                    success = true;
                    break;
                }
                catch (UnauthorizedAccessException)
                {
                    logError($"[CLEANUP] Access denied. Attempt {i + 1}/{delays.Length}. Retrying...");
                }
                catch (IOException ex) when (ex.Message.Contains("being used by another process"))
                {
                    logError($"[CLEANUP] Directory locked. Attempt {i + 1}/{delays.Length}. Retrying... {ex.Message}");
                }
                catch (Exception ex)
                {
                    logError($"[CLEANUP] Unexpected error: {ex.Message}. Attempt {i + 1}/{delays.Length}.");
                }

                if (!success && i < delays.Length - 1)
                    await Task.Delay(delays[i]);
            }

            if (!success)
            {
                logError($"[CLEANUP] Failed to delete after {delays.Length} attempts: {tempDirectoryPath}");
                logInfo("[CLEANUP] Consider deleting manually or scheduling for next reboot.");
            }
        }
    }
}
