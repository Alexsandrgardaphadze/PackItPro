// StubInstaller/ExitCodeClassifier.cs
// Maps installer exit codes to well-known outcomes.
// MSI reference: https://learn.microsoft.com/en-us/windows/win32/msi/error-codes
namespace StubInstaller
{
    internal enum ExitCodeResult
    {
        Success,
        SuccessRebootRequired,
        SuccessRebootInitiated,
        UserCancelled,
        AnotherInstallRunning,
        Failure,
    }

    internal static class ExitCodeClassifier
    {
        internal static ExitCodeResult Classify(int code) => code switch
        {
            0 => ExitCodeResult.Success,
            3010 => ExitCodeResult.SuccessRebootRequired,
            1641 => ExitCodeResult.SuccessRebootInitiated,
            1602 => ExitCodeResult.UserCancelled,
            1618 => ExitCodeResult.AnotherInstallRunning,
            _ => ExitCodeResult.Failure,
        };

        internal static bool IsSuccess(ExitCodeResult r) =>
            r is ExitCodeResult.Success
              or ExitCodeResult.SuccessRebootRequired
              or ExitCodeResult.SuccessRebootInitiated;

        internal static string Describe(int code) => Classify(code) switch
        {
            ExitCodeResult.Success => $"Success ({code})",
            ExitCodeResult.SuccessRebootRequired => $"Success, reboot required ({code})",
            ExitCodeResult.SuccessRebootInitiated => $"Success, reboot initiated ({code})",
            ExitCodeResult.UserCancelled => $"Cancelled by user ({code})",
            ExitCodeResult.AnotherInstallRunning => $"Another install running, will retry ({code})",
            _ => $"Failed ({code})",
        };
    }
}