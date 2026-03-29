// StubInstaller/ExitCodeClassifier.cs
// Maps installer exit codes to well-known outcomes.
// MSI reference: https://learn.microsoft.com/en-us/windows/win32/msi/error-codes
namespace StubInstaller.Core
{
    internal enum ExitCodeResult
    {
        Success,
        SuccessRebootRequired,
        SuccessRebootInitiated,
        AlreadyInstalled,  // exit 8: component already installed (VCRedist AIO)
        UserCancelled,
        AnotherInstallRunning,
        WrongArguments,    // exit 2: Inno/NSIS received wrong silent flag
        AccessDenied,      // exit 5: Win32 ERROR_ACCESS_DENIED
        Failure,
    }

    internal static class ExitCodeClassifier
    {
        internal static ExitCodeResult Classify(int code) => code switch
        {
            0 => ExitCodeResult.Success,
            3010 => ExitCodeResult.SuccessRebootRequired,
            1641 => ExitCodeResult.SuccessRebootInitiated,
            8 => ExitCodeResult.AlreadyInstalled,   // VCRedist AIO: all components already installed
            1602 => ExitCodeResult.UserCancelled,
            1618 => ExitCodeResult.AnotherInstallRunning,
            2 => ExitCodeResult.WrongArguments,     // Inno: setup cancelled (wrong silent flag)
            5 => ExitCodeResult.AccessDenied,       // Win32: ERROR_ACCESS_DENIED
            1603 => ExitCodeResult.Failure,            // MSI: fatal error (usually needs admin)
            _ => ExitCodeResult.Failure,
        };

        internal static bool IsSuccess(ExitCodeResult r) =>
            r is ExitCodeResult.Success
              or ExitCodeResult.SuccessRebootRequired
              or ExitCodeResult.SuccessRebootInitiated
              or ExitCodeResult.AlreadyInstalled;

        internal static string Describe(int code) => Classify(code) switch
        {
            ExitCodeResult.Success => $"Success ({code})",
            ExitCodeResult.SuccessRebootRequired => $"Success, reboot required ({code})",
            ExitCodeResult.SuccessRebootInitiated => $"Success, reboot initiated ({code})",
            ExitCodeResult.AlreadyInstalled => $"Already installed — skipped ({code})",
            ExitCodeResult.UserCancelled => $"Cancelled by user ({code})",
            ExitCodeResult.AnotherInstallRunning => $"Another install running ({code})",
            ExitCodeResult.WrongArguments => $"Wrong silent arguments — repackage with correct args ({code})",
            ExitCodeResult.AccessDenied => $"Access denied — may need admin rights or file is locked ({code})",
            _ => $"Failed ({code})",
        };
    }
}