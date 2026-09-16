namespace XeonV3Control.App;

internal static class WindowsErrorCodes
{
    internal const int InvalidImageHash = 577;
    internal const int DriverBlocked = 1275;
    internal const int SystemIntegrityPolicyViolation = 4551;

    internal static bool IsDriverLoadBlocked(int errorCode) => errorCode is
        InvalidImageHash or DriverBlocked or SystemIntegrityPolicyViolation;
}
