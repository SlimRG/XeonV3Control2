using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace XeonV3Control.App.Hardware;

[Flags]
internal enum ServiceControlManagerAccess : uint
{
    Connect = 0x0001,
    CreateService = 0x0002
}

[Flags]
internal enum ServiceAccess : uint
{
    QueryConfig = 0x0001,
    QueryStatus = 0x0004,
    Start = 0x0010,
    Stop = 0x0020,
    Delete = 0x00010000
}

internal enum WindowsServiceType : uint
{
    KernelDriver = 0x00000001
}

internal enum WindowsServiceStartType : uint
{
    Demand = 0x00000003
}

internal enum WindowsServiceErrorControl : uint
{
    Normal = 0x00000001
}

internal enum WindowsServiceControl : uint
{
    Stop = 0x00000001
}

internal enum WindowsServiceState : uint
{
    Stopped = 0x00000001,
    StartPending = 0x00000002,
    StopPending = 0x00000003,
    Running = 0x00000004
}

internal enum ServiceStatusInfoLevel : uint
{
    Process = 0
}

internal static class WindowsServiceError
{
    internal const int InsufficientBuffer = 122;
    internal const int AlreadyRunning = 1056;
    internal const int CannotAcceptControl = 1061;
    internal const int DoesNotExist = 1060;
    internal const int NotActive = 1062;
    internal const int MarkedForDelete = 1072;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WindowsServiceStatus
{
    internal uint ServiceType;
    internal WindowsServiceState CurrentState;
    internal uint ControlsAccepted;
    internal uint Win32ExitCode;
    internal uint ServiceSpecificExitCode;
    internal uint CheckPoint;
    internal uint WaitHint;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WindowsServiceStatusProcess
{
    internal uint ServiceType;
    internal WindowsServiceState CurrentState;
    internal uint ControlsAccepted;
    internal uint Win32ExitCode;
    internal uint ServiceSpecificExitCode;
    internal uint CheckPoint;
    internal uint WaitHint;
    internal uint ProcessId;
    internal uint ServiceFlags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WindowsQueryServiceConfig
{
    internal WindowsServiceType ServiceType;
    internal WindowsServiceStartType StartType;
    internal uint ErrorControl;
    internal nint BinaryPathName;
    internal nint LoadOrderGroup;
    internal uint TagId;
    internal nint Dependencies;
    internal nint ServiceStartName;
    internal nint DisplayName;
}

internal sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeServiceHandle() : base(ownsHandle: true)
        {
        }

    protected override bool ReleaseHandle() => WindowsServiceInterop.CloseServiceHandle(handle);
}

internal static class WindowsServiceInterop
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        ServiceControlManagerAccess desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle CreateService(
        SafeServiceHandle manager,
        string serviceName,
        string displayName,
        ServiceAccess desiredAccess,
        WindowsServiceType serviceType,
        WindowsServiceStartType startType,
        WindowsServiceErrorControl errorControl,
        string binaryPathName,
        string? loadOrderGroup,
        nint tagId,
        string? dependencies,
        string? serviceStartName,
        string? password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle OpenService(
        SafeServiceHandle manager,
        string serviceName,
        ServiceAccess desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartService(SafeServiceHandle service, uint argumentCount, nint arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ControlService(
        SafeServiceHandle service,
        WindowsServiceControl control,
        out WindowsServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteService(SafeServiceHandle service);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        ServiceStatusInfoLevel infoLevel,
        out WindowsServiceStatusProcess status,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceConfig(
        SafeServiceHandle service,
        nint config,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseServiceHandle(nint serviceHandle);
}
