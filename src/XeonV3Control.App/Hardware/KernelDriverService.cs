using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using XeonV3Control.Core;

namespace XeonV3Control.App.Hardware;

/// <summary>Owns one demand-start kernel-driver service through the Windows Service Control Manager.</summary>
internal sealed class KernelDriverService : IDisposable
{
    private const int ServiceOperationTimeoutMilliseconds = 15_000;
    private const int MinimumStatusPollMilliseconds = 50;
    private const int MaximumStatusPollMilliseconds = 500;
    private const uint WaitHintDivisor = 10;

    private const ServiceAccess LifecycleAccess = ServiceAccess.Start | ServiceAccess.Stop |
        ServiceAccess.QueryStatus | ServiceAccess.QueryConfig | ServiceAccess.Delete;
    private const ServiceAccess CleanupAccess = ServiceAccess.Stop | ServiceAccess.QueryStatus |
        ServiceAccess.QueryConfig | ServiceAccess.Delete;

    private readonly string serviceName;
    private SafeServiceHandle? manager;
    private SafeServiceHandle? service;
    private int disposed;

    private KernelDriverService(string serviceName, SafeServiceHandle manager, SafeServiceHandle service)
    {
        this.serviceName = serviceName;
        this.manager = manager;
        this.service = service;
    }

    internal static KernelDriverService Create(string serviceName, string binaryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(binaryPath);

        SafeServiceHandle manager = OpenManager(ServiceControlManagerAccess.Connect | ServiceControlManagerAccess.CreateService);
        SafeServiceHandle service = WindowsServiceInterop.CreateService(
            manager,
            serviceName,
            serviceName,
            LifecycleAccess,
            WindowsServiceType.KernelDriver,
            WindowsServiceStartType.Demand,
            WindowsServiceErrorControl.Normal,
            binaryPath,
            null,
            0,
            null,
            null,
            null);
        if (!service.IsInvalid)
        {
            return new KernelDriverService(serviceName, manager, service);
        }

        int error = Marshal.GetLastWin32Error();
        service.Dispose();
        manager.Dispose();
        throw new Win32Exception(error, OperationError.DriverService);
    }

    internal void Start(Action<string>? trace = null, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        SafeServiceHandle currentService = service ?? throw new ObjectDisposedException(nameof(KernelDriverService));
        if (!WindowsServiceInterop.StartService(currentService, 0, 0))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != WindowsServiceError.AlreadyRunning)
            {
                throw new Win32Exception(error, OperationError.DriverService);
            }
        }

        WaitForState(currentService, WindowsServiceState.Running, cancellationToken);
        trace?.Invoke("DRIVER_SERVICE_RUNNING name=" + serviceName);
    }

    internal static StaleDriverServiceCleanupResult CleanupStale(
        string serviceName,
        string expectedBinaryPath,
        Action<string>? trace = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedBinaryPath);
        cancellationToken.ThrowIfCancellationRequested();

        using SafeServiceHandle manager = OpenManager(ServiceControlManagerAccess.Connect);
        SafeServiceHandle service = WindowsServiceInterop.OpenService(manager, serviceName, CleanupAccess);
        if (service.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            service.Dispose();
            if (error == WindowsServiceError.DoesNotExist)
            {
                return StaleDriverServiceCleanupResult.NotFound;
            }
            if (error == WindowsServiceError.MarkedForDelete)
            {
                WaitUntilServiceRemoved(manager, serviceName, cancellationToken);
                return StaleDriverServiceCleanupResult.Removed;
            }

            throw new Win32Exception(error, OperationError.DriverService);
        }

        using (service)
        {
            ServiceConfiguration configuration = QueryConfiguration(service);
            if (configuration.ServiceType != WindowsServiceType.KernelDriver ||
                configuration.StartType != WindowsServiceStartType.Demand ||
                !ServiceBinaryPathsEqual(configuration.BinaryPath, expectedBinaryPath))
            {
                trace?.Invoke("STALE_DRIVER_SERVICE_SKIPPED name=" + serviceName + " reason=ownership-mismatch");
                return StaleDriverServiceCleanupResult.OwnershipMismatch;
            }

            StopService(service, cancellationToken);
            if (!WindowsServiceInterop.DeleteService(service))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != WindowsServiceError.MarkedForDelete)
                {
                    throw new Win32Exception(error, OperationError.DriverService);
                }
            }
        }

        WaitUntilServiceRemoved(manager, serviceName, cancellationToken);
        trace?.Invoke("STALE_DRIVER_SERVICE_REMOVED name=" + serviceName);
        return StaleDriverServiceCleanupResult.Removed;
    }

    internal void StopAndDelete(Action<string>? trace = null)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        SafeServiceHandle currentService = service ?? throw new ObjectDisposedException(nameof(KernelDriverService));
        SafeServiceHandle currentManager = manager ?? throw new ObjectDisposedException(nameof(KernelDriverService));

        StopService(currentService, CancellationToken.None);
        if (!WindowsServiceInterop.DeleteService(currentService))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != WindowsServiceError.MarkedForDelete)
            {
                throw new Win32Exception(error, OperationError.DriverService);
            }
        }

        currentService.Dispose();
        service = null;
        WaitUntilServiceRemoved(currentManager, serviceName, CancellationToken.None);
        trace?.Invoke("DRIVER_SERVICE_REMOVED name=" + serviceName);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        service?.Dispose();
        service = null;
        manager?.Dispose();
        manager = null;
    }

    private static void StopService(SafeServiceHandle service, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        WindowsServiceStatusProcess status = QueryStatus(service);
        if (status.CurrentState == WindowsServiceState.Stopped)
        {
            return;
        }

        if (status.CurrentState == WindowsServiceState.StartPending)
        {
            WaitForStableState(service, cancellationToken);
            status = QueryStatus(service);
            if (status.CurrentState == WindowsServiceState.Stopped)
            {
                return;
            }
        }

        if (status.CurrentState != WindowsServiceState.StopPending &&
            !WindowsServiceInterop.ControlService(service, WindowsServiceControl.Stop, out _))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == WindowsServiceError.NotActive)
            {
                return;
            }
            if (error != WindowsServiceError.CannotAcceptControl)
            {
                throw new Win32Exception(error, OperationError.DriverService);
            }
        }

        WaitForState(service, WindowsServiceState.Stopped, cancellationToken);
    }

    private static void WaitForStableState(SafeServiceHandle service, CancellationToken cancellationToken)
    {
        Stopwatch timer = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WindowsServiceStatusProcess status = QueryStatus(service);
            if (status.CurrentState is not (WindowsServiceState.StartPending or WindowsServiceState.StopPending))
            {
                return;
            }
            ThrowIfTimedOut(timer);
            WaitForNextPoll(StatusPollDelay(status.WaitHint), cancellationToken);
        }
    }

    private static void WaitForState(
        SafeServiceHandle service,
        WindowsServiceState desiredState,
        CancellationToken cancellationToken = default)
    {
        Stopwatch timer = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WindowsServiceStatusProcess status = QueryStatus(service);
            if (status.CurrentState == desiredState)
            {
                return;
            }
            if (desiredState == WindowsServiceState.Running && status.CurrentState == WindowsServiceState.Stopped)
            {
                throw new IOException(OperationError.DriverService);
            }
            ThrowIfTimedOut(timer);
            WaitForNextPoll(StatusPollDelay(status.WaitHint), cancellationToken);
        }
    }

    private static void WaitForNextPoll(int milliseconds, CancellationToken cancellationToken)
    {
        if (!cancellationToken.CanBeCanceled)
        {
            Thread.Sleep(milliseconds);
            return;
        }

        if (cancellationToken.WaitHandle.WaitOne(milliseconds))
        {
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private static void ThrowIfTimedOut(Stopwatch timer)
    {
        if (timer.ElapsedMilliseconds >= ServiceOperationTimeoutMilliseconds)
        {
            throw new TimeoutException(OperationError.DriverService);
        }
    }

    private static int StatusPollDelay(uint waitHint)
    {
        uint candidate = waitHint / WaitHintDivisor;
        int bounded = candidate > int.MaxValue ? int.MaxValue : (int)candidate;
        return Math.Clamp(bounded, MinimumStatusPollMilliseconds, MaximumStatusPollMilliseconds);
    }

    private static WindowsServiceStatusProcess QueryStatus(SafeServiceHandle service)
    {
        if (!WindowsServiceInterop.QueryServiceStatusEx(
                service,
                ServiceStatusInfoLevel.Process,
                out WindowsServiceStatusProcess status,
                (uint)Marshal.SizeOf<WindowsServiceStatusProcess>(),
                out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), OperationError.DriverService);
        }

        return status;
    }

    private static ServiceConfiguration QueryConfiguration(SafeServiceHandle service)
    {
        _ = WindowsServiceInterop.QueryServiceConfig(service, 0, 0, out uint required);
        int error = Marshal.GetLastWin32Error();
        if (required == 0 || error != WindowsServiceError.InsufficientBuffer)
        {
            throw new Win32Exception(error, OperationError.DriverService);
        }

        nint buffer = Marshal.AllocHGlobal(checked((int)required));
        try
        {
            if (!WindowsServiceInterop.QueryServiceConfig(service, buffer, required, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), OperationError.DriverService);
            }

            WindowsQueryServiceConfig config = Marshal.PtrToStructure<WindowsQueryServiceConfig>(buffer);
            string binaryPath = Marshal.PtrToStringUni(config.BinaryPathName)
                ?? throw new IOException(OperationError.DriverService);
            return new ServiceConfiguration(config.ServiceType, config.StartType, binaryPath);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ServiceBinaryPathsEqual(string actual, string expected)
    {
        static string Normalize(string value)
        {
            string result = value.Trim();
            if (result.Length >= 2 && result[0] == '"' && result[^1] == '"')
            {
                result = result[1..^1];
            }
            return result;
        }

        return string.Equals(Normalize(actual), Normalize(expected), StringComparison.OrdinalIgnoreCase);
    }

    private static SafeServiceHandle OpenManager(ServiceControlManagerAccess access)
    {
        SafeServiceHandle manager = WindowsServiceInterop.OpenSCManager(null, null, access);
        if (!manager.IsInvalid)
        {
            return manager;
        }

        int error = Marshal.GetLastWin32Error();
        manager.Dispose();
        throw new Win32Exception(error, OperationError.DriverService);
    }

    private static void WaitUntilServiceRemoved(
        SafeServiceHandle manager,
        string serviceName,
        CancellationToken cancellationToken)
    {
        Stopwatch timer = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using SafeServiceHandle probe = WindowsServiceInterop.OpenService(
                manager,
                serviceName,
                ServiceAccess.QueryStatus);
            if (probe.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == WindowsServiceError.DoesNotExist)
                {
                    return;
                }
                if (error != WindowsServiceError.MarkedForDelete)
                {
                    throw new Win32Exception(error, OperationError.DriverService);
                }
            }

            ThrowIfTimedOut(timer);
            WaitForNextPoll(MinimumStatusPollMilliseconds, cancellationToken);
        }
    }

    private readonly record struct ServiceConfiguration(
        WindowsServiceType ServiceType,
        WindowsServiceStartType StartType,
        string BinaryPath);
}

internal enum StaleDriverServiceCleanupResult
{
    NotFound,
    Removed,
    OwnershipMismatch
}
