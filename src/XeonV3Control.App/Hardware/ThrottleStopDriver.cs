using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using XeonV3Control.Core;

namespace XeonV3Control.App.Hardware;

/// <summary>Owns a unique service; never attaches to or reconfigures ThrottleStop's service.</summary>
internal sealed class ThrottleStopDriver : IX99SpiFlashAccess, IDisposable
{
    private const uint ReadPhysicalMemoryIoctl = 0x80006498;
    private const uint WritePhysicalMemoryIoctl = 0x8000649C;
    private const uint ReadPciConfigIoctl = 0x800064A0;
    private const uint WritePciConfigIoctl = 0x800064A4;
    private const int DriverProtocolAddressBytes = sizeof(ulong);
    private const uint GenericReadAccess = 0x80000000;
    private const uint OpenExisting = 3;
    private const int PciBusShift = 0;
    private const int PciDeviceShift = 8;
    private const int PciFunctionShift = 16;
    private const int PciRegisterOffsetShift = 32;
    private const int BitsPerByte = 8;
    private const string SystemDriversDirectoryName = "drivers";
    private const string NativeDosDevicePathPrefix = @"\??\";

    private readonly string service = ApplicationIdentity.DriverServicePrefix + Guid.NewGuid().ToString("N");
    private readonly string directory;
    private Action<string>? trace;
    private SafeFileHandle? device;
    private FileStream? lockedDriver;
    private KernelDriverService? driverService;
    private int disposed;
    private ulong spiBar;
    private uint biosRegionStart;
    private uint biosRegionEndExclusive;
    private uint pendingFlashAddress;
    private bool pendingFlashAddressValid;

    private ThrottleStopDriver()
    {
        directory = Path.Combine(Environment.SystemDirectory, SystemDriversDirectoryName, service);
    }

    internal static ThrottleStopDriver Open(Action<string>? diagnostic = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException(OperationError.AdministratorRequired);
        }
        if (!X86Base.IsSupported)
        {
            throw new NotSupportedException(OperationError.PlatformUnsupported);
        }

        var vendor = X86Base.CpuId(X99Platform.CpuIdVendorLeaf, 0);
        var cpu = X86Base.CpuId(X99Platform.CpuIdVersionLeaf, 0);
        int model = ((cpu.Eax >> X99Platform.CpuBaseModelShift) & X99Platform.CpuNibbleMask) |
            ((cpu.Eax >> X99Platform.CpuExtendedModelShift) & X99Platform.CpuExtendedModelMask);
        int family = (cpu.Eax >> X99Platform.CpuBaseFamilyShift) & X99Platform.CpuNibbleMask;
        if (vendor.Ebx != X99Platform.IntelVendorEbx || vendor.Edx != X99Platform.IntelVendorEdx ||
            vendor.Ecx != X99Platform.IntelVendorEcx || family != X99Platform.IntelCpuFamily ||
            !X99Platform.IsSupportedCpuModel(model))
        {
            throw new NotSupportedException(OperationError.PlatformUnsupported);
        }

        var driver = new ThrottleStopDriver { trace = diagnostic };
        try
        {
            diagnostic?.Invoke("DRIVER_LOADING service=" + driver.service);
            driver.Load(cancellationToken);
            diagnostic?.Invoke("DRIVER_OPENED");

            uint id = driver.ReadLpc(X99Platform.LpcVendorDeviceRegister);
            diagnostic?.Invoke($"PCI.LPC=0x{id:X8}");
            if (!X99Platform.IsSupportedLpcDeviceId(id))
            {
                throw new NotSupportedException(OperationError.PlatformUnsupported);
            }

            uint rcba = driver.ReadLpc(X99Platform.LpcRcbaRegister);
            diagnostic?.Invoke($"RCBA=0x{rcba:X8}");
            if (rcba == uint.MaxValue || (rcba & X99Platform.RcbaEnableFlag) == 0 ||
                (rcba & X99Platform.RcbaAddressMask) == 0)
            {
                throw new IOException(OperationError.DescriptorUnavailable);
            }

            driver.spiBar = (rcba & X99Platform.RcbaAddressMask) + X99Platform.SpiBarOffsetFromRcba;
            uint biosRegion = driver.Read(X99Platform.Spi.BiosRegionRegister, X99Platform.Spi.DwordWidth);
            (driver.biosRegionStart, int biosLength) = X99SpiReader.DecodeBiosRegion(biosRegion);
            driver.biosRegionEndExclusive = checked(driver.biosRegionStart + (uint)biosLength);
            diagnostic?.Invoke($"SPI.BIOS=0x{driver.biosRegionStart:X8}-0x{driver.biosRegionEndExclusive:X8}");
            return driver;
        }
        catch
        {
            driver.Dispose();
            throw;
        }
    }

    private void Load(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        BinaryIntegrityManifest manifest = ThrottleStopDriverAuthenticity.Manifest;
        RecoverStaleDriverArtifacts(manifest, trace, cancellationToken);
        Directory.CreateDirectory(directory);
        EnsurePlainDriverDirectory(directory);
        string path = Path.Combine(directory, manifest.FileName);

        using Stream resource = typeof(ThrottleStopDriver).Assembly.GetManifestResourceStream(
                ThrottleStopDriverAuthenticity.DriverResourceName)
            ?? throw new InvalidDataException(OperationError.IntegrityManifest);
        using var memory = new MemoryStream();
        resource.CopyTo(memory);
        byte[] bytes = memory.ToArray();
        ThrottleStopDriverAuthenticity.VerifyBytes(bytes);

        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(bytes);
            output.Flush(flushToDisk: true);
        }

        // Keep write/delete sharing denied through the entire kernel-service lifetime.
        lockedDriver = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        ThrottleStopDriverAuthenticity.VerifyLockedFile(lockedDriver, path);

        string serviceBinaryPath = NativeDosDevicePathPrefix + Path.GetFullPath(path);
        driverService = KernelDriverService.Create(service, serviceBinaryPath);
        driverService.Start(trace, cancellationToken);
        trace?.Invoke("DRIVER_FILE=" + path + " EXISTS=" + File.Exists(path));

        cancellationToken.ThrowIfCancellationRequested();
        device = Native.CreateFile(@"\\.\" + service, GenericReadAccess, 0, 0, OpenExisting, 0, 0);
        if (device.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    private uint ReadLpc(uint offset)
    {
        if (offset is not (X99Platform.LpcVendorDeviceRegister or X99Platform.LpcRcbaRegister))
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }
        return ReadLpcConfig(offset, X99Platform.Spi.DwordWidth);
    }

    public byte ReadBiosControl() => checked((byte)ReadLpcConfig(
        X99Platform.LpcBiosControlRegister, X99Platform.Spi.ByteWidth));

    public void SetBiosWriteEnable(bool enabled)
    {
        byte current = ReadBiosControl();
        byte desired = enabled
            ? (byte)(current | X99Platform.BiosWriteEnable)
            : (byte)(current & ~X99Platform.BiosWriteEnable);
        if (desired == current)
        {
            return;
        }

        // Capability boundary: only BIOS_CNTL.BIOSWE may be changed. BLE, SMM_BWP and all
        // other policy/state bits are preserved exactly as read from hardware.
        byte[] input = BuildPciConfigAddress(X99Platform.LpcBiosControlRegister, X99Platform.Spi.ByteWidth);
        input[DriverProtocolAddressBytes] = desired;
        _ = Ioctl(WritePciConfigIoctl, input, 0);
    }

    private uint ReadLpcConfig(uint offset, int width)
    {
        bool dwordRead = (offset == X99Platform.LpcVendorDeviceRegister ||
                          offset == X99Platform.LpcRcbaRegister) &&
                         width == X99Platform.Spi.DwordWidth;
        bool biosControlRead = offset == X99Platform.LpcBiosControlRegister &&
                               width == X99Platform.Spi.ByteWidth;
        bool allowed = dwordRead || biosControlRead;
        if (!allowed)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        byte[] input = BuildPciConfigAddress(offset, 0);
        byte[] data = Ioctl(ReadPciConfigIoctl, input, width);
        return width == X99Platform.Spi.ByteWidth
            ? data[0]
            : BinaryPrimitives.ReadUInt32LittleEndian(data);
    }

    private static byte[] BuildPciConfigAddress(uint offset, int trailingBytes)
    {
        byte[] input = new byte[DriverProtocolAddressBytes + trailingBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(input,
            ((ulong)offset << PciRegisterOffsetShift) |
            ((ulong)X99Platform.LpcFunctionNumber << PciFunctionShift) |
            ((ulong)X99Platform.LpcDeviceNumber << PciDeviceShift) |
            ((ulong)X99Platform.LpcBusNumber << PciBusShift));
        return input;
    }

    public uint Read(int offset, int width)
    {
        bool flashRegionRegister = offset >= X99Platform.Spi.FirstFlashRegionRegister &&
            offset <= X99Platform.Spi.LastFlashRegionRegister &&
            (offset - X99Platform.Spi.FirstFlashRegionRegister) % X99Platform.Spi.FlashRegionRegisterStride == 0;
        bool protectedRangeRegister = offset >= X99Platform.Spi.ProtectedRange0Register &&
            offset <= X99Platform.Spi.ProtectedRange4Register &&
            (offset - X99Platform.Spi.ProtectedRange0Register) % X99Platform.Spi.ProtectedRangeRegisterStride == 0;
        bool allowed = (offset == X99Platform.Spi.HardwareStatusRegister && width == X99Platform.Spi.WordWidth) ||
            (offset == X99Platform.Spi.FlashRegionAccessPermissionsRegister && width == X99Platform.Spi.DwordWidth) ||
            ((flashRegionRegister || protectedRangeRegister) && width == X99Platform.Spi.DwordWidth) ||
            (offset >= X99Platform.Spi.FlashData0Register && offset <= X99Platform.Spi.FlashDataLastRegister &&
             offset % X99Platform.Spi.DwordWidth == 0 && width == X99Platform.Spi.DwordWidth);
        if (!allowed || spiBar == 0)
        {
            throw new InvalidOperationException(OperationError.RegisterDenied);
        }

        byte[] input = new byte[DriverProtocolAddressBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(input, spiBar + (uint)offset);
        byte[] data = Ioctl(ReadPhysicalMemoryIoctl, input, width);
        return width == X99Platform.Spi.WordWidth
            ? BinaryPrimitives.ReadUInt16LittleEndian(data)
            : BinaryPrimitives.ReadUInt32LittleEndian(data);
    }

    public void Write(int offset, int width, uint value)
    {
        bool controlAllowed = offset == X99Platform.Spi.HardwareControlRegister && width == X99Platform.Spi.WordWidth &&
            ((value == X99Platform.Spi.ReadCycleCommand && pendingFlashAddressValid) ||
             (value == X99Platform.Spi.ProgramCycleCommand && IsPendingBiosWrite(X99Platform.Spi.TransferBytes)) ||
             (value == X99Platform.Spi.Erase4KCycleCommand && IsPendingBiosErase()));
        bool allowed =
            (offset == X99Platform.Spi.HardwareStatusRegister && width == X99Platform.Spi.WordWidth &&
             (value & ~X99Platform.Spi.CompletionStatusWriteOneToClear) == 0) ||
            controlAllowed ||
            (offset == X99Platform.Spi.FlashAddressRegister && width == X99Platform.Spi.DwordWidth &&
             value <= X99Platform.Spi.MaximumHardwareSequenceAddressExclusive - X99Platform.Spi.TransferBytes &&
             value % X99Platform.Spi.TransferBytes == 0) ||
            (offset >= X99Platform.Spi.FlashData0Register && offset <= X99Platform.Spi.FlashDataLastRegister &&
             offset % X99Platform.Spi.DwordWidth == 0 && width == X99Platform.Spi.DwordWidth);
        if (!allowed || spiBar == 0)
        {
            throw new InvalidOperationException(OperationError.RegisterDenied);
        }

        byte[] input = new byte[DriverProtocolAddressBytes + width];
        BinaryPrimitives.WriteUInt64LittleEndian(input, spiBar + (uint)offset);
        for (int n = 0; n < width; n++)
        {
            input[DriverProtocolAddressBytes + n] = (byte)(value >> (n * BitsPerByte));
        }
        _ = Ioctl(WritePhysicalMemoryIoctl, input, 0);
        if (offset == X99Platform.Spi.FlashAddressRegister)
        {
            pendingFlashAddress = value;
            pendingFlashAddressValid = true;
        }
        else if (offset == X99Platform.Spi.HardwareControlRegister)
        {
            pendingFlashAddressValid = false;
        }
    }

    private bool IsPendingBiosWrite(int bytes) => bytes > 0 && pendingFlashAddressValid &&
        biosRegionEndExclusive > biosRegionStart && biosRegionEndExclusive - biosRegionStart >= checked((uint)bytes) &&
        pendingFlashAddress >= biosRegionStart && pendingFlashAddress <= biosRegionEndExclusive - checked((uint)bytes);

    private bool IsPendingBiosErase() => IsPendingBiosWrite(4096) && (pendingFlashAddress & 0xFFFu) == 0;

    private byte[] Ioctl(uint code, byte[] input, int outputSize)
    {
        byte[] output = new byte[outputSize];
        if (!Native.DeviceIoControl(device!, code, input, (uint)input.Length, output,
                (uint)output.Length, out uint returned, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        if (returned != outputSize)
        {
            throw new IOException(OperationError.DriverResponse);
        }
        return output;
    }

    private static void RecoverStaleDriverArtifacts(
        BinaryIntegrityManifest manifest,
        Action<string>? trace,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string root = Path.Combine(Environment.SystemDirectory, SystemDriversDirectoryName);
        if (!Directory.Exists(root))
        {
            return;
        }

        string[] staleDirectories;
        try
        {
            staleDirectories = Directory.GetDirectories(root, ApplicationIdentity.DriverServicePrefix + "*");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(error);
            return;
        }

        foreach (string staleDirectory in staleDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string serviceName = Path.GetFileName(staleDirectory);
            if (!IsOwnedServiceName(serviceName))
            {
                continue;
            }

            string expectedFile = Path.Combine(staleDirectory, manifest.FileName);
            string expectedBinaryPath = NativeDosDevicePathPrefix + Path.GetFullPath(expectedFile);
            try
            {
                StaleDriverServiceCleanupResult cleanup = KernelDriverService.CleanupStale(
                    serviceName,
                    expectedBinaryPath,
                    trace,
                    cancellationToken);
                if (cleanup == StaleDriverServiceCleanupResult.OwnershipMismatch)
                {
                    continue;
                }
                TryDeleteOwnedDriverDirectory(staleDirectory, expectedFile, trace);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                trace?.Invoke("STALE_DRIVER_CLEANUP_FAILED name=" + serviceName + " error=" + error.GetType().Name);
                AppLog.Error(error);
            }
        }
    }

    private static bool IsOwnedServiceName(string serviceName)
    {
        if (!serviceName.StartsWith(ApplicationIdentity.DriverServicePrefix, StringComparison.Ordinal))
        {
            return false;
        }
        ReadOnlySpan<char> suffix = serviceName.AsSpan(ApplicationIdentity.DriverServicePrefix.Length);
        return Guid.TryParseExact(suffix, "N", out _);
    }

    private static void TryDeleteOwnedDriverDirectory(string directory, string expectedFile, Action<string>? trace)
    {
        string[] entries;
        try
        {
            var directoryInfo = new DirectoryInfo(directory);
            directoryInfo.Refresh();
            if (!directoryInfo.Exists)
            {
                return;
            }
            if ((directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                trace?.Invoke("STALE_DRIVER_DIRECTORY_SKIPPED name=" + directoryInfo.Name + " reason=reparse-point");
                return;
            }
            entries = Directory.GetFileSystemEntries(directory);
        }
        catch (DirectoryNotFoundException)
        {
            return;
        }

        if (entries.Length > 1 ||
            (entries.Length == 1 && !string.Equals(
                Path.GetFullPath(entries[0]),
                Path.GetFullPath(expectedFile),
                StringComparison.OrdinalIgnoreCase)))
        {
            trace?.Invoke("STALE_DRIVER_DIRECTORY_SKIPPED name=" + Path.GetFileName(directory) + " reason=unexpected-content");
            return;
        }

        try
        {
            if (File.Exists(expectedFile))
            {
                if ((File.GetAttributes(expectedFile) & FileAttributes.ReparsePoint) != 0)
                {
                    trace?.Invoke("STALE_DRIVER_DIRECTORY_SKIPPED name=" + Path.GetFileName(directory) + " reason=file-reparse-point");
                    return;
                }
                File.Delete(expectedFile);
            }
            Directory.Delete(directory);
            trace?.Invoke("STALE_DRIVER_DIRECTORY_REMOVED name=" + Path.GetFileName(directory));
        }
        catch (DirectoryNotFoundException)
        {
            return;
        }
        catch (FileNotFoundException)
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory);
            }
        }
    }

    private static void EnsurePlainDriverDirectory(string path)
    {
        var directoryInfo = new DirectoryInfo(path);
        directoryInfo.Refresh();
        if (!directoryInfo.Exists || (directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new System.Security.SecurityException(OperationError.DriverService);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        device?.Dispose();
        device = null;

        bool serviceRemoved = driverService is null;
        if (driverService is not null)
        {
            try
            {
                driverService.StopAndDelete(trace);
                serviceRemoved = true;
            }
            catch (Exception error)
            {
                AppLog.Error(error);
            }
            finally
            {
                driverService.Dispose();
                driverService = null;
            }
        }

        lockedDriver?.Dispose();
        lockedDriver = null;

        // A failed SCM cleanup deliberately leaves the verified binary in place so no live service points at a deleted file.
        if (!serviceRemoved)
        {
            return;
        }

        try
        {
            string path = Path.Combine(directory, ThrottleStopDriverAuthenticity.Manifest.FileName);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(error);
        }
    }

    private static class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(string name, uint access, uint share,
            nint security, uint disposition, uint flags, nint template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] input,
            uint inputSize, byte[] output, uint outputSize, out uint returned, nint overlapped);
    }
}
