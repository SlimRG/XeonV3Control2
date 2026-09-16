using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace XeonV3Control.Core;

public sealed record FirmwareFlashResult(int ChangedSectors, int WrittenBytes, string BiosSha256);

/// <summary>
/// Fail-closed Wellsburg hardware-sequencing BIOS-region writer. It never writes the flash descriptor,
/// Intel ME, GbE or PDR regions and never changes FRAP, protected-range or chipset lock registers.
/// </summary>
public sealed class X99SpiFlasher(IX99SpiFlashAccess registers)
{
    private const int SectorBytes = 4096;

    public FirmwareFlashResult FlashBios(
        ReadOnlySpan<byte> targetImageBytes,
        BiosImage targetImage,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targetImage);
        UefiDriverMutationPlanner.EnsureImageMatches(targetImageBytes, targetImage);
        EnsureControllerReady();

        (uint biosStart, int biosLength) = ReadBiosRegion();
        if ((biosStart & (SectorBytes - 1)) != 0 || biosLength <= 0 || biosLength % SectorBytes != 0)
        {
            throw new InvalidDataException(OperationError.FlashLayoutMismatch);
        }

        byte[] targetBios = SelectTargetBios(targetImageBytes, targetImage, biosLength);
        byte[] currentBios = new byte[biosLength];
        ReadRange(biosStart, currentBios, cancellationToken);
        ValidateTargetIdentity(currentBios, targetBios, cancellationToken);

        var changed = new List<int>();
        for (int offset = 0; offset < biosLength; offset += SectorBytes)
        {
            if (!currentBios.AsSpan(offset, SectorBytes).SequenceEqual(targetBios.AsSpan(offset, SectorBytes)))
            {
                changed.Add(offset);
            }
        }
        if (changed.Count == 0)
        {
            progress?.Report(1);
            return new(0, 0, Convert.ToHexString(SHA256.HashData(targetBios)));
        }

        SpiProtectionSnapshot protectionSnapshot = ReadProtectionSnapshot();
        EnsureBiosWritePermission(protectionSnapshot.Permissions);
        EnsureChangedSectorsWritable(biosStart, changed, protectionSnapshot.ProtectedRanges);
        EnsureChangedSectorsUse4KErase(biosStart, changed);
        EnsureProtectionConfigurationUnchanged(protectionSnapshot);

        byte initialBiosControl = registers.ReadBiosControl();
        Exception? operationFailure = null;
        try
        {
            EnableBiosWriteAccess(initialBiosControl);
            byte[] preflight = new byte[SectorBytes];
            byte[] verify = new byte[SectorBytes];
            int completed = 0;
            foreach (int relativeOffset in changed)
            {
                cancellationToken.ThrowIfCancellationRequested();
                EnsureProtectionConfigurationUnchanged(protectionSnapshot);
                EnsureBiosWriteAccess();

                uint absolute = checked(biosStart + (uint)relativeOffset);
                ReadRange(absolute, preflight, cancellationToken);
                if (!preflight.AsSpan().SequenceEqual(currentBios.AsSpan(relativeOffset, SectorBytes)))
                {
                    throw new IOException(OperationError.FlashSourceChanged);
                }

                // Re-read FRAP/PR0-PR4 and BIOS_CNTL immediately before the destructive command.
                EnsureProtectionConfigurationUnchanged(protectionSnapshot);
                EnsureBiosWriteAccess();

                // Once erase starts, finish and verify this 4 KiB sector before observing cancellation
                // or protection drift. Stopping between erase and program could leave the sector blank.
                Erase4K(absolute, CancellationToken.None);
                ReadOnlySpan<byte> sector = targetBios.AsSpan(relativeOffset, SectorBytes);
                for (int chunk = 0; chunk < SectorBytes; chunk += X99Platform.Spi.TransferBytes)
                {
                    ReadOnlySpan<byte> payload = sector.Slice(chunk, X99Platform.Spi.TransferBytes);
                    if (payload.IndexOfAnyExcept(byte.MaxValue) < 0)
                    {
                        continue;
                    }

                    // BIOSWE can be cleared by firmware/SMM independently of SPIBAR. Re-assert only
                    // this single host-write-enable bit if needed; BLE/SMM_BWP are never changed.
                    EnsureBiosWriteAccess();
                    Program64(checked(absolute + (uint)chunk), payload, CancellationToken.None);
                }

                ReadRange(absolute, verify, CancellationToken.None);
                if (!verify.AsSpan().SequenceEqual(sector))
                {
                    throw new IOException(OperationError.FlashVerifyFailed);
                }
                completed++;
                progress?.Report(completed / (double)changed.Count);

                // If firmware/SMM/another privileged tool changed FRAP or a protected-range register
                // after erase had already begun, the current sector is first restored and verified,
                // then flashing stops before any next sector can be erased.
                EnsureProtectionConfigurationUnchanged(protectionSnapshot);
            }

            byte[] final = new byte[biosLength];
            ReadRange(biosStart, final, CancellationToken.None);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(final), SHA256.HashData(targetBios)))
            {
                throw new IOException(OperationError.FlashVerifyFailed);
            }
            progress?.Report(1);
            return new(changed.Count, changed.Count * SectorBytes, Convert.ToHexString(SHA256.HashData(final)));
        }
        catch (Exception error)
        {
            operationFailure = error;
            throw;
        }
        finally
        {
            RestoreBiosWriteAccess(initialBiosControl, operationFailure);
        }
    }

    private void EnableBiosWriteAccess(byte initial)
    {
        if ((initial & X99Platform.SmmBiosWriteProtection) != 0)
        {
            throw new IOException(OperationError.FlashSmmWriteProtectionEnabled, new InvalidOperationException(
                DescribeBiosControl(initial)));
        }

        if ((initial & X99Platform.BiosWriteEnable) == 0)
        {
            registers.SetBiosWriteEnable(true);
        }
        EnsureBiosWriteAccess();

        // A BIOSWE transition can generate an SMI when BLE is set. Read a second time after the
        // transition so an SMI handler that immediately revokes BIOSWE is detected before erase.
        Thread.SpinWait(256);
        EnsureBiosWriteAccess();
    }

    private void EnsureBiosWriteAccess()
    {
        byte control = registers.ReadBiosControl();
        if ((control & X99Platform.SmmBiosWriteProtection) != 0)
        {
            throw new IOException(OperationError.FlashSmmWriteProtectionEnabled, new InvalidOperationException(
                DescribeBiosControl(control)));
        }
        if ((control & X99Platform.BiosWriteEnable) != 0)
        {
            return;
        }

        registers.SetBiosWriteEnable(true);
        control = registers.ReadBiosControl();
        if ((control & X99Platform.BiosWriteEnable) == 0)
        {
            throw new IOException(OperationError.FlashBiosWriteEnableUnavailable, new InvalidOperationException(
                DescribeBiosControl(control)));
        }
    }

    private void RestoreBiosWriteAccess(byte initial, Exception? operationFailure)
    {
        bool initiallyEnabled = (initial & X99Platform.BiosWriteEnable) != 0;
        try
        {
            registers.SetBiosWriteEnable(initiallyEnabled);
            byte restored = registers.ReadBiosControl();
            if (((restored & X99Platform.BiosWriteEnable) != 0) != initiallyEnabled)
            {
                throw new IOException(OperationError.FlashBiosWriteRestoreFailed, new InvalidOperationException(
                    $"Initial {DescribeBiosControl(initial)}; restored {DescribeBiosControl(restored)}"));
            }
        }
        catch (Exception restoreError) when (operationFailure is not null)
        {
            operationFailure.Data["BIOSWE restore failure"] = restoreError.ToString();
        }
    }

    private static string DescribeBiosControl(byte value) =>
        $"BIOS_CNTL=0x{value:X2} (BIOSWE={((value & X99Platform.BiosWriteEnable) != 0 ? 1 : 0)}, " +
        $"BLE={((value & X99Platform.BiosLockEnable) != 0 ? 1 : 0)}, " +
        $"SMM_BWP={((value & X99Platform.SmmBiosWriteProtection) != 0 ? 1 : 0)})";

    private static byte[] SelectTargetBios(ReadOnlySpan<byte> source, BiosImage image, int expectedLength)
    {
        FlashRegion? region = image.Regions.SingleOrDefault(item => item.Kind == FlashRegionKind.BIOS);
        if (region is not null)
        {
            if (!region.WithinImage || region.Length != expectedLength || region.Offset < 0 ||
                region.Offset > source.Length - region.Length)
            {
                throw new InvalidDataException(OperationError.FlashLayoutMismatch);
            }
            return source.Slice(checked((int)region.Offset), checked((int)region.Length)).ToArray();
        }
        if (source.Length != expectedLength || image.Kind == ImageKind.Capsule)
        {
            throw new InvalidDataException(OperationError.FlashLayoutMismatch);
        }
        return source.ToArray();
    }

    private static void ValidateTargetIdentity(
        ReadOnlySpan<byte> current,
        ReadOnlySpan<byte> target,
        CancellationToken token)
    {
        BiosImage currentImage = BiosImageLoader.Analyze(current, cancellationToken: token);
        BiosImage targetImage = BiosImageLoader.Analyze(target, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(currentImage);
        BiosImageLoader.EnsureValidBiosImage(targetImage);

        if (!StableIdentityCompatible(currentImage.FirmwareIdentity, targetImage.FirmwareIdentity))
        {
            throw new InvalidDataException(OperationError.FlashIdentityMismatch);
        }

        var currentVolumes = currentImage.Volumes.Select(v => (v.Offset, v.Length, v.FileSystem)).ToArray();
        var targetVolumes = targetImage.Volumes.Select(v => (v.Offset, v.Length, v.FileSystem)).ToArray();
        if (!currentVolumes.SequenceEqual(targetVolumes))
        {
            throw new InvalidDataException(OperationError.FlashLayoutMismatch);
        }
    }

    private static bool StableIdentityCompatible(FirmwareImageIdentity current, FirmwareImageIdentity target)
    {
        static bool RequiredEqual(string? left, string? right) =>
            !string.IsNullOrWhiteSpace(left) && !string.IsNullOrWhiteSpace(right) &&
            string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);

        static bool OptionalEqual(string? left, string? right)
        {
            bool leftMissing = string.IsNullOrWhiteSpace(left);
            bool rightMissing = string.IsNullOrWhiteSpace(right);
            return leftMissing && rightMissing ||
                !leftMissing && !rightMissing &&
                string.Equals(left!.Trim(), right!.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        return RequiredEqual(current.BoardManufacturer, target.BoardManufacturer) &&
            RequiredEqual(current.BoardName, target.BoardName) &&
            OptionalEqual(current.BoardVersion, target.BoardVersion);
    }

    private (uint Start, int Length) ReadBiosRegion()
    {
        uint value = registers.Read(X99Platform.Spi.BiosRegionRegister, X99Platform.Spi.DwordWidth);
        if ((value & X99Platform.Spi.RegionReservedBitsMask) != 0)
        {
            throw new InvalidDataException(OperationError.FlashLayoutMismatch);
        }
        uint start = (value & X99Platform.Spi.RegionFieldMask) << X99Platform.Spi.RegionAddressShift;
        uint limit = ((value >> 16) & X99Platform.Spi.RegionFieldMask) << X99Platform.Spi.RegionAddressShift;
        limit |= X99Platform.Spi.RegionTailMask;
        if (start > limit || limit >= X99Platform.Spi.MaximumHardwareSequenceAddressExclusive)
        {
            throw new InvalidDataException(OperationError.FlashLayoutMismatch);
        }
        return (start, checked((int)(limit - start + 1)));
    }

    private void EnsureControllerReady()
    {
        uint status = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
        if ((status & X99Platform.Spi.DescriptorValid) == 0)
        {
            throw new IOException(OperationError.DescriptorUnavailable);
        }
        if ((status & X99Platform.Spi.CycleInProgress) != 0)
        {
            throw new IOException(OperationError.SpiBusy);
        }
    }

    private static void EnsureBiosWritePermission(uint permissions)
    {
        uint biosWriteBit = 1u << (8 + (int)FlashRegionKind.BIOS);
        if ((permissions & biosWriteBit) == 0)
        {
            throw new IOException(OperationError.WriteProtected);
        }
    }

    private SpiProtectionSnapshot ReadProtectionSnapshot()
    {
        uint permissions = registers.Read(
            X99Platform.Spi.FlashRegionAccessPermissionsRegister,
            X99Platform.Spi.DwordWidth);
        var protectedRanges = new uint[X99Platform.Spi.ProtectedRangeCount];
        for (int index = 0; index < protectedRanges.Length; index++)
        {
            int register = X99Platform.Spi.ProtectedRange0Register +
                index * X99Platform.Spi.ProtectedRangeRegisterStride;
            protectedRanges[index] = registers.Read(register, X99Platform.Spi.DwordWidth);
        }
        return new SpiProtectionSnapshot(permissions, protectedRanges);
    }

    private void EnsureProtectionConfigurationUnchanged(SpiProtectionSnapshot expected)
    {
        EnsureControllerReady();
        uint currentPermissions = registers.Read(
            X99Platform.Spi.FlashRegionAccessPermissionsRegister,
            X99Platform.Spi.DwordWidth);
        if (currentPermissions != expected.Permissions)
        {
            throw new IOException(OperationError.FlashProtectionStateChanged);
        }

        for (int index = 0; index < expected.ProtectedRanges.Length; index++)
        {
            int register = X99Platform.Spi.ProtectedRange0Register +
                index * X99Platform.Spi.ProtectedRangeRegisterStride;
            uint current = registers.Read(register, X99Platform.Spi.DwordWidth);
            if (current != expected.ProtectedRanges[index])
            {
                throw new IOException(OperationError.FlashProtectionStateChanged);
            }
        }
    }

    private static void EnsureChangedSectorsWritable(
        uint biosStart,
        IReadOnlyList<int> changedSectors,
        IReadOnlyList<uint> protectedRanges)
    {
        for (int index = 0; index < protectedRanges.Count; index++)
        {
            uint value = protectedRanges[index];
            if ((value & X99Platform.Spi.ProtectedRangeReservedBitsMask) != 0)
            {
                throw new InvalidDataException(OperationError.FlashLayoutMismatch);
            }
            if ((value & X99Platform.Spi.ProtectedRangeWriteProtection) == 0)
            {
                continue;
            }

            uint protectedStart = (value & X99Platform.Spi.ProtectedRangeFieldMask) <<
                X99Platform.Spi.RegionAddressShift;
            uint protectedEnd = ((value >> 16) & X99Platform.Spi.ProtectedRangeFieldMask) <<
                X99Platform.Spi.RegionAddressShift;
            protectedEnd |= X99Platform.Spi.RegionTailMask;
            if (protectedStart > protectedEnd)
            {
                throw new InvalidDataException(OperationError.FlashLayoutMismatch);
            }

            foreach (int relativeOffset in changedSectors)
            {
                uint sectorStart = checked(biosStart + (uint)relativeOffset);
                uint sectorEnd = checked(sectorStart + (uint)SectorBytes - 1u);
                if (sectorStart <= protectedEnd && sectorEnd >= protectedStart)
                {
                    throw new IOException(OperationError.WriteProtected);
                }
            }
        }
    }

    private void EnsureChangedSectorsUse4KErase(uint biosStart, IReadOnlyList<int> changedSectors)
    {
        foreach (int relativeOffset in changedSectors)
        {
            uint address = checked(biosStart + (uint)relativeOffset);
            registers.Write(X99Platform.Spi.FlashAddressRegister, X99Platform.Spi.DwordWidth, address);
            uint status = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
            if ((status & X99Platform.Spi.BlockEraseSizeMask) != X99Platform.Spi.BlockEraseSize4K)
            {
                throw new IOException(OperationError.FlashEraseSizeUnsupported);
            }
        }
    }

    private void ReadRange(uint address, Span<byte> destination, CancellationToken token)
    {
        for (int offset = 0; offset < destination.Length; offset += X99Platform.Spi.TransferBytes)
        {
            token.ThrowIfCancellationRequested();
            int count = Math.Min(X99Platform.Spi.TransferBytes, destination.Length - offset);
            if (count != X99Platform.Spi.TransferBytes)
            {
                throw new InvalidDataException(OperationError.FlashLayoutMismatch);
            }
            StartCycle(address + (uint)offset, X99Platform.Spi.ReadCycleCommand, token);
            for (int dword = 0; dword < X99Platform.Spi.TransferDwords; dword++)
            {
                uint value = registers.Read(
                    X99Platform.Spi.FlashData0Register + dword * X99Platform.Spi.DwordWidth,
                    X99Platform.Spi.DwordWidth);
                BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset + dword * 4, 4), value);
            }
        }
    }

    private void Program64(uint address, ReadOnlySpan<byte> data, CancellationToken token)
    {
        if (data.Length != X99Platform.Spi.TransferBytes || address % X99Platform.Spi.TransferBytes != 0)
        {
            throw new ArgumentException(nameof(data));
        }
        for (int dword = 0; dword < X99Platform.Spi.TransferDwords; dword++)
        {
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(dword * 4, 4));
            registers.Write(
                X99Platform.Spi.FlashData0Register + dword * X99Platform.Spi.DwordWidth,
                X99Platform.Spi.DwordWidth,
                value);
        }
        StartCycle(address, X99Platform.Spi.ProgramCycleCommand, token);
    }

    private void Erase4K(uint address, CancellationToken token)
    {
        if ((address & (SectorBytes - 1)) != 0)
        {
            throw new ArgumentException(nameof(address));
        }
        StartCycle(address, X99Platform.Spi.Erase4KCycleCommand, token);
    }

    private void StartCycle(uint address, uint command, CancellationToken token)
    {
        uint before = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
        registers.Write(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth,
            before & X99Platform.Spi.CompletionStatusWriteOneToClear);
        registers.Write(X99Platform.Spi.FlashAddressRegister, X99Platform.Spi.DwordWidth, address);
        registers.Write(X99Platform.Spi.HardwareControlRegister, X99Platform.Spi.WordWidth, command);

        var timer = Stopwatch.StartNew();
        while (true)
        {
            token.ThrowIfCancellationRequested();
            uint status = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
            if ((status & X99Platform.Spi.CycleInProgress) == 0)
            {
                if ((status & X99Platform.Spi.AccessError) != 0)
                {
                    byte biosControl = registers.ReadBiosControl();
                    throw new IOException(OperationError.WriteProtected, new InvalidOperationException(
                        $"SPI access error: FADDR=0x{address:X8}, HSFS=0x{status:X4}, " +
                        $"HSFC=0x{command:X4}, {DescribeBiosControl(biosControl)}."));
                }
                if ((status & X99Platform.Spi.CycleError) != 0 || (status & X99Platform.Spi.CycleDone) == 0)
                {
                    byte biosControl = registers.ReadBiosControl();
                    throw new IOException(OperationError.SpiCycleError, new InvalidOperationException(
                        $"SPI hardware cycle failed: FADDR=0x{address:X8}, HSFS=0x{status:X4}, " +
                        $"HSFC=0x{command:X4}, {DescribeBiosControl(biosControl)}."));
                }
                return;
            }
            if (timer.Elapsed >= X99Platform.Spi.ReadCycleTimeout)
            {
                byte biosControl = registers.ReadBiosControl();
                throw new TimeoutException(OperationError.SpiTimeout, new TimeoutException(
                    $"SPI hardware cycle timed out: FADDR=0x{address:X8}, HSFS=0x{status:X4}, " +
                    $"HSFC=0x{command:X4}, {DescribeBiosControl(biosControl)}."));
            }
            Thread.SpinWait(64);
        }
    }

    private sealed record SpiProtectionSnapshot(uint Permissions, uint[] ProtectedRanges);

}
