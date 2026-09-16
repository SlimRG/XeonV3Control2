using System.Buffers.Binary;
using System.Diagnostics;

namespace XeonV3Control.Core;

/// <summary>Register-only transport; production implementation restricts access to one validated SPI BAR.</summary>
public interface ISpiRegisters
{
    uint Read(int offset, int width);
    void Write(int offset, int width, uint value);
}

/// <summary>Minimal additional capability required for a BIOS-region write.
/// Implementations may change only BIOS_CNTL.BIOSWE; security policy bits stay read-only.</summary>
public interface IX99SpiFlashAccess : ISpiRegisters
{
    byte ReadBiosControl();
    void SetBiosWriteEnable(bool enabled);
}

public sealed class X99SpiReader(ISpiRegisters registers) : IFirmwareReader
{
    private const int ReadCycleAttempts = 3;
    private static readonly FlashRegionKind[] RegionKinds =
    [
        FlashRegionKind.Descriptor,
        FlashRegionKind.BIOS,
        FlashRegionKind.ME,
        FlashRegionKind.GbE,
        FlashRegionKind.PDR
    ];

    public FirmwareCapabilities Capabilities => new(true, false, FirmwareReadScope.FullSpi);

    public FirmwareReadSnapshot ReadFirmware(IProgress<double>? progress, CancellationToken cancellationToken)
    {
        EnsureControllerReady();

        uint permissions = registers.Read(
            X99Platform.Spi.FlashRegionAccessPermissionsRegister,
            X99Platform.Spi.DwordWidth) & X99Platform.Spi.RegionReadAccessMask;
        IReadOnlyList<SpiRegionDefinition> regions = ReadRegionMap();
        SpiRegionDefinition bios = regions.FirstOrDefault(region => region.Kind == FlashRegionKind.BIOS)
            ?? throw new InvalidDataException(FirmwareValidationError.InvalidBiosRegion);
        if (!HasReadPermission(permissions, bios.Index))
        {
            throw new IOException(OperationError.ReadProtected);
        }

        uint flashEnd = regions.Max(region => checked(region.Start + (uint)region.Length));
        if (flashEnd > X99Platform.Spi.MaximumHardwareSequenceAddressExclusive ||
            flashEnd > BiosImageLoader.MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.InvalidDescriptor);
        }

        byte[] fullImage = new byte[checked((int)flashEnd)];
        Array.Fill(fullImage, byte.MaxValue);

        long totalReadableBytes = regions
            .Where(region => HasReadPermission(permissions, region.Index))
            .Sum(region => (long)region.Length);
        long completedBytes = 0;
        var statuses = new List<FirmwareRegionReadStatus>(regions.Count);

        foreach (SpiRegionDefinition region in regions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool readable = HasReadPermission(permissions, region.Index);
            if (readable)
            {
                try
                {
                    ReadRange(
                        region.Start,
                        fullImage.AsSpan(checked((int)region.Start), region.Length),
                        bytesRead =>
                        {
                            if (totalReadableBytes > 0)
                            {
                                progress?.Report((completedBytes + bytesRead) / (double)totalReadableBytes);
                            }
                        },
                        cancellationToken);
                }
                catch (SpiRegionAccessDeniedException)
                {
                    fullImage.AsSpan(checked((int)region.Start), region.Length).Fill(byte.MaxValue);
                    readable = false;
                }
                catch (Exception error) when (region.Kind != FlashRegionKind.BIOS &&
                    IsRecoverableReadFailure(error))
                {
                    // Descriptor/ME/GbE/PDR failures must not prevent a valid BIOS-region dump.
                    // The unreadable region remains explicit (0xFF + Readable=false) and the
                    // two-pass verifier still requires the resulting scope/map to be stable.
                    fullImage.AsSpan(checked((int)region.Start), region.Length).Fill(byte.MaxValue);
                    readable = false;
                }
                catch (Exception error) when (region.Kind == FlashRegionKind.BIOS &&
                    IsRecoverableReadFailure(error))
                {
                    throw new IOException(error.Message, new InvalidOperationException(
                        $"SPI BIOS-region read failed: start=0x{region.Start:X8}, length=0x{region.Length:X}, " +
                        $"FRAP.read=0x{permissions:X2}.", error));
                }
            }

            statuses.Add(new FirmwareRegionReadStatus(region.Kind, region.Start, region.Length, readable));
            if (readable)
            {
                completedBytes += region.Length;
                if (totalReadableBytes > 0)
                {
                    progress?.Report(completedBytes / (double)totalReadableBytes);
                }
            }
        }

        FirmwareRegionReadStatus biosStatus = statuses.First(status => status.Kind == FlashRegionKind.BIOS);
        if (!biosStatus.Readable)
        {
            throw new IOException(OperationError.ReadProtected);
        }

        FirmwareRegionReadStatus? descriptorStatus = statuses.FirstOrDefault(
            status => status.Kind == FlashRegionKind.Descriptor);
        if (descriptorStatus is not { Readable: true } ||
            !TryDecodeFlashSize(fullImage, descriptorStatus, out uint flashSize) ||
            flashSize < flashEnd)
        {
            progress?.Report(1);
            byte[] biosImage = fullImage
                .AsSpan(checked((int)bios.Start), bios.Length)
                .ToArray();
            return new FirmwareReadSnapshot(biosImage, FirmwareReadScope.BiosRegion, statuses.ToArray());
        }

        if (flashSize > fullImage.Length)
        {
            int previousLength = fullImage.Length;
            Array.Resize(ref fullImage, checked((int)flashSize));
            fullImage.AsSpan(previousLength).Fill(byte.MaxValue);
        }

        bool allMappedRegionsReadable = statuses.All(status => status.Readable);
        bool completeAddressSpaceRead = allMappedRegionsReadable && ReadUnmappedAddressSpace(
            regions,
            flashSize,
            fullImage,
            cancellationToken);
        progress?.Report(1);

        FirmwareReadScope scope = allMappedRegionsReadable && completeAddressSpaceRead
            ? FirmwareReadScope.FullSpi
            : FirmwareReadScope.PartialSpi;
        return new FirmwareReadSnapshot(fullImage, scope, statuses.ToArray());
    }

    private void EnsureControllerReady()
    {
        uint status = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
        if (status == ushort.MaxValue || (status & X99Platform.Spi.DescriptorValid) == 0)
        {
            throw new IOException(OperationError.DescriptorUnavailable);
        }

        if ((status & X99Platform.Spi.CycleInProgress) != 0)
        {
            throw new IOException(OperationError.SpiBusy);
        }
    }

    private IReadOnlyList<SpiRegionDefinition> ReadRegionMap()
    {
        var regions = new List<SpiRegionDefinition>(X99Platform.Spi.FlashRegionCount);
        for (int index = 0; index < X99Platform.Spi.FlashRegionCount; index++)
        {
            int registerOffset = X99Platform.Spi.FirstFlashRegionRegister +
                index * X99Platform.Spi.FlashRegionRegisterStride;
            uint value = registers.Read(registerOffset, X99Platform.Spi.DwordWidth);
            SpiRegionDefinition? region = DecodeRegion(index, value);
            if (region is not null)
            {
                regions.Add(region);
            }
        }

        if (regions.Count == 0 || regions.All(region => region.Kind != FlashRegionKind.BIOS))
        {
            throw new InvalidDataException(FirmwareValidationError.InvalidBiosRegion);
        }

        SpiRegionDefinition[] ordered = regions.OrderBy(region => region.Start).ToArray();
        for (int index = 1; index < ordered.Length; index++)
        {
            uint previousEnd = checked(ordered[index - 1].Start + (uint)ordered[index - 1].Length);
            if (ordered[index].Start < previousEnd)
            {
                throw new InvalidDataException(FirmwareValidationError.OverlappingRegions);
            }
        }

        return ordered;
    }

    private void ReadRange(
        uint start,
        Span<byte> destination,
        Action<int> reportBytesRead,
        CancellationToken cancellationToken)
    {
        for (int offset = 0; offset < destination.Length; offset += X99Platform.Spi.TransferBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if ((registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth) &
                 X99Platform.Spi.CycleInProgress) != 0)
            {
                throw new IOException(OperationError.SpiBusy);
            }

            // Only controller state required for an SPI read cycle is touched. No erase/write opcode,
            // BIOS_CNTL, FRAP, protected range or lock register is modified.
            uint address = checked(start + (uint)offset);
            ExecuteReadCycle(address);

            for (int word = 0; word < X99Platform.Spi.TransferDwords; word++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(
                    destination.Slice(
                        offset + word * X99Platform.Spi.DwordWidth,
                        X99Platform.Spi.DwordWidth),
                    registers.Read(
                        X99Platform.Spi.FlashData0Register + word * X99Platform.Spi.DwordWidth,
                        X99Platform.Spi.DwordWidth));
            }

            if (offset % X99Platform.Spi.ProgressReportIntervalBytes == 0)
            {
                reportBytesRead(offset);
            }
        }

        reportBytesRead(destination.Length);
    }

    private void ExecuteReadCycle(uint address)
    {
        for (int attempt = 1; attempt <= ReadCycleAttempts; attempt++)
        {
            uint before = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
            if ((before & X99Platform.Spi.CycleInProgress) != 0)
            {
                throw new IOException(OperationError.SpiBusy);
            }

            // HSFS is a 16-bit register on Wellsburg. Clear only the RW1C completion bits
            // with a 16-bit access before every transaction; byte writes are not used here.
            registers.Write(
                X99Platform.Spi.HardwareStatusRegister,
                X99Platform.Spi.WordWidth,
                before & X99Platform.Spi.CompletionStatusWriteOneToClear);
            registers.Write(
                X99Platform.Spi.FlashAddressRegister,
                X99Platform.Spi.DwordWidth,
                address);
            registers.Write(
                X99Platform.Spi.HardwareControlRegister,
                X99Platform.Spi.WordWidth,
                X99Platform.Spi.ReadCycleCommand);

            uint status = WaitForRead(address, attempt);
            if ((status & X99Platform.Spi.AccessError) != 0)
            {
                throw new SpiRegionAccessDeniedException();
            }

            if ((status & X99Platform.Spi.CycleError) != 0)
            {
                if (attempt < ReadCycleAttempts)
                {
                    continue;
                }

                throw CreateReadFailure(OperationError.SpiCycleError, address, status, attempt);
            }

            if ((status & X99Platform.Spi.CycleDone) != 0)
            {
                return;
            }
        }

        throw new IOException(OperationError.SpiCycleError);
    }

    private uint WaitForRead(uint address, int attempt)
    {
        var timer = Stopwatch.StartNew();
        SpinWait wait = default;
        uint lastStatus = 0;
        while (timer.Elapsed < X99Platform.Spi.ReadCycleTimeout)
        {
            lastStatus = registers.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth);
            if ((lastStatus & X99Platform.Spi.CycleInProgress) == 0 &&
                (lastStatus & (X99Platform.Spi.CycleDone | X99Platform.Spi.CycleError | X99Platform.Spi.AccessError)) != 0)
            {
                return lastStatus;
            }

            wait.SpinOnce();
        }

        throw CreateReadTimeout(address, lastStatus, attempt);
    }

    private static IOException CreateReadFailure(string message, uint address, uint status, int attempt) =>
        new(message, new InvalidOperationException(
            $"SPI hardware read failed: FADDR=0x{address:X8}, HSFS=0x{status:X4}, " +
            $"HSFC=0x{X99Platform.Spi.ReadCycleCommand:X4}, attempt={attempt}/{ReadCycleAttempts}."));

    private static TimeoutException CreateReadTimeout(uint address, uint status, int attempt) =>
        new(OperationError.SpiTimeout, new TimeoutException(
            $"SPI hardware read timed out: FADDR=0x{address:X8}, HSFS=0x{status:X4}, " +
            $"HSFC=0x{X99Platform.Spi.ReadCycleCommand:X4}, attempt={attempt}/{ReadCycleAttempts}."));

    private static bool IsRecoverableReadFailure(Exception error) =>
        (error is IOException && error.Message == OperationError.SpiCycleError) ||
        (error is TimeoutException && error.Message == OperationError.SpiTimeout);

    public static (uint Start, int Length) DecodeBiosRegion(uint value)
    {
        SpiRegionDefinition? region = DecodeRegion(1, value);
        if (region is null || region.Kind != FlashRegionKind.BIOS)
        {
            throw new InvalidDataException(FirmwareValidationError.InvalidBiosRegion);
        }

        return (region.Start, region.Length);
    }

    private static SpiRegionDefinition? DecodeRegion(int index, uint value)
    {
        if (index is < 0 or >= X99Platform.Spi.FlashRegionCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        // Intel flash descriptors use 0x00007FFF as the canonical "region unused"
        // encoding (base 0x7FFF, limit 0). Some Wellsburg firmware exposes that
        // descriptor value verbatim through FREGn even though bits 15:13 are
        // reserved in the C610/X99 SPIBAR view. Recognize only this disabled
        // sentinel before validating reserved bits; active regions remain strict.
        bool canonicalUnusedDescriptorRegion = index > 0 &&
            value == IntelFlashDescriptorSpecification.RegionAddressFieldMask;
        if (canonicalUnusedDescriptorRegion || (index > 0 && value == 0))
        {
            return null;
        }

        if ((value & X99Platform.Spi.RegionReservedBitsMask) != 0)
        {
            throw new InvalidDataException(index == 1
                ? FirmwareValidationError.InvalidBiosRegion
                : FirmwareValidationError.InvalidDescriptor);
        }

        uint startField = value & X99Platform.Spi.RegionFieldMask;
        uint endField = (value >> 16) & X99Platform.Spi.RegionFieldMask;
        if (startField > endField)
        {
            return null;
        }

        uint start = startField << X99Platform.Spi.RegionAddressShift;
        uint end = (endField << X99Platform.Spi.RegionAddressShift) | X99Platform.Spi.RegionTailMask;
        if (end >= X99Platform.Spi.MaximumFlashAddressExclusive)
        {
            throw new InvalidDataException(index == 1
                ? FirmwareValidationError.InvalidBiosRegion
                : FirmwareValidationError.InvalidDescriptor);
        }

        uint rawLength = checked(end - start + 1);
        if (rawLength > BiosImageLoader.MaxImageBytes ||
            rawLength % X99Platform.Spi.TransferBytes != 0 ||
            (index == 1 && rawLength < X99Platform.Spi.MinimumReadableBiosRegionBytes))
        {
            throw new InvalidDataException(index == 1
                ? FirmwareValidationError.InvalidBiosRegion
                : FirmwareValidationError.InvalidDescriptor);
        }

        return new SpiRegionDefinition(index, RegionKinds[index], start, checked((int)rawLength));
    }

    private static bool HasReadPermission(uint permissions, int regionIndex) =>
        (permissions & (1u << regionIndex)) != 0;

    internal static bool TryDecodeFlashSize(
        ReadOnlySpan<byte> image,
        FirmwareRegionReadStatus descriptor,
        out uint flashSize)
    {
        flashSize = 0;
        if (descriptor.Start != 0 || !descriptor.Readable ||
            descriptor.Length < IntelFlashDescriptorSpecification.DescriptorWindowBytes ||
            image.Length < IntelFlashDescriptorSpecification.DescriptorWindowBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(IntelFlashDescriptorSpecification.SignatureOffset, sizeof(uint))) !=
                IntelFlashDescriptorSpecification.Signature)
        {
            return false;
        }

        uint flashMap0 = BinaryPrimitives.ReadUInt32LittleEndian(
            image.Slice(IntelFlashDescriptorSpecification.FlashMap0Offset, sizeof(uint)));
        int componentBase = checked((int)((flashMap0 >> IntelFlashDescriptorSpecification.ComponentBaseFieldShift) &
            IntelFlashDescriptorSpecification.ComponentBaseFieldMask) *
            IntelFlashDescriptorSpecification.ComponentSectionAddressUnitBytes);
        int componentCount = checked((int)((flashMap0 >> IntelFlashDescriptorSpecification.ComponentCountFieldShift) &
            IntelFlashDescriptorSpecification.ComponentCountFieldMask) +
            IntelFlashDescriptorSpecification.ComponentCountBias);
        if (componentCount is < 1 or > IntelFlashDescriptorSpecification.MaximumWellsburgComponentCount ||
            componentBase < 0 ||
            componentBase + sizeof(uint) > IntelFlashDescriptorSpecification.DescriptorWindowBytes ||
            componentBase + sizeof(uint) > descriptor.Length)
        {
            return false;
        }

        uint componentConfiguration = BinaryPrimitives.ReadUInt32LittleEndian(
            image.Slice(componentBase + IntelFlashDescriptorSpecification.FlashComponentConfigurationOffset, sizeof(uint)));
        ulong totalBytes = 0;
        for (int component = 0; component < componentCount; component++)
        {
            int shift = component == 0 ? 0 : IntelFlashDescriptorSpecification.SecondComponentDensityFieldShift;
            uint densityIndex = (componentConfiguration >> shift) &
                IntelFlashDescriptorSpecification.ComponentDensityFieldMask;
            if (densityIndex > IntelFlashDescriptorSpecification.MaximumWellsburgComponentDensityIndex)
            {
                return false;
            }

            totalBytes += (ulong)IntelFlashDescriptorSpecification.MinimumComponentBytes << checked((int)densityIndex);
        }

        if (totalBytes is 0 or > X99Platform.Spi.MaximumHardwareSequenceAddressExclusive ||
            totalBytes > BiosImageLoader.MaxImageBytes)
        {
            return false;
        }

        flashSize = checked((uint)totalBytes);
        return true;
    }

    private bool ReadUnmappedAddressSpace(
        IReadOnlyList<SpiRegionDefinition> regions,
        uint flashSize,
        byte[] image,
        CancellationToken cancellationToken)
    {
        bool complete = true;
        uint cursor = 0;
        foreach (SpiRegionDefinition region in regions.OrderBy(region => region.Start))
        {
            if (region.Start > cursor)
            {
                complete &= TryReadUnmappedRange(cursor, region.Start, image, cancellationToken);
            }

            cursor = checked(region.Start + (uint)region.Length);
        }

        if (cursor < flashSize)
        {
            complete &= TryReadUnmappedRange(cursor, flashSize, image, cancellationToken);
        }

        return complete;
    }

    private bool TryReadUnmappedRange(
        uint start,
        uint endExclusive,
        byte[] image,
        CancellationToken cancellationToken)
    {
        if (endExclusive <= start)
        {
            return true;
        }

        int length = checked((int)(endExclusive - start));
        Span<byte> destination = image.AsSpan(checked((int)start), length);
        try
        {
            ReadRange(start, destination, _ => { }, cancellationToken);
            return true;
        }
        catch (SpiRegionAccessDeniedException)
        {
            destination.Fill(byte.MaxValue);
            return false;
        }
        catch (Exception error) when (IsRecoverableReadFailure(error))
        {
            destination.Fill(byte.MaxValue);
            return false;
        }
    }

    private sealed record SpiRegionDefinition(int Index, FlashRegionKind Kind, uint Start, int Length);

    private sealed class SpiRegionAccessDeniedException : IOException
    {
    }
}
