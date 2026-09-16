using System.Buffers.Binary;

namespace XeonV3Control.Core;

/// <summary>Logical PI firmware-file states after normalizing the firmware-volume erase polarity.</summary>
internal enum FfsFileState : byte
{
    HeaderConstruction = AmiSecureBootSpecification.FfsFileHeaderConstructionState,
    HeaderValid = AmiSecureBootSpecification.FfsFileHeaderValidState,
    DataValid = AmiSecureBootSpecification.FfsFileDataValidState,
    MarkedForUpdate = AmiSecureBootSpecification.FfsFileMarkedForUpdateState,
    Deleted = AmiSecureBootSpecification.FfsFileDeletedState,
    HeaderInvalid = AmiSecureBootSpecification.FfsFileHeaderInvalidState,
}

internal readonly record struct FfsFileHeaderInfo(
    Guid Guid,
    byte Type,
    byte Attributes,
    int Size,
    int HeaderSize,
    FfsFileState State);

/// <summary>Strict parser for PI FFS file headers used by firmware mutation code.</summary>
internal static class UefiFfsFileParser
{
    internal static bool TryRead(
        ReadOnlySpan<byte> source,
        int offset,
        int limit,
        byte eraseByte,
        out FfsFileHeaderInfo header)
    {
        header = default;
        if (eraseByte is not (byte.MinValue or byte.MaxValue) ||
            offset < 0 || limit < offset || limit > source.Length)
        {
            return false;
        }

        int available = limit - offset;
        if (available < AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            return false;
        }

        ReadOnlySpan<byte> fixedHeader = source.Slice(offset, AmiSecureBootSpecification.FfsFileHeaderBytes);
        byte attributes = fixedHeader[AmiSecureBootSpecification.FfsAttributesOffset];
        if ((attributes & ~AmiSecureBootSpecification.FfsKnownAttributeMask) != 0)
        {
            return false;
        }

        int encodedSize = ReadU24(fixedHeader, AmiSecureBootSpecification.FfsSizeOffset);
        bool largeFile = (attributes & AmiSecureBootSpecification.FfsLargeFileAttribute) != 0;
        int headerSize;
        long fileSize;

        if (largeFile)
        {
            // PI FFS_FILE_HEADER2 uses a zero 24-bit Size field and stores the real size in ExtendedSize.
            if (encodedSize != AmiSecureBootSpecification.FfsLargeFileSizeMarker ||
                available < AmiSecureBootSpecification.FfsExtendedFileHeaderBytes)
            {
                return false;
            }

            headerSize = AmiSecureBootSpecification.FfsExtendedFileHeaderBytes;
            ulong extendedSize = BinaryPrimitives.ReadUInt64LittleEndian(
                source[(offset + AmiSecureBootSpecification.FfsExtendedSizeOffset)..]);
            if (extendedSize > int.MaxValue)
            {
                return false;
            }
            fileSize = (long)extendedSize;
        }
        else
        {
            headerSize = AmiSecureBootSpecification.FfsFileHeaderBytes;
            fileSize = encodedSize;
        }

        if (fileSize < headerSize || fileSize > available)
        {
            return false;
        }

        ReadOnlySpan<byte> completeHeader = source.Slice(offset, headerSize);
        if (!HasValidHeaderChecksum(completeHeader))
        {
            return false;
        }

        byte logicalState = eraseByte == byte.MaxValue
            ? unchecked((byte)~fixedHeader[AmiSecureBootSpecification.FfsStateOffset])
            : fixedHeader[AmiSecureBootSpecification.FfsStateOffset];
        if ((logicalState & ~AmiSecureBootSpecification.FfsKnownStateMask) != 0 || logicalState == 0)
        {
            return false;
        }

        FfsFileState state = HighestState(logicalState);
        if (state == FfsFileState.DataValid &&
            (logicalState & AmiSecureBootSpecification.FfsDataValidPrerequisiteMask) !=
            AmiSecureBootSpecification.FfsDataValidPrerequisiteMask)
        {
            return false;
        }

        int size = checked((int)fileSize);
        if (state == FfsFileState.DataValid &&
            !HasValidFileChecksum(source.Slice(offset, size), headerSize, attributes))
        {
            return false;
        }

        header = new FfsFileHeaderInfo(
            new Guid(fixedHeader[..AmiSecureBootSpecification.FfsNameBytes]),
            fixedHeader[AmiSecureBootSpecification.FfsTypeOffset],
            attributes,
            size,
            headerSize,
            state);
        return true;
    }

    private static bool HasValidHeaderChecksum(ReadOnlySpan<byte> header)
    {
        byte sum = 0;
        for (int index = 0; index < header.Length; index++)
        {
            if (index is AmiSecureBootSpecification.FfsFileChecksumOffset or AmiSecureBootSpecification.FfsStateOffset)
            {
                continue;
            }
            sum = unchecked((byte)(sum + header[index]));
        }
        return sum == 0;
    }

    private static bool HasValidFileChecksum(ReadOnlySpan<byte> file, int headerSize, byte attributes)
    {
        byte stored = file[AmiSecureBootSpecification.FfsFileChecksumOffset];
        if ((attributes & AmiSecureBootSpecification.FfsChecksumAttribute) == 0)
        {
            return stored == AmiSecureBootSpecification.FfsFixedFileChecksum;
        }

        byte sum = stored;
        foreach (byte value in file[headerSize..])
        {
            sum = unchecked((byte)(sum + value));
        }
        return sum == 0;
    }

    private static FfsFileState HighestState(byte state)
    {
        if ((state & AmiSecureBootSpecification.FfsFileHeaderInvalidState) != 0)
        {
            return FfsFileState.HeaderInvalid;
        }
        if ((state & AmiSecureBootSpecification.FfsFileDeletedState) != 0)
        {
            return FfsFileState.Deleted;
        }
        if ((state & AmiSecureBootSpecification.FfsFileMarkedForUpdateState) != 0)
        {
            return FfsFileState.MarkedForUpdate;
        }
        if ((state & AmiSecureBootSpecification.FfsFileDataValidState) != 0)
        {
            return FfsFileState.DataValid;
        }
        if ((state & AmiSecureBootSpecification.FfsFileHeaderValidState) != 0)
        {
            return FfsFileState.HeaderValid;
        }
        return FfsFileState.HeaderConstruction;
    }

    private static int ReadU24(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;
}

/// <summary>Shared PI FFS checksum writer used by firmware mutation paths.</summary>
internal static class UefiFfsChecksum
{
    internal static bool TryRecalculate(Span<byte> file, int headerSize)
    {
        if (headerSize < AmiSecureBootSpecification.FfsFileHeaderBytes ||
            headerSize > file.Length ||
            AmiSecureBootSpecification.FfsHeaderChecksumOffset >= headerSize ||
            AmiSecureBootSpecification.FfsFileChecksumOffset >= headerSize ||
            AmiSecureBootSpecification.FfsStateOffset >= headerSize)
        {
            return false;
        }

        file[AmiSecureBootSpecification.FfsHeaderChecksumOffset] = 0;
        file[AmiSecureBootSpecification.FfsFileChecksumOffset] =
            (file[AmiSecureBootSpecification.FfsAttributesOffset] & AmiSecureBootSpecification.FfsChecksumAttribute) != 0
                ? unchecked((byte)(0 - Sum8(file[headerSize..])))
                : AmiSecureBootSpecification.FfsFixedFileChecksum;

        byte headerSum = 0;
        for (int index = 0; index < headerSize; index++)
        {
            if (index is AmiSecureBootSpecification.FfsFileChecksumOffset or AmiSecureBootSpecification.FfsStateOffset)
            {
                continue;
            }
            headerSum = unchecked((byte)(headerSum + file[index]));
        }
        file[AmiSecureBootSpecification.FfsHeaderChecksumOffset] = unchecked((byte)(0 - headerSum));
        return true;
    }

    private static byte Sum8(ReadOnlySpan<byte> data)
    {
        byte sum = 0;
        foreach (byte value in data)
        {
            sum = unchecked((byte)(sum + value));
        }
        return sum;
    }
}
