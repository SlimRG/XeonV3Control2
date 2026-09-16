using System.Buffers.Binary;

namespace XeonV3Control.Core;

/// <summary>
/// Rebase helper for a deliberately narrow, provable XIP PEIM subset. It supports only a direct,
/// uncompressed PE32/PE32+ section whose raw layout is identical to its RVA layout and whose current
/// ImageBase exactly matches the physical SPI-mapped payload address. TE and nested sections are rejected.
/// </summary>
internal static class UefiXipPeRebaser
{
    private const ulong FourGiB = 0x1_0000_0000UL;
    private const ushort ImageFileRelocationsStripped = 0x0001;
    private const int PeCharacteristicsOffset = 22;
    private const int PeOptionalImageBase32Offset = 28;
    private const int PeOptionalImageBase64Offset = 24;
    private const int PeOptionalSectionAlignmentOffset = 32;
    private const int PeOptionalFileAlignmentOffset = 36;
    private const int PeOptionalSizeOfImageOffset = 56;
    private const int PeOptionalSizeOfHeadersOffset = 60;
    private const int PeOptionalNumberOfRvaAndSizes32Offset = 92;
    private const int PeOptionalNumberOfRvaAndSizes64Offset = 108;
    private const int PeOptionalDataDirectory32Offset = 96;
    private const int PeOptionalDataDirectory64Offset = 112;
    private const int PeSectionVirtualSizeOffset = 8;
    private const int PeSectionVirtualAddressOffset = 12;
    private const int BaseRelocationDirectoryIndex = 5;
    private const int DataDirectoryEntryBytes = 8;
    private const int BaseRelocationBlockHeaderBytes = 8;
    private const int BaseRelocationEntryBytes = 2;
    private const int RelocationAbsolute = 0;
    private const int RelocationHighLow = 3;
    private const int RelocationDir64 = 10;
    private const int MaximumRelocations = 1_000_000;

    internal static bool TryRebasePeim(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiFfsFileLocation file,
        int destinationOffset,
        byte eraseByte,
        out byte[] rebased)
    {
        rebased = [];
        FlashRegion? descriptor = image.Regions.SingleOrDefault(region => region.Kind == FlashRegionKind.Descriptor);
        FlashRegion? bios = image.Regions.SingleOrDefault(region => region.Kind == FlashRegionKind.BIOS);
        if (image.Kind != ImageKind.IntelSpiImage || image.Size != source.Length ||
            source.Length < BiosImageLoader.MinBiosImageBytes || !IsPowerOfTwo(source.Length) ||
            descriptor is null || descriptor.Offset != 0 || !descriptor.WithinImage ||
            bios is null || !bios.WithinImage || !RangeWithin(file.Offset, file.Size, bios.Offset, bios.Length) ||
            !RangeWithin(destinationOffset, file.Size, bios.Offset, bios.Length) ||
            file.Type != 0x06 || destinationOffset < 0 || AmiSecureBootSpecification.IsFixed(file.Attributes) ||
            file.Offset < 0 || file.Size <= file.HeaderSize || file.Offset > source.Length - file.Size ||
            destinationOffset > source.Length - file.Size ||
            !UefiFfsFileParser.TryRead(source, file.Offset, checked(file.Offset + file.Size), eraseByte,
                out FfsFileHeaderInfo sourceHeader) ||
            sourceHeader.State != FfsFileState.DataValid || sourceHeader.Guid != file.Guid ||
            sourceHeader.Type != file.Type || sourceHeader.Attributes != file.Attributes ||
            sourceHeader.Size != file.Size || sourceHeader.HeaderSize != file.HeaderSize)
        {
            return false;
        }

        ReadOnlySpan<byte> sourceFile = source.Slice(file.Offset, file.Size);
        if (!TryFindDirectPe32Payload(sourceFile, file.HeaderSize, eraseByte, out int payloadOffset, out int payloadSize))
        {
            return false;
        }

        ulong flashBase = FourGiB - checked((ulong)source.Length);
        ulong oldPayloadAddress = checked(flashBase + (ulong)file.Offset + (ulong)payloadOffset);
        ulong newPayloadAddress = checked(flashBase + (ulong)destinationOffset + (ulong)payloadOffset);
        if (oldPayloadAddress == newPayloadAddress)
        {
            rebased = sourceFile.ToArray();
            return true;
        }

        rebased = sourceFile.ToArray();
        Span<byte> pe = rebased.AsSpan(payloadOffset, payloadSize);
        if (!TryRebasePe32(pe, oldPayloadAddress, newPayloadAddress) ||
            !UefiFfsChecksum.TryRecalculate(rebased, file.HeaderSize) ||
            !UefiFfsFileParser.TryRead(rebased, 0, rebased.Length, eraseByte, out FfsFileHeaderInfo resultHeader) ||
            resultHeader.State != FfsFileState.DataValid || resultHeader.Guid != file.Guid ||
            resultHeader.Type != file.Type || resultHeader.Attributes != file.Attributes ||
            resultHeader.Size != file.Size || resultHeader.HeaderSize != file.HeaderSize)
        {
            rebased = [];
            return false;
        }
        return true;
    }

    private static bool TryFindDirectPe32Payload(
        ReadOnlySpan<byte> file,
        int fileHeaderSize,
        byte eraseByte,
        out int payloadOffset,
        out int payloadSize)
    {
        payloadOffset = 0;
        payloadSize = 0;
        int offset = fileHeaderSize;
        int peCount = 0;
        while (offset <= file.Length - UefiPiCode.CommonSectionHeaderBytes)
        {
            if (IsTrailingPadding(file[offset..], eraseByte))
            {
                break;
            }

            int encodedSize = ReadU24(file, offset);
            int headerSize;
            int sectionSize;
            byte type = file[offset + AmiSecureBootSpecification.SectionTypeOffset];
            if (encodedSize == AmiSecureBootSpecification.U24ExtendedSizeMarker)
            {
                if (offset > file.Length - UefiPiCode.ExtendedSectionHeaderBytes)
                {
                    return false;
                }
                uint extended = BinaryPrimitives.ReadUInt32LittleEndian(
                    file[(offset + UefiPiCode.ExtendedSectionSizeOffset)..]);
                if (extended > int.MaxValue)
                {
                    return false;
                }
                sectionSize = checked((int)extended);
                headerSize = UefiPiCode.ExtendedSectionHeaderBytes;
            }
            else
            {
                sectionSize = encodedSize;
                headerSize = UefiPiCode.CommonSectionHeaderBytes;
            }

            if (sectionSize <= headerSize || sectionSize > file.Length - offset ||
                type is UefiPiCode.SectionCompression or UefiPiCode.SectionGuidDefined or
                    UefiPiCode.SectionDisposable or UefiPiCode.SectionTe)
            {
                return false;
            }

            if (type == UefiPiCode.SectionPe32)
            {
                peCount++;
                if (peCount != 1)
                {
                    return false;
                }
                payloadOffset = checked(offset + headerSize);
                payloadSize = checked(sectionSize - headerSize);
            }

            int next = Align4(checked(offset + sectionSize));
            if (next < offset || next > file.Length)
            {
                return false;
            }
            offset = next;
        }

        return peCount == 1 && payloadSize > 0 && IsTrailingPadding(file[offset..], eraseByte);
    }

    private static bool TryRebasePe32(Span<byte> image, ulong expectedOldBase, ulong newBase)
    {
        if (image.Length < UefiPiCode.DosPeOffsetOffset + sizeof(int) ||
            BinaryPrimitives.ReadUInt16LittleEndian(image) != UefiPiCode.DosMagic)
        {
            return false;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(image[UefiPiCode.DosPeOffsetOffset..]);
        if (peOffset < 0 || peOffset > image.Length - UefiPiCode.PeOptionalHeaderOffset ||
            BinaryPrimitives.ReadUInt32LittleEndian(image[peOffset..]) != UefiPiCode.PeSignature)
        {
            return false;
        }

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeMachineOffset)..]);
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeNumberOfSectionsOffset)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeOptionalHeaderSizeOffset)..]);
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + PeCharacteristicsOffset)..]);
        int optionalOffset = checked(peOffset + UefiPiCode.PeOptionalHeaderOffset);
        if (sectionCount is < 1 or > UefiPiCode.MaximumExecutableSections ||
            (characteristics & ImageFileRelocationsStripped) != 0 || optionalSize <= 0 ||
            optionalOffset > image.Length - optionalSize)
        {
            return false;
        }

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image[optionalOffset..]);
        bool pe32 = machine == UefiPiCode.PeMachineIa32 && magic == UefiPiCode.PeOptionalMagic32;
        bool pe64 = machine == UefiPiCode.PeMachineX64 && magic == UefiPiCode.PeOptionalMagic64;
        if (!pe32 && !pe64)
        {
            return false;
        }

        int imageBaseOffset = pe32 ? PeOptionalImageBase32Offset : PeOptionalImageBase64Offset;
        int numberOfDirectoriesOffset = pe32 ? PeOptionalNumberOfRvaAndSizes32Offset : PeOptionalNumberOfRvaAndSizes64Offset;
        int dataDirectoryOffset = pe32 ? PeOptionalDataDirectory32Offset : PeOptionalDataDirectory64Offset;
        int minimumOptionalSize = checked(dataDirectoryOffset + (BaseRelocationDirectoryIndex + 1) * DataDirectoryEntryBytes);
        if (optionalSize < minimumOptionalSize)
        {
            return false;
        }

        ulong currentBase = pe32
            ? BinaryPrimitives.ReadUInt32LittleEndian(image[(optionalOffset + imageBaseOffset)..])
            : BinaryPrimitives.ReadUInt64LittleEndian(image[(optionalOffset + imageBaseOffset)..]);
        if (currentBase != expectedOldBase || pe32 && newBase > uint.MaxValue)
        {
            return false;
        }

        uint sectionAlignment = BinaryPrimitives.ReadUInt32LittleEndian(
            image[(optionalOffset + PeOptionalSectionAlignmentOffset)..]);
        uint fileAlignment = BinaryPrimitives.ReadUInt32LittleEndian(
            image[(optionalOffset + PeOptionalFileAlignmentOffset)..]);
        uint sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(
            image[(optionalOffset + PeOptionalSizeOfImageOffset)..]);
        uint sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(
            image[(optionalOffset + PeOptionalSizeOfHeadersOffset)..]);
        if (sectionAlignment < UefiPiCode.SectionAlignmentBytes || sectionAlignment > 0x1000 ||
            sectionAlignment != fileAlignment || !IsPowerOfTwo(sectionAlignment) ||
            sizeOfImage == 0 || sizeOfHeaders == 0 || sizeOfHeaders > image.Length ||
            expectedOldBase > FourGiB - sizeOfImage || newBase > FourGiB - sizeOfImage)
        {
            return false;
        }

        int sectionHeadersOffset = checked(optionalOffset + optionalSize);
        int sectionHeadersBytes = checked(sectionCount * UefiPiCode.PeSectionHeaderBytes);
        if (sectionHeadersOffset > image.Length - sectionHeadersBytes)
        {
            return false;
        }

        var sections = new PeSection[sectionCount];
        for (int index = 0; index < sectionCount; index++)
        {
            int sectionOffset = checked(sectionHeadersOffset + index * UefiPiCode.PeSectionHeaderBytes);
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(
                image[(sectionOffset + PeSectionVirtualSizeOffset)..]);
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(
                image[(sectionOffset + PeSectionVirtualAddressOffset)..]);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(
                image[(sectionOffset + UefiPiCode.PeSectionRawSizeOffset)..]);
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(
                image[(sectionOffset + UefiPiCode.PeSectionRawPointerOffset)..]);
            if (rawPointer != virtualAddress ||
                (rawSize != 0 && (rawPointer > (uint)image.Length || rawSize > (uint)image.Length - rawPointer)) ||
                (virtualSize != 0 && virtualAddress > sizeOfImage) ||
                Math.Max(virtualSize, rawSize) > sizeOfImage - Math.Min(virtualAddress, sizeOfImage))
            {
                return false;
            }
            sections[index] = new(virtualAddress, virtualSize, rawPointer, rawSize);
        }

        uint directoryCount = BinaryPrimitives.ReadUInt32LittleEndian(
            image[(optionalOffset + numberOfDirectoriesOffset)..]);
        if (directoryCount <= BaseRelocationDirectoryIndex)
        {
            return false;
        }
        int relocDirectoryOffset = checked(optionalOffset + dataDirectoryOffset + BaseRelocationDirectoryIndex * DataDirectoryEntryBytes);
        uint relocRva = BinaryPrimitives.ReadUInt32LittleEndian(image[relocDirectoryOffset..]);
        uint relocSize = BinaryPrimitives.ReadUInt32LittleEndian(image[(relocDirectoryOffset + sizeof(uint))..]);
        if (relocRva == 0 || relocSize < BaseRelocationBlockHeaderBytes || relocSize > int.MaxValue ||
            !TryMapRva(relocRva, relocSize, sizeOfHeaders, sections, image.Length, out int relocOffset))
        {
            return false;
        }

        long delta = checked((long)newBase - (long)expectedOldBase);
        int applied = 0;
        int consumed = 0;
        var targets = new HashSet<int>();
        while (consumed < relocSize)
        {
            if (relocSize - consumed < BaseRelocationBlockHeaderBytes)
            {
                return false;
            }
            int blockOffset = checked(relocOffset + consumed);
            uint pageRva = BinaryPrimitives.ReadUInt32LittleEndian(image[blockOffset..]);
            uint blockSizeRaw = BinaryPrimitives.ReadUInt32LittleEndian(image[(blockOffset + sizeof(uint))..]);
            if (blockSizeRaw < BaseRelocationBlockHeaderBytes || blockSizeRaw > int.MaxValue ||
                blockSizeRaw > relocSize - consumed ||
                (blockSizeRaw - BaseRelocationBlockHeaderBytes) % BaseRelocationEntryBytes != 0)
            {
                return false;
            }
            int blockSize = checked((int)blockSizeRaw);
            int entryCount = (blockSize - BaseRelocationBlockHeaderBytes) / BaseRelocationEntryBytes;
            for (int index = 0; index < entryCount; index++)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(
                    image[(blockOffset + BaseRelocationBlockHeaderBytes + index * BaseRelocationEntryBytes)..]);
                int type = entry >> 12;
                uint targetRva = checked(pageRva + (uint)(entry & 0x0FFF));
                if (type == RelocationAbsolute)
                {
                    continue;
                }
                int expectedType = pe32 ? RelocationHighLow : RelocationDir64;
                int width = pe32 ? sizeof(uint) : sizeof(ulong);
                if (type != expectedType || applied >= MaximumRelocations ||
                    !TryMapRva(targetRva, checked((uint)width), sizeOfHeaders, sections, image.Length, out int targetOffset) ||
                    !targets.Add(targetOffset))
                {
                    return false;
                }

                if (pe32)
                {
                    uint value = BinaryPrimitives.ReadUInt32LittleEndian(image[targetOffset..]);
                    if (value < expectedOldBase || value >= checked(expectedOldBase + sizeOfImage))
                    {
                        return false;
                    }
                    long adjusted = checked((long)value + delta);
                    if (adjusted < 0 || adjusted > uint.MaxValue)
                    {
                        return false;
                    }
                    BinaryPrimitives.WriteUInt32LittleEndian(image[targetOffset..], checked((uint)adjusted));
                }
                else
                {
                    ulong value = BinaryPrimitives.ReadUInt64LittleEndian(image[targetOffset..]);
                    if (value < expectedOldBase || value >= checked(expectedOldBase + sizeOfImage))
                    {
                        return false;
                    }
                    ulong adjusted = delta >= 0
                        ? checked(value + (ulong)delta)
                        : checked(value - (ulong)-delta);
                    BinaryPrimitives.WriteUInt64LittleEndian(image[targetOffset..], adjusted);
                }
                applied++;
            }
            consumed = checked(consumed + blockSize);
        }

        if (consumed != relocSize || applied == 0)
        {
            return false;
        }

        if (pe32)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(image[(optionalOffset + imageBaseOffset)..], checked((uint)newBase));
        }
        else
        {
            BinaryPrimitives.WriteUInt64LittleEndian(image[(optionalOffset + imageBaseOffset)..], newBase);
        }
        return true;
    }

    private static bool TryMapRva(
        uint rva,
        uint size,
        uint sizeOfHeaders,
        IReadOnlyList<PeSection> sections,
        int imageLength,
        out int offset)
    {
        offset = 0;
        ulong end = (ulong)rva + size;
        if (end > int.MaxValue)
        {
            return false;
        }
        if (rva < sizeOfHeaders && end <= sizeOfHeaders && end <= (ulong)imageLength)
        {
            offset = checked((int)rva);
            return true;
        }

        PeSection? match = null;
        foreach (PeSection section in sections)
        {
            ulong sectionStart = section.VirtualAddress;
            ulong sectionEnd = sectionStart + section.RawSize;
            if (rva >= sectionStart && end <= sectionEnd)
            {
                if (match is not null)
                {
                    return false;
                }
                match = section;
            }
        }
        if (match is null)
        {
            return false;
        }

        ulong raw = (ulong)match.RawPointer + (rva - match.VirtualAddress);
        if (raw + size > (ulong)imageLength)
        {
            return false;
        }
        offset = checked((int)raw);
        return true;
    }


    private static bool RangeWithin(long offset, int length, long containerOffset, long containerLength)
    {
        if (offset < containerOffset || length < 0 || containerLength < 0)
        {
            return false;
        }
        long relative = offset - containerOffset;
        return relative <= containerLength && length <= containerLength - relative;
    }

    private static int ReadU24(ReadOnlySpan<byte> source, int offset) =>
        source[offset] | source[offset + 1] << 8 | source[offset + 2] << 16;

    private static int Align4(int value) => checked((value + 3) & ~3);

    private static bool IsTrailingPadding(ReadOnlySpan<byte> data, byte eraseByte)
    {
        foreach (byte value in data)
        {
            if (value != eraseByte && value != 0)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsPowerOfTwo(long value) => value > 0 && (value & (value - 1)) == 0;
    private static bool IsPowerOfTwo(uint value) => value != 0 && (value & (value - 1)) == 0;

    private sealed record PeSection(uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize);
}
