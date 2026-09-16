using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpCompress.Compressors.LZMA;

namespace XeonV3Control.Core;

/// <summary>
/// Narrow AMI FFS editor for the common LZMA GUID-defined section layout used by the
/// boot-logo and BDS modules in the supported X99 firmware family. It is deliberately
/// fail-closed: the target FFS and the LZMA section must be unique and structurally valid.
/// </summary>
internal static class AmiLzmaFfsEditor
{
    private static readonly byte[] LzmaGuid = AmiSecureBootSpecification.LzmaGuidedSectionDefinition.ToByteArray();
    private static readonly byte[] PersonalizationPaddingMagic = [(byte)'X', (byte)'V', (byte)'3', (byte)'P'];

    internal readonly record struct LocatedFile(
        FirmwareVolume Volume,
        UefiFfsFileLocation File,
        string Sha256);

    internal readonly record struct SectionInfo(
        int Offset,
        int Size,
        int HeaderSize,
        byte Type,
        int AlignedEnd);

    internal static bool TryLocateUniqueFile(
        ReadOnlySpan<byte> source,
        BiosImage image,
        Guid fileGuid,
        CancellationToken token,
        out LocatedFile located)
    {
        located = default;
        int matches = 0;
        foreach (FirmwareVolume volume in image.Volumes)
        {
            token.ThrowIfCancellationRequested();
            if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem) ||
                !UefiFfsVolumeScanner.TryReadFiles(source, volume, token, out _, out IReadOnlyList<UefiFfsFileLocation> files))
            {
                continue;
            }

            foreach (UefiFfsFileLocation file in files)
            {
                if (file.State != FfsFileState.DataValid || file.Guid != fileGuid)
                {
                    continue;
                }

                matches++;
                if (matches > 1)
                {
                    located = default;
                    return false;
                }

                located = new(
                    volume,
                    file,
                    Convert.ToHexString(SHA256.HashData(source.Slice(file.Offset, file.Size))));
            }
        }
        return matches == 1;
    }

    internal static bool TryDecodeExpandedSectionStream(
        ReadOnlySpan<byte> ffs,
        CancellationToken token,
        out byte[] expanded,
        out int guidedSectionOffset,
        out int guidedSectionSize,
        out int guidedDataOffset)
    {
        expanded = [];
        guidedSectionOffset = 0;
        guidedSectionSize = 0;
        guidedDataOffset = 0;
        if (ffs.Length < AmiSecureBootSpecification.FfsFileHeaderBytes ||
            !TryReadFfsHeaderSize(ffs, out int ffsHeaderSize))
        {
            return false;
        }

        int cursor = ffsHeaderSize;
        int guidedMatches = 0;
        while (cursor <= ffs.Length - AmiSecureBootSpecification.SectionHeaderBytes)
        {
            token.ThrowIfCancellationRequested();
            if (!TryReadSection(ffs, cursor, ffs.Length, out SectionInfo section))
            {
                return false;
            }

            if (section.Type == AmiSecureBootSpecification.GuidedSectionType &&
                section.HeaderSize == AmiSecureBootSpecification.SectionHeaderBytes &&
                section.Size >= AmiSecureBootSpecification.GuidedSectionHeaderBytes &&
                ffs.Slice(section.Offset + AmiSecureBootSpecification.GuidedSectionDefinitionOffset,
                        AmiSecureBootSpecification.GuidedSectionDefinitionBytes)
                    .SequenceEqual(LzmaGuid))
            {
                guidedMatches++;
                if (guidedMatches > 1)
                {
                    return false;
                }

                int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    ffs[(section.Offset + AmiSecureBootSpecification.GuidedSectionDataOffsetOffset)..]);
                if (dataOffset < AmiSecureBootSpecification.GuidedSectionHeaderBytes ||
                    dataOffset > section.Size - AmiSecureBootSpecification.LzmaHeaderBytes)
                {
                    return false;
                }

                ReadOnlySpan<byte> packed = ffs.Slice(section.Offset + dataOffset, section.Size - dataOffset);
                if (!TryDecodeLzma(packed, token, out byte[] decoded))
                {
                    return false;
                }
                expanded = decoded;
                guidedSectionOffset = section.Offset;
                guidedSectionSize = section.Size;
                guidedDataOffset = dataOffset;
            }

            if (section.AlignedEnd <= cursor)
            {
                return false;
            }
            cursor = section.AlignedEnd;
        }

        return guidedMatches == 1 && expanded.Length != 0;
    }

    internal static byte[] RewriteExpandedSectionStream(
        ReadOnlySpan<byte> ffs,
        Func<byte[], byte[]> transform,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(transform);
        return RewriteExpandedSectionStreamCandidates(
            ffs,
            expanded => [transform(expanded)],
            token);
    }

    internal static byte[] RewriteExpandedSectionStreamCandidates(
        ReadOnlySpan<byte> ffs,
        Func<byte[], IReadOnlyList<byte[]>> transformCandidates,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(transformCandidates);
        if (!TryDecodeExpandedSectionStream(
                ffs,
                token,
                out byte[] expanded,
                out int guidedSectionOffset,
                out int guidedSectionSize,
                out int guidedDataOffset))
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }

        IReadOnlyList<byte[]> proposed = transformCandidates(expanded);
        if (proposed is null || proposed.Count is 0 or > 32)
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }

        var rewrittenCandidates = new List<byte[]>(proposed.Count);
        foreach (byte[]? candidate in proposed)
        {
            if (candidate is null ||
                candidate.Length < AmiSecureBootSpecification.SectionHeaderBytes ||
                candidate.Length > UefiDriverInspectionPolicy.MaximumExpandedSectionBytes)
            {
                throw new InvalidDataException(OperationError.PersonalizationUnsupported);
            }
            bool duplicate = false;
            foreach (byte[] existing in rewrittenCandidates)
            {
                if (existing.AsSpan().SequenceEqual(candidate))
                {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate)
            {
                rewrittenCandidates.Add(candidate);
            }
        }
        if (rewrittenCandidates.Count == 0)
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }

        // Personalization edits are footprint-preserving. AMI X99 volumes commonly pack the target
        // FFS immediately before another file. Try several legal LZMA parser-depth settings and, for
        // tightly packed code patches, several semantically equivalent expanded streams. This keeps
        // the neighbouring FFS at its original offset instead of rebuilding a large DXE volume.
        int originalAlignedSize = Align8(ffs.Length);
        int[] fastByteCandidates =
        [
            31, 32, 24, 28, 40, 48, 56, 57, 60, 64, 72, 80, 96,
            128, 160, 192, 224, 256, 273, 20, 16, 12, 8, 5
        ];

        var triedEncodings = new HashSet<int>();
        foreach (int numFastBytes in fastByteCandidates)
        {
            triedEncodings.Add(numFastBytes);
            foreach (byte[] rewrittenExpanded in rewrittenCandidates)
            {
                token.ThrowIfCancellationRequested();
                byte[] candidate = BuildRewrittenFfs(
                    ffs,
                    guidedSectionOffset,
                    guidedSectionSize,
                    guidedDataOffset,
                    rewrittenExpanded,
                    numFastBytes,
                    token);
                if (TryFinalizeCandidateForOriginalSlot(
                        candidate,
                        originalAlignedSize,
                        rewrittenExpanded,
                        token,
                        out byte[] finalized))
                {
                    return finalized;
                }
            }
        }

        // BDS and similarly small code modules are cheap enough for an exhaustive NumFastBytes sweep.
        // Interleave expanded-stream candidates at each encoder setting so a compact semantic variant
        // can succeed without paying a complete 269-setting sweep for every alternative.
        if (rewrittenCandidates.All(item => item.Length <= 256 * 1024))
        {
            for (int numFastBytes = 5; numFastBytes <= 273; numFastBytes++)
            {
                if (!triedEncodings.Add(numFastBytes))
                {
                    continue;
                }
                foreach (byte[] rewrittenExpanded in rewrittenCandidates)
                {
                    token.ThrowIfCancellationRequested();
                    byte[] candidate = BuildRewrittenFfs(
                        ffs,
                        guidedSectionOffset,
                        guidedSectionSize,
                        guidedDataOffset,
                        rewrittenExpanded,
                        numFastBytes,
                        token);
                    if (TryFinalizeCandidateForOriginalSlot(
                            candidate,
                            originalAlignedSize,
                            rewrittenExpanded,
                            token,
                            out byte[] finalized))
                    {
                        return finalized;
                    }
                }
            }
        }

        throw new InvalidDataException(OperationError.PersonalizationSpace);
    }

    private static bool TryFinalizeCandidateForOriginalSlot(
        ReadOnlySpan<byte> candidate,
        int originalAlignedSize,
        ReadOnlySpan<byte> expectedExpanded,
        CancellationToken token,
        out byte[] finalized)
    {
        finalized = [];
        int candidateAlignedSize = Align8(candidate.Length);
        if (candidateAlignedSize > originalAlignedSize)
        {
            return false;
        }

        byte[] normalized;
        if (candidateAlignedSize == originalAlignedSize)
        {
            normalized = candidate.ToArray();
        }
        else if (!TryPadFfsToOriginalSlot(candidate, originalAlignedSize, out normalized))
        {
            return false;
        }

        if (Align8(normalized.Length) != originalAlignedSize ||
            !TryDecodeExpandedSectionStream(
                normalized,
                token,
                out byte[] decoded,
                out _,
                out _,
                out _) ||
            !decoded.AsSpan().SequenceEqual(expectedExpanded))
        {
            return false;
        }

        finalized = normalized;
        return true;
    }

    private static bool TryPadFfsToOriginalSlot(
        ReadOnlySpan<byte> candidate,
        int originalAlignedSize,
        out byte[] padded)
    {
        padded = [];
        if (originalAlignedSize <= 0 ||
            originalAlignedSize > AmiSecureBootSpecification.MaximumNormalFfsFileBytes ||
            candidate.Length <= 0 ||
            Align8(candidate.Length) >= originalAlignedSize ||
            candidate.Length > originalAlignedSize - AmiSecureBootSpecification.SectionHeaderBytes)
        {
            return false;
        }

        // Sections following another section begin on a 4-byte boundary. Use an ordinary RAW section
        // to consume the target FFS's former alignment slack rather than placing undecodable junk after
        // an LZMA stream or changing the next FFS offset. A tiny private marker lets a later mutation
        // recognize and replace only padding that this editor created.
        int paddingSectionOffset = Align4(candidate.Length);
        int paddingSectionSize = originalAlignedSize - paddingSectionOffset;
        if (paddingSectionSize < AmiSecureBootSpecification.SectionHeaderBytes + PersonalizationPaddingMagic.Length ||
            paddingSectionSize > AmiSecureBootSpecification.MaximumNormalU24Size)
        {
            return false;
        }

        byte[] result = new byte[originalAlignedSize];
        candidate.CopyTo(result);
        WriteU24(result, paddingSectionOffset, paddingSectionSize);
        result[paddingSectionOffset + AmiSecureBootSpecification.SectionTypeOffset] =
            AmiSecureBootSpecification.RawSectionType;
        PersonalizationPaddingMagic.AsSpan().CopyTo(
            result.AsSpan(paddingSectionOffset + AmiSecureBootSpecification.SectionHeaderBytes));

        if (!TryReadFfsHeaderSize(result, out int headerSize) ||
            headerSize != AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            return false;
        }
        WriteU24(result, AmiSecureBootSpecification.FfsSizeOffset, result.Length);
        if (!UefiFfsChecksum.TryRecalculate(result, headerSize))
        {
            return false;
        }

        padded = result;
        return true;
    }

    private static byte[] BuildRewrittenFfs(
        ReadOnlySpan<byte> ffs,
        int guidedSectionOffset,
        int guidedSectionSize,
        int guidedDataOffset,
        ReadOnlySpan<byte> rewrittenExpanded,
        int numFastBytes,
        CancellationToken token)
    {
        byte[] packed = EncodeLzma(rewrittenExpanded, numFastBytes, token);
        int newGuidedSize = checked(guidedDataOffset + packed.Length);
        if (newGuidedSize > AmiSecureBootSpecification.MaximumNormalU24Size)
        {
            throw new InvalidDataException(OperationError.PersonalizationSpace);
        }

        int beforeLength = guidedSectionOffset;
        int oldGuidedEnd = checked(guidedSectionOffset + guidedSectionSize);
        bool hasPersonalizationPadding = TryGetPersonalizationPaddingSection(ffs, oldGuidedEnd, out _);
        bool guidedIsFinalSection = oldGuidedEnd == ffs.Length || hasPersonalizationPadding;
        int oldSuffixStart = guidedIsFinalSection ? oldGuidedEnd : Align4(oldGuidedEnd);
        if (oldSuffixStart > ffs.Length)
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }
        ReadOnlySpan<byte> suffix = hasPersonalizationPadding
            ? ReadOnlySpan<byte>.Empty
            : ffs[oldSuffixStart..];
        int newGuidedAlignedEnd = guidedIsFinalSection
            ? guidedSectionOffset + newGuidedSize
            : Align4(guidedSectionOffset + newGuidedSize);
        int newFileSize = checked(newGuidedAlignedEnd + suffix.Length);
        if (newFileSize > AmiSecureBootSpecification.MaximumNormalFfsFileBytes)
        {
            throw new InvalidDataException(OperationError.PersonalizationSpace);
        }

        byte[] result = new byte[newFileSize];
        ffs[..beforeLength].CopyTo(result);
        ffs.Slice(guidedSectionOffset, guidedDataOffset).CopyTo(result.AsSpan(guidedSectionOffset));
        WriteU24(result, guidedSectionOffset, newGuidedSize);
        packed.AsSpan().CopyTo(result.AsSpan(guidedSectionOffset + guidedDataOffset));
        if (suffix.Length != 0)
        {
            suffix.CopyTo(result.AsSpan(newGuidedAlignedEnd));
        }

        if (!TryReadFfsHeaderSize(result, out int headerSize))
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }
        if (headerSize != AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            // The current supported AMI logo/BDS modules use ordinary FFS headers. Avoid silently
            // changing FFS_FILE_HEADER2 semantics until a real image requires it.
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }
        WriteU24(result, AmiSecureBootSpecification.FfsSizeOffset, result.Length);
        if (!UefiFfsChecksum.TryRecalculate(result, headerSize))
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }
        return result;
    }

    private static bool TryGetPersonalizationPaddingSection(
        ReadOnlySpan<byte> ffs,
        int previousSectionEnd,
        out SectionInfo paddingSection)
    {
        paddingSection = default;
        if (previousSectionEnd < 0 || previousSectionEnd > ffs.Length)
        {
            return false;
        }

        int paddingOffset = Align4(previousSectionEnd);
        if (paddingOffset > ffs.Length - AmiSecureBootSpecification.SectionHeaderBytes - PersonalizationPaddingMagic.Length ||
            !IsAllZero(ffs[previousSectionEnd..paddingOffset]) ||
            !TryReadSection(ffs, paddingOffset, ffs.Length, out SectionInfo section) ||
            section.Type != AmiSecureBootSpecification.RawSectionType ||
            section.Offset + section.Size != ffs.Length ||
            section.Size < AmiSecureBootSpecification.SectionHeaderBytes + PersonalizationPaddingMagic.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> payload = ffs.Slice(
            section.Offset + AmiSecureBootSpecification.SectionHeaderBytes,
            section.Size - AmiSecureBootSpecification.SectionHeaderBytes);
        if (!payload[..PersonalizationPaddingMagic.Length].SequenceEqual(PersonalizationPaddingMagic) ||
            !IsAllZero(payload[PersonalizationPaddingMagic.Length..]))
        {
            return false;
        }

        paddingSection = section;
        return true;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        foreach (byte value in data)
        {
            if (value != 0)
            {
                return false;
            }
        }
        return true;
    }

    internal static bool TryReadSections(ReadOnlySpan<byte> stream, out IReadOnlyList<SectionInfo> sections)
    {
        var result = new List<SectionInfo>();
        int cursor = 0;
        while (cursor <= stream.Length - AmiSecureBootSpecification.SectionHeaderBytes)
        {
            if (!TryReadSection(stream, cursor, stream.Length, out SectionInfo section))
            {
                sections = [];
                return false;
            }
            result.Add(section);
            int sectionEnd = checked(section.Offset + section.Size);
            if (sectionEnd == stream.Length)
            {
                // PI sections are aligned relative to the next section. The final section does not
                // require trailing alignment bytes when its declared size ends exactly at the stream.
                // AMI logo/BDS LZMA payloads use this layout, including final sections whose size is
                // not divisible by four.
                cursor = stream.Length;
                break;
            }

            int next = section.AlignedEnd;
            if (next > stream.Length)
            {
                sections = [];
                return false;
            }
            if (next <= cursor)
            {
                sections = [];
                return false;
            }
            cursor = next;
        }
        sections = result;
        return result.Count != 0 && cursor == stream.Length;
    }

    internal static byte[] ReplaceSection(
        ReadOnlySpan<byte> stream,
        SectionInfo target,
        ReadOnlySpan<byte> replacementSection)
    {
        if (!TryReadSections(stream, out IReadOnlyList<SectionInfo> sections) ||
            sections.Count(section => section.Offset == target.Offset && section.Size == target.Size) != 1)
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }

        using var output = new MemoryStream(checked(stream.Length - target.Size + replacementSection.Length + 16));
        for (int index = 0; index < sections.Count; index++)
        {
            SectionInfo section = sections[index];
            ReadOnlySpan<byte> bytes = section.Offset == target.Offset && section.Size == target.Size
                ? replacementSection
                : stream.Slice(section.Offset, section.Size);
            output.Write(bytes);
            if (index + 1 < sections.Count)
            {
                while ((output.Length & 3) != 0)
                {
                    output.WriteByte(0);
                }
            }
        }
        return output.ToArray();
    }

    internal static byte[] BuildNormalSection(byte type, ReadOnlySpan<byte> payload)
    {
        int size = checked(AmiSecureBootSpecification.SectionHeaderBytes + payload.Length);
        if (size > AmiSecureBootSpecification.MaximumNormalU24Size)
        {
            throw new InvalidDataException(OperationError.PersonalizationSpace);
        }
        byte[] section = new byte[size];
        WriteU24(section, 0, size);
        section[AmiSecureBootSpecification.SectionTypeOffset] = type;
        payload.CopyTo(section.AsSpan(AmiSecureBootSpecification.SectionHeaderBytes));
        return section;
    }

    private static bool TryDecodeLzma(ReadOnlySpan<byte> packed, CancellationToken token, out byte[] expanded)
    {
        expanded = [];
        if (packed.Length < AmiSecureBootSpecification.LzmaHeaderBytes ||
            packed[0] > AmiSecureBootSpecification.MaximumValidLzmaPropertiesByte)
        {
            return false;
        }
        long outputLength = BinaryPrimitives.ReadInt64LittleEndian(
            packed[AmiSecureBootSpecification.LzmaUncompressedSizeOffset..]);
        uint dictionarySize = BinaryPrimitives.ReadUInt32LittleEndian(
            packed[AmiSecureBootSpecification.LzmaDictionarySizeOffset..]);
        if (outputLength < AmiSecureBootSpecification.SectionHeaderBytes ||
            outputLength > UefiDriverInspectionPolicy.MaximumExpandedSectionBytes ||
            dictionarySize > UefiDriverInspectionPolicy.MaximumExpandedSectionBytes)
        {
            return false;
        }

        try
        {
            using var input = new MemoryStream(packed[AmiSecureBootSpecification.LzmaHeaderBytes..].ToArray(), writable: false);
            using var decoder = LzmaStream.Create(
                packed[..AmiSecureBootSpecification.LzmaPropertiesBytes].ToArray(),
                input,
                input.Length,
                outputLength);
            expanded = new byte[checked((int)outputLength)];
            int written = 0;
            while (written < expanded.Length)
            {
                token.ThrowIfCancellationRequested();
                int count = decoder.Read(expanded, written,
                    Math.Min(UefiDriverInspectionPolicy.DecoderReadBufferBytes, expanded.Length - written));
                if (count == 0)
                {
                    expanded = [];
                    return false;
                }
                written += count;
            }
            return true;
        }
        catch (Exception error) when (FirmwareCompressionFailure.IsMalformedInput(error))
        {
            expanded = [];
            return false;
        }
    }

    private static byte[] EncodeLzma(
        ReadOnlySpan<byte> expanded,
        int numFastBytes,
        CancellationToken token)
    {
        using var compressed = new MemoryStream();
        byte[] properties;
        using (var encoder = LzmaStream.Create(
                   new LzmaEncoderProperties(false, SecureBootRepairPolicy.LzmaDictionaryBytes, numFastBytes),
                   false,
                   compressed))
        {
            properties = encoder.Properties.ToArray();
            encoder.Write(expanded);
        }
        token.ThrowIfCancellationRequested();

        byte[] compressedBytes = compressed.ToArray();
        byte[] packed = new byte[checked(AmiSecureBootSpecification.LzmaHeaderBytes + compressedBytes.Length)];
        properties.CopyTo(packed, 0);
        BinaryPrimitives.WriteInt64LittleEndian(
            packed.AsSpan(AmiSecureBootSpecification.LzmaUncompressedSizeOffset),
            expanded.Length);
        compressedBytes.CopyTo(packed, AmiSecureBootSpecification.LzmaHeaderBytes);
        return packed;
    }

    private static bool TryReadFfsHeaderSize(ReadOnlySpan<byte> ffs, out int headerSize)
    {
        headerSize = 0;
        if (ffs.Length < AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            return false;
        }
        byte attributes = ffs[AmiSecureBootSpecification.FfsAttributesOffset];
        bool large = (attributes & AmiSecureBootSpecification.FfsLargeFileAttribute) != 0;
        headerSize = large
            ? AmiSecureBootSpecification.FfsExtendedFileHeaderBytes
            : AmiSecureBootSpecification.FfsFileHeaderBytes;
        return ffs.Length >= headerSize;
    }

    private static bool TryReadSection(
        ReadOnlySpan<byte> stream,
        int offset,
        int limit,
        out SectionInfo section)
    {
        section = default;
        if (offset < 0 || limit < offset || limit > stream.Length ||
            limit - offset < AmiSecureBootSpecification.SectionHeaderBytes)
        {
            return false;
        }

        int encoded = ReadU24(stream, offset);
        int headerSize = AmiSecureBootSpecification.SectionHeaderBytes;
        long size = encoded;
        if (encoded == AmiSecureBootSpecification.U24ExtendedSizeMarker)
        {
            if (limit - offset < UefiPiCode.ExtendedSectionHeaderBytes)
            {
                return false;
            }
            size = BinaryPrimitives.ReadUInt32LittleEndian(stream[(offset + UefiPiCode.ExtendedSectionSizeOffset)..]);
            headerSize = UefiPiCode.ExtendedSectionHeaderBytes;
        }
        if (size < headerSize || size > int.MaxValue || size > limit - offset)
        {
            return false;
        }

        int sectionSize = checked((int)size);
        int alignedEnd = Align4(offset + sectionSize);
        if (alignedEnd > limit && offset + sectionSize != limit)
        {
            return false;
        }
        section = new(offset, sectionSize, headerSize, stream[offset + AmiSecureBootSpecification.SectionTypeOffset], alignedEnd);
        return true;
    }

    private static int Align4(int value) => checked((value + 3) & ~3);

    private static int Align8(int value) => checked((value + 7) & ~7);

    private static int ReadU24(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;

    private static void WriteU24(Span<byte> data, int offset, int value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
        data[offset + 2] = (byte)(value >> 16);
    }
}
