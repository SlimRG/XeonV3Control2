using System.Buffers.Binary;
using System.Security.Cryptography;

namespace XeonV3Control.Core;

/// <summary>
/// Performs a narrowly-scoped removal of a validated Intel CPU microcode patch from a supported
/// active RAW FFS container. The FFS file and firmware volume keep their original size and offsets;
/// remaining patches are compacted inside the payload, released bytes are restored to the FV erase
/// value, and the Intel FIT is canonically repacked so all remaining used entries stay contiguous.
/// </summary>
public static class CpuPatchImageUpdater
{
    private const byte FfsRaw = 0x01;

    private readonly record struct PatchIdentity(
        long Offset,
        int Size,
        string Sha256,
        uint ProcessorSignature,
        uint ProcessorFlags,
        uint UpdateRevision,
        long VolumeOffset,
        Guid FileGuid,
        long FileOffset);

    private sealed record PreparedRemoval(
        UefiFfsVolumeLayout VolumeLayout,
        FfsFileHeaderInfo FileHeader,
        int FileOffset,
        int FileEnd,
        int PayloadStart,
        int? MpdtFooterStart,
        int TargetIndex,
        IReadOnlyList<IntelMicrocodeInfo> Microcodes,
        FitTable Fit);

    private sealed record FitTable(
        int Offset,
        int EntryCount,
        ulong ImageBaseAddress,
        bool HeaderChecksumValid,
        IReadOnlyList<int> MicrocodeEntryIndices);

    private sealed record FitRewriteResult(
        IReadOnlyList<int> MicrocodeEntryIndices,
        int UsedEntryCount);

    public static CpuPatchRemovalPlan PlanRemoval(
        ReadOnlySpan<byte> source,
        string sourceSha256,
        IntelMicrocodeInfo patch,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceSha256);
        ArgumentNullException.ThrowIfNull(patch);
        token.ThrowIfCancellationRequested();

        if (!TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(patch))
        {
            return new(
                CpuPatchRemovalPlanStatus.UnsupportedLayout,
                sourceSha256,
                patch.Sha256,
                patch.Offset,
                patch.Size,
                patch.ProcessorSignature,
                patch.ProcessorFlags,
                patch.UpdateRevision,
                patch.VolumeOffset,
                patch.FileGuid,
                patch.FileOffset,
                0,
                0,
                0,
                -1,
                0,
                CpuPatchRemovalReason.NotTurboBoostTarget);
        }

        var identity = new PatchIdentity(
            patch.Offset,
            patch.Size,
            patch.Sha256,
            patch.ProcessorSignature,
            patch.ProcessorFlags,
            patch.UpdateRevision,
            patch.VolumeOffset,
            patch.FileGuid,
            patch.FileOffset);

        CpuPatchRemovalReason reason;
        PreparedRemoval? prepared;
        try
        {
            prepared = TryPrepare(source, identity, token, out reason);
        }
        catch (Exception error) when (error is ArgumentOutOfRangeException or OverflowException)
        {
            prepared = null;
            reason = CpuPatchRemovalReason.InvalidFfs;
        }

        int relativePatchOffset = patch.Offset >= patch.FileOffset &&
            patch.Offset - patch.FileOffset <= int.MaxValue
                ? (int)(patch.Offset - patch.FileOffset)
                : 0;

        if (prepared is null)
        {
            return new(
                CpuPatchRemovalPlanStatus.UnsupportedLayout,
                sourceSha256,
                patch.Sha256,
                patch.Offset,
                patch.Size,
                patch.ProcessorSignature,
                patch.ProcessorFlags,
                patch.UpdateRevision,
                patch.VolumeOffset,
                patch.FileGuid,
                patch.FileOffset,
                relativePatchOffset,
                0,
                0,
                -1,
                0,
                reason);
        }

        return new(
            CpuPatchRemovalPlanStatus.Ready,
            sourceSha256,
            patch.Sha256,
            patch.Offset,
            patch.Size,
            patch.ProcessorSignature,
            patch.ProcessorFlags,
            patch.UpdateRevision,
            patch.VolumeOffset,
            patch.FileGuid,
            patch.FileOffset,
            checked((int)(patch.Offset - patch.FileOffset)),
            prepared.FileHeader.Size,
            prepared.Microcodes.Count,
            prepared.Fit.Offset,
            prepared.Fit.MicrocodeEntryIndices.Count,
            CpuPatchRemovalReason.Ready);
    }

    /// <summary>Returns a modified copy. The input span is never mutated.</summary>
    public static byte[] Remove(
        ReadOnlySpan<byte> source,
        CpuPatchRemovalPlan plan,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        token.ThrowIfCancellationRequested();
        if (!plan.CanApply)
        {
            throw new InvalidDataException(OperationError.CpuPatchRemovalUnsupported);
        }

        FirmwareMutationFileIo.VerifySha256(source, plan.SourceImageSha256, OperationError.CpuPatchSourceChanged);
        return RemoveVerifiedSource(source, plan, token);
    }

    private static byte[] RemoveVerifiedSource(
        ReadOnlySpan<byte> source,
        CpuPatchRemovalPlan plan,
        CancellationToken token)
    {
        var identity = new PatchIdentity(
            plan.PatchOffset,
            plan.PatchSize,
            plan.PatchSha256,
            plan.ProcessorSignature,
            plan.ProcessorFlags,
            plan.UpdateRevision,
            plan.VolumeOffset,
            plan.FileGuid,
            plan.FileOffset);
        PreparedRemoval prepared = TryPrepare(source, identity, token, out _)
            ?? throw new InvalidDataException(OperationError.CpuPatchRemovalUnsupported);

        if (prepared.FileHeader.Size != plan.FileSize ||
            prepared.Microcodes.Count != plan.MicrocodeCount ||
            prepared.Fit.Offset != plan.FitOffset ||
            prepared.Fit.MicrocodeEntryIndices.Count != plan.FitMicrocodeEntryCount)
        {
            throw new InvalidDataException(OperationError.CpuPatchSourceChanged);
        }

        byte[] output = source.ToArray();
        var remaining = new List<(IntelMicrocodeInfo Source, int NewOffset)>(prepared.Microcodes.Count - 1);
        int destination = prepared.PayloadStart;
        for (int index = 0; index < prepared.Microcodes.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            if (index == prepared.TargetIndex)
            {
                continue;
            }

            IntelMicrocodeInfo microcode = prepared.Microcodes[index];
            source.Slice(checked((int)microcode.Offset), microcode.Size)
                .CopyTo(output.AsSpan(destination, microcode.Size));
            remaining.Add((microcode, destination));
            destination = checked(destination + microcode.Size);
        }

        int preservedTailStart = prepared.MpdtFooterStart ?? prepared.FileEnd;
        if (destination > preservedTailStart)
        {
            throw new InvalidDataException(OperationError.CpuPatchRemovalUnsupported);
        }
        output.AsSpan(destination, preservedTailStart - destination).Fill(prepared.VolumeLayout.EraseByte);

        if (!UefiFfsChecksum.TryRecalculate(
                output.AsSpan(prepared.FileOffset, prepared.FileHeader.Size),
                prepared.FileHeader.HeaderSize))
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }
        FitRewriteResult fitRewrite = UpdateFit(
            output,
            prepared.Fit,
            prepared.Microcodes,
            remaining,
            prepared.TargetIndex,
            token);
        ValidateResult(source, output, prepared, remaining, fitRewrite, token);
        return output;
    }

    /// <summary>
    /// Reads the exact analyzed file, verifies its SHA-256, creates a new verified image, and never
    /// overwrites either the source or an existing destination.
    /// </summary>
    public static async Task<BiosImage> RemoveFileAsync(
        string sourcePath,
        string destinationPath,
        CpuPatchRemovalPlan plan,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(plan);

        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourcePath, token);
        FirmwareMutationFileIo.VerifySha256(source, plan.SourceImageSha256, OperationError.CpuPatchSourceChanged);
        byte[] updated = RemoveVerifiedSource(source, plan, token);
        string expectedOutputSha256 = Convert.ToHexString(SHA256.HashData(updated));

        string destination = Path.GetFullPath(destinationPath);
        bool committed = false;
        try
        {
            await FirmwareMutationFileIo.WriteNewVerifiedImageAsync(destination, updated, token);
            committed = true;
            BiosImage result = await BiosImageLoader.LoadValidatedAsync(destination, token);
            if (result.Size != updated.LongLength ||
                !string.Equals(result.Sha256, expectedOutputSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
            return result;
        }
        catch
        {
            if (committed)
            {
                _ = FileSystemCleanup.TryDeleteFile(destination, out _);
            }
            throw;
        }
    }

    private static PreparedRemoval? TryPrepare(
        ReadOnlySpan<byte> source,
        PatchIdentity target,
        CancellationToken token,
        out CpuPatchRemovalReason reason)
    {
        reason = CpuPatchRemovalReason.InvalidFfs;
        token.ThrowIfCancellationRequested();
        if (target.ProcessorSignature != TurboBoostUnlockReport.XeonE5V3ProcessorSignature ||
            target.ProcessorFlags != TurboBoostUnlockReport.XeonE5V3ProcessorFlags)
        {
            reason = CpuPatchRemovalReason.NotTurboBoostTarget;
            return null;
        }
        if (target.VolumeOffset < 0 || target.VolumeOffset > int.MaxValue)
        {
            reason = CpuPatchRemovalReason.InvalidFirmwareVolume;
            return null;
        }
        if (target.FileOffset < 0 || target.FileOffset > int.MaxValue ||
            target.Offset < 0 || target.Offset > int.MaxValue)
        {
            return null;
        }

        int volumeStart = checked((int)target.VolumeOffset);
        if (volumeStart > source.Length - UefiFirmwareSpecification.FirmwareVolumeMinimumHeaderBytes)
        {
            reason = CpuPatchRemovalReason.InvalidFirmwareVolume;
            return null;
        }

        ulong volumeLength64 = BinaryPrimitives.ReadUInt64LittleEndian(
            source[(volumeStart + UefiFirmwareSpecification.FirmwareVolumeLengthOffset)..]);
        if (volumeLength64 > int.MaxValue ||
            volumeLength64 < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes ||
            volumeStart > source.Length - (int)volumeLength64)
        {
            reason = CpuPatchRemovalReason.InvalidFirmwareVolume;
            return null;
        }

        Guid fileSystem = new(source.Slice(
            volumeStart + UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset,
            16));
        if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(fileSystem) ||
            !HasValidFirmwareVolumeHeader(source, volumeStart, checked((int)volumeLength64)))
        {
            reason = CpuPatchRemovalReason.InvalidFirmwareVolume;
            return null;
        }

        var volume = new FirmwareVolume(volumeStart, (int)volumeLength64, fileSystem, true);
        if (!UefiFfsVolumeScanner.TryGetLayout(source, volume, out UefiFfsVolumeLayout layout))
        {
            return null;
        }

        int fileOffset = checked((int)target.FileOffset);
        if (!UefiFfsFileParser.TryRead(source, fileOffset, layout.End, layout.EraseByte, out FfsFileHeaderInfo header))
        {
            return null;
        }
        if (header.State != FfsFileState.DataValid || header.Type != FfsRaw || header.Guid != target.FileGuid)
        {
            reason = CpuPatchRemovalReason.NotActiveRawFfs;
            return null;
        }

        int fileEnd = checked(fileOffset + header.Size);
        int payloadStart = checked(fileOffset + header.HeaderSize);
        var microcodes = new List<IntelMicrocodeInfo>();
        int cursor = payloadStart;
        while (cursor <= fileEnd - IntelMicrocodeContainerSpecification.HeaderBytes)
        {
            token.ThrowIfCancellationRequested();
            if (!TurboBoostUnlockInspector.TryReadMicrocode(
                    source,
                    cursor,
                    fileEnd,
                    out IntelMicrocodeInfo? microcode) || microcode is null)
            {
                break;
            }

            IntelMicrocodeInfo normalized = microcode with
            {
                VolumeOffset = target.VolumeOffset,
                FileGuid = target.FileGuid,
                FileOffset = target.FileOffset,
                FfsType = FfsRaw
            };
            microcodes.Add(normalized);
            cursor = checked(cursor + normalized.Size);
        }

        if (microcodes.Count < 2)
        {
            reason = CpuPatchRemovalReason.UnsupportedMicrocodeLayout;
            return null;
        }

        int targetIndex = microcodes.FindIndex(item =>
            item.Offset == target.Offset &&
            item.Size == target.Size &&
            item.ProcessorSignature == target.ProcessorSignature &&
            item.ProcessorFlags == target.ProcessorFlags &&
            item.UpdateRevision == target.UpdateRevision &&
            string.Equals(item.Sha256, target.Sha256, StringComparison.OrdinalIgnoreCase));
        if (targetIndex < 0)
        {
            reason = CpuPatchRemovalReason.PatchIdentityMismatch;
            return null;
        }

        int? footerStart = null;
        if (!TryValidateContainerTail(source, cursor, fileEnd, layout.EraseByte, out footerStart))
        {
            reason = CpuPatchRemovalReason.UnsupportedContainerTail;
            return null;
        }

        if (!TryReadFit(source, microcodes, out FitTable? fit) || fit is null)
        {
            reason = CpuPatchRemovalReason.FitUnavailableOrMismatch;
            return null;
        }
        reason = CpuPatchRemovalReason.Ready;
        return new(
            layout,
            header,
            fileOffset,
            fileEnd,
            payloadStart,
            footerStart,
            targetIndex,
            microcodes,
            fit);
    }

    private static bool HasValidFirmwareVolumeHeader(ReadOnlySpan<byte> source, int start, int length)
    {
        if (length < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes ||
            start < 0 || start > source.Length - length ||
            start > source.Length - UefiFirmwareSpecification.FirmwareVolumeMinimumHeaderBytes ||
            !source.Slice(
                    start + UefiFirmwareSpecification.FirmwareVolumeSignatureOffset,
                    UefiFirmwareSpecification.FirmwareVolumeSignature.Length)
                .SequenceEqual(UefiFirmwareSpecification.FirmwareVolumeSignature) ||
            source.Slice(start, UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset).IndexOfAnyExcept((byte)0) >= 0 ||
            source[start + UefiFirmwareSpecification.FirmwareVolumeReservedOffset] != 0 ||
            source[start + UefiFirmwareSpecification.FirmwareVolumeRevisionOffset] != UefiFirmwareSpecification.FirmwareVolumeRevision2)
        {
            return false;
        }

        int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
            source[(start + UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset)..]);
        if (headerLength < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes ||
            headerLength > length || (headerLength & 1) != 0)
        {
            return false;
        }

        uint sum = 0;
        ReadOnlySpan<byte> header = source.Slice(start, headerLength);
        for (int offset = 0; offset < header.Length; offset += sizeof(ushort))
        {
            sum += BinaryPrimitives.ReadUInt16LittleEndian(header[offset..]);
        }
        return (sum & ushort.MaxValue) == 0;
    }

    private static bool TryValidateContainerTail(
        ReadOnlySpan<byte> source,
        int tailStart,
        int fileEnd,
        byte eraseByte,
        out int? footerStart)
    {
        footerStart = null;
        if (tailStart > fileEnd)
        {
            return false;
        }
        if (tailStart == fileEnd)
        {
            return true;
        }

        ReadOnlySpan<byte> tail = source[tailStart..fileEnd];
        if (tail.IndexOfAnyExcept(eraseByte) < 0)
        {
            return true;
        }
        if (tail.Length < IntelMicrocodeContainerSpecification.MpdtFooterBytes)
        {
            return false;
        }

        int candidate = fileEnd - IntelMicrocodeContainerSpecification.MpdtFooterBytes;
        ReadOnlySpan<byte> footer = source[candidate..fileEnd];
        if (!footer[..IntelMicrocodeContainerSpecification.MpdtSignature.Length]
                .SequenceEqual(IntelMicrocodeContainerSpecification.MpdtSignature) ||
            source[tailStart..candidate].IndexOfAnyExcept(eraseByte) >= 0)
        {
            return false;
        }

        footerStart = candidate;
        return true;
    }

    private static bool TryReadFit(
        ReadOnlySpan<byte> source,
        IReadOnlyList<IntelMicrocodeInfo> microcodes,
        out FitTable? fit)
    {
        fit = null;
        if (source.Length < IntelFirmwareInterfaceTableSpecification.PointerOffsetFromTop)
        {
            return false;
        }

        int pointerOffset = source.Length - IntelFirmwareInterfaceTableSpecification.PointerOffsetFromTop;
        ulong address = BinaryPrimitives.ReadUInt64LittleEndian(source[pointerOffset..]);
        ulong imageBase = IntelFirmwareInterfaceTableSpecification.FourGib - (ulong)source.Length;
        if (address < imageBase || address >= IntelFirmwareInterfaceTableSpecification.FourGib ||
            (address & 0x0F) != 0)
        {
            return false;
        }

        ulong fitOffset64 = address - imageBase;
        if (fitOffset64 > int.MaxValue)
        {
            return false;
        }
        int fitOffset = (int)fitOffset64;
        if (fitOffset > source.Length - IntelFirmwareInterfaceTableSpecification.EntryBytes)
        {
            return false;
        }

        ReadOnlySpan<byte> header = source.Slice(fitOffset, IntelFirmwareInterfaceTableSpecification.EntryBytes);
        if (!header[..IntelFirmwareInterfaceTableSpecification.HeaderSignature.Length]
                .SequenceEqual(IntelFirmwareInterfaceTableSpecification.HeaderSignature) ||
            header[IntelFirmwareInterfaceTableSpecification.ReservedOffset] != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(header[IntelFirmwareInterfaceTableSpecification.VersionOffset..]) !=
                IntelFirmwareInterfaceTableSpecification.Version100 ||
            (header[IntelFirmwareInterfaceTableSpecification.TypeOffset] & IntelFirmwareInterfaceTableSpecification.TypeMask) !=
                IntelFirmwareInterfaceTableSpecification.HeaderType)
        {
            return false;
        }

        int entryCount = ReadU24(header, IntelFirmwareInterfaceTableSpecification.SizeOffset);
        if (entryCount <= 0 || entryCount > IntelFirmwareInterfaceTableSpecification.MaximumEntries ||
            fitOffset > source.Length - checked(entryCount * IntelFirmwareInterfaceTableSpecification.EntryBytes))
        {
            return false;
        }

        bool headerChecksumValid =
            (header[IntelFirmwareInterfaceTableSpecification.TypeOffset] &
             IntelFirmwareInterfaceTableSpecification.ChecksumValidMask) != 0;
        ReadOnlySpan<byte> table = source.Slice(
            fitOffset,
            checked(entryCount * IntelFirmwareInterfaceTableSpecification.EntryBytes));
        if (headerChecksumValid && Sum8(table) != 0)
        {
            return false;
        }

        var entryByOffset = new Dictionary<int, int>();
        for (int index = 1; index < entryCount; index++)
        {
            ReadOnlySpan<byte> entry = table.Slice(
                index * IntelFirmwareInterfaceTableSpecification.EntryBytes,
                IntelFirmwareInterfaceTableSpecification.EntryBytes);
            byte type = (byte)(entry[IntelFirmwareInterfaceTableSpecification.TypeOffset] &
                IntelFirmwareInterfaceTableSpecification.TypeMask);
            if (type == IntelFirmwareInterfaceTableSpecification.UnusedType)
            {
                if (entry.IndexOfAnyExcept(byte.MaxValue) >= 0)
                {
                    return false;
                }
                continue;
            }
            if (type != IntelFirmwareInterfaceTableSpecification.MicrocodeType)
            {
                continue;
            }
            if (entry[IntelFirmwareInterfaceTableSpecification.ReservedOffset] != 0 ||
                ReadU24(entry, IntelFirmwareInterfaceTableSpecification.SizeOffset) != 0 ||
                BinaryPrimitives.ReadUInt16LittleEndian(entry[IntelFirmwareInterfaceTableSpecification.VersionOffset..]) !=
                    IntelFirmwareInterfaceTableSpecification.Version100 ||
                (entry[IntelFirmwareInterfaceTableSpecification.TypeOffset] &
                 IntelFirmwareInterfaceTableSpecification.ChecksumValidMask) != 0)
            {
                return false;
            }

            ulong componentAddress = BinaryPrimitives.ReadUInt64LittleEndian(entry);
            if (componentAddress < imageBase || componentAddress >= IntelFirmwareInterfaceTableSpecification.FourGib ||
                (componentAddress & 0x0F) != 0)
            {
                continue;
            }
            ulong componentOffset64 = componentAddress - imageBase;
            if (componentOffset64 > int.MaxValue)
            {
                continue;
            }
            int componentOffset = (int)componentOffset64;
            if (microcodes.Any(item => item.Offset == componentOffset))
            {
                if (!entryByOffset.TryAdd(componentOffset, index))
                {
                    return false;
                }
            }
        }

        var indices = new List<int>(microcodes.Count);
        foreach (IntelMicrocodeInfo microcode in microcodes)
        {
            if (!entryByOffset.TryGetValue(checked((int)microcode.Offset), out int index))
            {
                return false;
            }
            indices.Add(index);
        }

        fit = new(fitOffset, entryCount, imageBase, headerChecksumValid, indices);
        return true;
    }

    private static FitRewriteResult UpdateFit(
        byte[] output,
        FitTable fit,
        IReadOnlyList<IntelMicrocodeInfo> originalMicrocodes,
        IReadOnlyList<(IntelMicrocodeInfo Source, int NewOffset)> remaining,
        int targetIndex,
        CancellationToken token)
    {
        if (originalMicrocodes.Count != fit.MicrocodeEntryIndices.Count ||
            targetIndex < 0 || targetIndex >= originalMicrocodes.Count)
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        Span<byte> table = output.AsSpan(
            fit.Offset,
            checked(fit.EntryCount * IntelFirmwareInterfaceTableSpecification.EntryBytes));
        var microcodeOrdinalByEntry = new Dictionary<int, int>(fit.MicrocodeEntryIndices.Count);
        for (int ordinal = 0; ordinal < fit.MicrocodeEntryIndices.Count; ordinal++)
        {
            if (!microcodeOrdinalByEntry.TryAdd(fit.MicrocodeEntryIndices[ordinal], ordinal))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }

        var newOffsetByOriginal = new Dictionary<long, int>(remaining.Count);
        foreach ((IntelMicrocodeInfo source, int newOffset) in remaining)
        {
            if (!newOffsetByOriginal.TryAdd(source.Offset, newOffset))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }

        var packedEntries = new List<byte[]>(fit.EntryCount - 1);
        var rewrittenMicrocodeIndices = new List<int>(remaining.Count);
        for (int entryIndex = 1; entryIndex < fit.EntryCount; entryIndex++)
        {
            token.ThrowIfCancellationRequested();
            ReadOnlySpan<byte> sourceEntry = table.Slice(
                entryIndex * IntelFirmwareInterfaceTableSpecification.EntryBytes,
                IntelFirmwareInterfaceTableSpecification.EntryBytes);
            byte type = (byte)(sourceEntry[IntelFirmwareInterfaceTableSpecification.TypeOffset] &
                IntelFirmwareInterfaceTableSpecification.TypeMask);
            if (type == IntelFirmwareInterfaceTableSpecification.UnusedType)
            {
                if (sourceEntry.IndexOfAnyExcept(byte.MaxValue) >= 0)
                {
                    throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
                }
                continue;
            }

            byte[] entry = sourceEntry.ToArray();
            if (microcodeOrdinalByEntry.TryGetValue(entryIndex, out int ordinal))
            {
                if (ordinal == targetIndex)
                {
                    continue;
                }

                IntelMicrocodeInfo original = originalMicrocodes[ordinal];
                if (!newOffsetByOriginal.TryGetValue(original.Offset, out int newOffset))
                {
                    throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
                }

                ulong address = checked(fit.ImageBaseAddress + (ulong)newOffset);
                BinaryPrimitives.WriteUInt64LittleEndian(entry, address);
                rewrittenMicrocodeIndices.Add(packedEntries.Count + 1);
            }

            packedEntries.Add(entry);
        }

        if (packedEntries.Count > fit.EntryCount - 1 ||
            rewrittenMicrocodeIndices.Count != remaining.Count)
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        for (int entryIndex = 1; entryIndex < fit.EntryCount; entryIndex++)
        {
            token.ThrowIfCancellationRequested();
            Span<byte> destinationEntry = table.Slice(
                entryIndex * IntelFirmwareInterfaceTableSpecification.EntryBytes,
                IntelFirmwareInterfaceTableSpecification.EntryBytes);
            int packedIndex = entryIndex - 1;
            if (packedIndex < packedEntries.Count)
            {
                packedEntries[packedIndex].CopyTo(destinationEntry);
            }
            else
            {
                destinationEntry.Fill(byte.MaxValue);
            }
        }

        if (fit.HeaderChecksumValid)
        {
            table[IntelFirmwareInterfaceTableSpecification.ChecksumOffset] = 0;
            table[IntelFirmwareInterfaceTableSpecification.ChecksumOffset] = unchecked((byte)(0 - Sum8(table)));
        }

        return new(rewrittenMicrocodeIndices, packedEntries.Count);
    }

    private static void ValidateResult(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        PreparedRemoval prepared,
        IReadOnlyList<(IntelMicrocodeInfo Source, int NewOffset)> remaining,
        FitRewriteResult expectedFit,
        CancellationToken token)
    {
        if (source.Length != output.Length)
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        if (!UefiFfsFileParser.TryRead(
                output,
                prepared.FileOffset,
                prepared.VolumeLayout.End,
                prepared.VolumeLayout.EraseByte,
                out FfsFileHeaderInfo header) ||
            header.Guid != prepared.FileHeader.Guid ||
            header.Type != prepared.FileHeader.Type ||
            header.Size != prepared.FileHeader.Size ||
            header.State != FfsFileState.DataValid)
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        foreach ((IntelMicrocodeInfo original, int newOffset) in remaining)
        {
            token.ThrowIfCancellationRequested();
            if (!TurboBoostUnlockInspector.TryReadMicrocode(
                    output,
                    newOffset,
                    prepared.FileEnd,
                    out IntelMicrocodeInfo? parsed) ||
                parsed is null ||
                parsed.Size != original.Size ||
                parsed.ProcessorSignature != original.ProcessorSignature ||
                parsed.UpdateRevision != original.UpdateRevision ||
                !string.Equals(parsed.Sha256, original.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }

        if (!TryReadFit(
                output,
                remaining.Select(item => item.Source with { Offset = item.NewOffset }).ToArray(),
                out FitTable? fit) ||
            fit is null ||
            fit.Offset != prepared.Fit.Offset ||
            fit.MicrocodeEntryIndices.Count != remaining.Count ||
            !fit.MicrocodeEntryIndices.SequenceEqual(expectedFit.MicrocodeEntryIndices))
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        ValidateCanonicalFitRewrite(source, output, prepared, remaining, expectedFit, token);

        VerifyUnchangedOutsideRanges(
            source,
            output,
            prepared.FileOffset,
            prepared.FileHeader.Size,
            prepared.Fit.Offset,
            checked(prepared.Fit.EntryCount * IntelFirmwareInterfaceTableSpecification.EntryBytes));

    }

    private static void ValidateCanonicalFitRewrite(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        PreparedRemoval prepared,
        IReadOnlyList<(IntelMicrocodeInfo Source, int NewOffset)> remaining,
        FitRewriteResult expectedFit,
        CancellationToken token)
    {
        int tableBytes = checked(prepared.Fit.EntryCount * IntelFirmwareInterfaceTableSpecification.EntryBytes);
        ReadOnlySpan<byte> sourceTable = source.Slice(prepared.Fit.Offset, tableBytes);
        ReadOnlySpan<byte> outputTable = output.Slice(prepared.Fit.Offset, tableBytes);
        ReadOnlySpan<byte> sourceHeader = sourceTable[..IntelFirmwareInterfaceTableSpecification.EntryBytes];
        ReadOnlySpan<byte> outputHeader = outputTable[..IntelFirmwareInterfaceTableSpecification.EntryBytes];

        for (int offset = 0; offset < IntelFirmwareInterfaceTableSpecification.EntryBytes; offset++)
        {
            if (prepared.Fit.HeaderChecksumValid &&
                offset == IntelFirmwareInterfaceTableSpecification.ChecksumOffset)
            {
                continue;
            }
            if (sourceHeader[offset] != outputHeader[offset])
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }
        if (prepared.Fit.HeaderChecksumValid && Sum8(outputTable) != 0)
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        var ordinalBySourceEntry = new Dictionary<int, int>(prepared.Fit.MicrocodeEntryIndices.Count);
        for (int ordinal = 0; ordinal < prepared.Fit.MicrocodeEntryIndices.Count; ordinal++)
        {
            if (!ordinalBySourceEntry.TryAdd(prepared.Fit.MicrocodeEntryIndices[ordinal], ordinal))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }

        var newOffsetByOriginal = new Dictionary<long, int>(remaining.Count);
        foreach ((IntelMicrocodeInfo microcode, int newOffset) in remaining)
        {
            if (!newOffsetByOriginal.TryAdd(microcode.Offset, newOffset))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }

        int packedIndex = 1;
        var actualMicrocodeIndices = new List<int>(remaining.Count);
        for (int sourceIndex = 1; sourceIndex < prepared.Fit.EntryCount; sourceIndex++)
        {
            token.ThrowIfCancellationRequested();
            ReadOnlySpan<byte> sourceEntry = sourceTable.Slice(
                sourceIndex * IntelFirmwareInterfaceTableSpecification.EntryBytes,
                IntelFirmwareInterfaceTableSpecification.EntryBytes);
            byte sourceType = (byte)(sourceEntry[IntelFirmwareInterfaceTableSpecification.TypeOffset] &
                IntelFirmwareInterfaceTableSpecification.TypeMask);
            if (sourceType == IntelFirmwareInterfaceTableSpecification.UnusedType)
            {
                if (sourceEntry.IndexOfAnyExcept(byte.MaxValue) >= 0)
                {
                    throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
                }
                continue;
            }

            if (ordinalBySourceEntry.TryGetValue(sourceIndex, out int ordinal) &&
                ordinal == prepared.TargetIndex)
            {
                continue;
            }
            if (packedIndex >= prepared.Fit.EntryCount)
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }

            ReadOnlySpan<byte> outputEntry = outputTable.Slice(
                packedIndex * IntelFirmwareInterfaceTableSpecification.EntryBytes,
                IntelFirmwareInterfaceTableSpecification.EntryBytes);
            if (ordinalBySourceEntry.TryGetValue(sourceIndex, out ordinal))
            {
                IntelMicrocodeInfo original = prepared.Microcodes[ordinal];
                if (!newOffsetByOriginal.TryGetValue(original.Offset, out int newOffset))
                {
                    throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
                }

                ulong expectedAddress = checked(prepared.Fit.ImageBaseAddress + (ulong)newOffset);
                if (BinaryPrimitives.ReadUInt64LittleEndian(outputEntry) != expectedAddress ||
                    !sourceEntry[sizeof(ulong)..].SequenceEqual(outputEntry[sizeof(ulong)..]))
                {
                    throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
                }
                actualMicrocodeIndices.Add(packedIndex);
            }
            else if (!sourceEntry.SequenceEqual(outputEntry))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }

            packedIndex++;
        }

        int usedEntryCount = packedIndex - 1;
        if (usedEntryCount != expectedFit.UsedEntryCount ||
            !actualMicrocodeIndices.SequenceEqual(expectedFit.MicrocodeEntryIndices))
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }

        for (int entryIndex = packedIndex; entryIndex < prepared.Fit.EntryCount; entryIndex++)
        {
            ReadOnlySpan<byte> entry = outputTable.Slice(
                entryIndex * IntelFirmwareInterfaceTableSpecification.EntryBytes,
                IntelFirmwareInterfaceTableSpecification.EntryBytes);
            if (entry.IndexOfAnyExcept(byte.MaxValue) >= 0)
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
        }
    }

    private static void VerifyUnchangedOutsideRanges(
        ReadOnlySpan<byte> before,
        ReadOnlySpan<byte> after,
        int firstStart,
        int firstLength,
        int secondStart,
        int secondLength)
    {
        var ranges = new[]
        {
            (Start: firstStart, End: checked(firstStart + firstLength)),
            (Start: secondStart, End: checked(secondStart + secondLength))
        }.OrderBy(item => item.Start).ToArray();

        int cursor = 0;
        foreach ((int start, int end) in ranges)
        {
            if (start < cursor || end < start || end > before.Length)
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
            if (!before[cursor..start].SequenceEqual(after[cursor..start]))
            {
                throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
            }
            cursor = Math.Max(cursor, end);
        }
        if (!before[cursor..].SequenceEqual(after[cursor..]))
        {
            throw new InvalidDataException(OperationError.CpuPatchOutputInvalid);
        }
    }

    private static int ReadU24(ReadOnlySpan<byte> source, int offset) =>
        source[offset] | source[offset + 1] << 8 | source[offset + 2] << 16;

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
