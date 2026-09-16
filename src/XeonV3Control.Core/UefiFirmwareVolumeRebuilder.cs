using System.Security.Cryptography;

namespace XeonV3Control.Core;

public enum UefiFirmwareVolumeMutationStrategy
{
    InPlace,
    GrowIntoAdjacentFreeSpace,
    RebuildFirmwareVolume,
    RequiresRebase,
    Unsupported
}

public static class UefiFirmwareVolumeMutationReason
{
    public const string None = nameof(None);
    public const string VolumeInvalid = nameof(VolumeInvalid);
    public const string TargetNotFound = nameof(TargetNotFound);
    public const string CandidateInvalid = nameof(CandidateInvalid);
    public const string CandidateMetadataChanged = nameof(CandidateMetadataChanged);
    public const string TransitionalFilePresent = nameof(TransitionalFilePresent);
    public const string DuplicateGuid = nameof(DuplicateGuid);
    public const string VolumeTopFileInvalid = nameof(VolumeTopFileInvalid);
    public const string InsufficientSpace = nameof(InsufficientSpace);
    public const string FixedFileWouldMove = nameof(FixedFileWouldMove);
    public const string PeiFileWouldMove = nameof(PeiFileWouldMove);
    public const string PeiRebaseNotProvable = nameof(PeiRebaseNotProvable);
    public const string UnknownFileWouldMove = nameof(UnknownFileWouldMove);
    public const string PaddingCannotRepresentGap = nameof(PaddingCannotRepresentGap);
    public const string CandidateAlignmentInvalid = nameof(CandidateAlignmentInvalid);
}

public sealed record UefiFirmwareVolumeReplacementPlan(
    UefiFirmwareVolumeMutationStrategy Strategy,
    string Reason,
    long VolumeOffset,
    long TargetOffset,
    int CandidateSize,
    int MovedFileCount,
    int GeneratedPadFileCount)
{
    public bool CanApply => Strategy is
        UefiFirmwareVolumeMutationStrategy.InPlace or
        UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace or
        UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume;
}

/// <summary>
/// Conservative PI FFSv2/v3 replacement planner/rebuilder. It never changes FV size/header and never
/// moves a fixed, VTF, or unknown file. A pure PEIM may move only when <see cref="UefiXipPeRebaser"/>
/// proves a direct PE32/PE32+ XIP relocation safe; all other PEI-sensitive files remain pinned. Existing
/// PAD files are placement slack and are regenerated only where needed to keep surviving files aligned.
/// </summary>
public static class UefiFirmwareVolumeRebuilder
{
    private static readonly Guid VolumeTopFileGuid = new("1ba0062e-c779-4582-8566-336ae8f78f09");
    private static readonly Guid AmiPadFileGuid = new("e4536585-7909-4a60-b5c6-ecdea6ebfb54");

    private const byte FfsSecurityCore = 0x03;
    private const byte FfsPeiCore = 0x04;
    private const byte FfsPeim = 0x06;
    private const byte FfsApplication = 0x09;
    private const byte FfsMmCore = 0x0D;
    private const byte FfsMmCoreStandalone = 0x0F;

    public static UefiFirmwareVolumeReplacementPlan PlanReplacement(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        ReadOnlySpan<byte> candidateFfs,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(target);
        UefiDriverMutationPlanner.EnsureImageMatches(source, image);
        token.ThrowIfCancellationRequested();

        if (!TryResolveContext(source, image, target, candidateFfs, token, out ReplacementContext context, out string reason))
        {
            return Failure(reason, target, candidateFfs.Length);
        }

        if (!IsDataAlignmentValid(
                context.Target.Offset,
                context.Layout.Start,
                context.Candidate.HeaderSize,
                context.Candidate.Attributes))
        {
            return Failure(UefiFirmwareVolumeMutationReason.CandidateAlignmentInvalid, target, candidateFfs.Length);
        }

        if (TryPlanSameOffsetReplacement(context, out PlacementPlan direct))
        {
            return ToPublicPlan(direct, context);
        }

        PlacementPlan rebuilt = BuildRebuildPlan(source, image, context, token);
        return ToPublicPlan(rebuilt, context);
    }

    internal static byte[] ApplyReplacement(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        ReadOnlySpan<byte> candidateFfs,
        UefiFirmwareVolumeMutationStrategy expectedStrategy,
        CancellationToken token = default)
    {
        UefiFirmwareVolumeReplacementPlan publicPlan = PlanReplacement(source, image, target, candidateFfs, token);
        if (!publicPlan.CanApply || publicPlan.Strategy != expectedStrategy ||
            !TryResolveContext(source, image, target, candidateFfs, token, out ReplacementContext context, out _))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }

        PlacementPlan placement = publicPlan.Strategy is
            UefiFirmwareVolumeMutationStrategy.InPlace or UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace
            ? BuildSameOffsetReplacement(context)
            : BuildRebuildPlan(source, image, context, token);
        if (!placement.CanApply || placement.Strategy != expectedStrategy)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }

        byte[] output = source.ToArray();
        if (placement.Strategy == UefiFirmwareVolumeMutationStrategy.InPlace)
        {
            ApplyInPlace(output, context, placement);
        }
        else
        {
            ApplyRebuiltRange(output, source, context, placement);
        }

        ValidatePhysicalResult(source, output, context, placement, token);
        return output;
    }

    private static bool TryResolveContext(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        ReadOnlySpan<byte> candidateFfs,
        CancellationToken token,
        out ReplacementContext context,
        out string reason)
    {
        context = default!;
        reason = UefiFirmwareVolumeMutationReason.VolumeInvalid;
        FirmwareVolume? volume = image.Volumes.SingleOrDefault(item => item.Offset == target.VolumeOffset);
        if (volume is null ||
            !UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem) ||
            !UefiFfsVolumeScanner.TryReadFiles(source, volume, token, out UefiFfsVolumeLayout layout,
                out IReadOnlyList<UefiFfsFileLocation> files) ||
            layout.EraseByte is not (byte.MinValue or byte.MaxValue))
        {
            return false;
        }

        if (files.Count == 0 || files.Count > SecureBootRepairPolicy.MaximumFilesPerFirmwareVolume ||
            files.Any(file => file.State != FfsFileState.DataValid))
        {
            reason = UefiFirmwareVolumeMutationReason.TransitionalFilePresent;
            return false;
        }

        UefiFfsFileLocation[] targetMatches = files.Where(file =>
            file.Guid == target.DriverGuid &&
            file.Offset == target.FileOffset &&
            file.State == FfsFileState.DataValid).ToArray();
        if (targetMatches.Length != 1)
        {
            reason = UefiFirmwareVolumeMutationReason.TargetNotFound;
            return false;
        }
        UefiFfsFileLocation targetFile = targetMatches[0];
        string sourceTargetSha = Convert.ToHexString(SHA256.HashData(source.Slice(targetFile.Offset, targetFile.Size)));
        string expectedSha;
        try
        {
            expectedSha = Sha256Identity.Normalize(target.ExpectedSha256, OperationError.UefiDriverUpdateUnsupported);
        }
        catch (InvalidDataException)
        {
            reason = UefiFirmwareVolumeMutationReason.TargetNotFound;
            return false;
        }
        if (!string.Equals(sourceTargetSha, expectedSha, StringComparison.Ordinal))
        {
            reason = UefiFirmwareVolumeMutationReason.TargetNotFound;
            return false;
        }

        if (!UefiFfsFileParser.TryRead(candidateFfs, 0, candidateFfs.Length, layout.EraseByte, out FfsFileHeaderInfo candidate) ||
            candidate.Size != candidateFfs.Length ||
            candidate.State != FfsFileState.DataValid ||
            candidate.Guid != targetFile.Guid ||
            candidate.Type != targetFile.Type)
        {
            reason = UefiFirmwareVolumeMutationReason.CandidateInvalid;
            return false;
        }
        if (candidate.Attributes != targetFile.Attributes || candidate.HeaderSize != targetFile.HeaderSize)
        {
            reason = UefiFirmwareVolumeMutationReason.CandidateMetadataChanged;
            return false;
        }

        if (HasDuplicateNonPadGuids(files))
        {
            reason = UefiFirmwareVolumeMutationReason.DuplicateGuid;
            return false;
        }
        if (!HasValidVolumeTopFile(files, layout))
        {
            reason = UefiFirmwareVolumeMutationReason.VolumeTopFileInvalid;
            return false;
        }

        int targetIndex = files.IndexOf(targetFile);
        if (targetIndex < 0)
        {
            reason = UefiFirmwareVolumeMutationReason.TargetNotFound;
            return false;
        }

        context = new ReplacementContext(
            volume,
            layout,
            files,
            targetFile,
            targetIndex,
            candidate,
            candidateFfs.ToArray());
        reason = UefiFirmwareVolumeMutationReason.None;
        return true;
    }

    private static bool TryPlanSameOffsetReplacement(ReplacementContext context, out PlacementPlan plan)
    {
        plan = BuildSameOffsetReplacement(context);
        return plan.CanApply;
    }

    private static PlacementPlan BuildSameOffsetReplacement(ReplacementContext context)
    {
        UefiFfsFileLocation target = context.Target;
        int nextNonPadIndex = context.TargetIndex + 1;
        bool consumedPad = false;
        while (nextNonPadIndex < context.Files.Count && context.Files[nextNonPadIndex].Type == UefiPiCode.FfsPad)
        {
            consumedPad = true;
            nextNonPadIndex++;
        }

        int boundary = nextNonPadIndex < context.Files.Count
            ? context.Files[nextNonPadIndex].Offset
            : context.Layout.End;
        int candidateNext = UefiFfsVolumeScanner.Align(
            context.Layout.Start,
            checked(target.Offset + context.CandidateBytes.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        if (candidateNext > boundary)
        {
            return PlacementPlan.Failure(UefiFirmwareVolumeMutationReason.InsufficientSpace);
        }

        int gap = boundary - candidateNext;
        bool hasFollowingNonPad = nextNonPadIndex < context.Files.Count;
        if (hasFollowingNonPad && !CanRepresentGap(gap))
        {
            return PlacementPlan.Failure(UefiFirmwareVolumeMutationReason.PaddingCannotRepresentGap);
        }

        UefiFirmwareVolumeMutationStrategy strategy;
        if (!consumedPad && gap == 0)
        {
            strategy = UefiFirmwareVolumeMutationStrategy.InPlace;
        }
        else if (!hasFollowingNonPad && !consumedPad)
        {
            // End-of-volume free space can remain erased; no file boundary is moved.
            strategy = UefiFirmwareVolumeMutationStrategy.InPlace;
        }
        else
        {
            strategy = UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace;
        }

        var placements = new List<FilePlacement>
        {
            new(context.Target, context.Target.Offset, context.CandidateBytes, IsTarget: true)
        };
        int generatedPads = 0;
        if (hasFollowingNonPad && gap > 0)
        {
            placements.Add(FilePlacement.Pad(candidateNext, gap, context.Layout.EraseByte));
            generatedPads++;
        }

        int mutationEnd = hasFollowingNonPad ? boundary : context.Layout.End;
        return new(
            strategy,
            UefiFirmwareVolumeMutationReason.None,
            placements,
            context.Target.Offset,
            mutationEnd,
            MovedFileCount: 0,
            GeneratedPadFileCount: generatedPads);
    }

    private static PlacementPlan BuildRebuildPlan(
        ReadOnlySpan<byte> source,
        BiosImage image,
        ReplacementContext context,
        CancellationToken token)
    {
        var placements = new List<FilePlacement>();
        int cursor = context.Target.Offset;
        int moved = 0;
        int pads = 0;

        placements.Add(new(context.Target, context.Target.Offset, context.CandidateBytes, IsTarget: true));
        cursor = UefiFfsVolumeScanner.Align(
            context.Layout.Start,
            checked(context.Target.Offset + context.CandidateBytes.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);

        for (int index = context.TargetIndex + 1; index < context.Files.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            UefiFfsFileLocation file = context.Files[index];
            if (file.Type == UefiPiCode.FfsPad)
            {
                continue;
            }

            bool vtf = file.Guid == VolumeTopFileGuid;
            bool purePeim = file.Type == FfsPeim;
            bool otherPeiSensitive = IsPeiSensitive(file.Type) && !purePeim;
            bool mustStay = vtf || AmiSecureBootSpecification.IsFixed(file.Attributes) || otherPeiSensitive ||
                !purePeim && !IsKnownMovableFileType(file.Type);

            int destination;
            byte[]? rewrittenBytes = null;
            bool rebased = false;
            if (mustStay)
            {
                destination = file.Offset;
                if (cursor > destination)
                {
                    return PlacementPlan.Failure(
                        IsPeiSensitive(file.Type)
                            ? UefiFirmwareVolumeMutationReason.PeiFileWouldMove
                            : AmiSecureBootSpecification.IsFixed(file.Attributes) || vtf
                                ? UefiFirmwareVolumeMutationReason.FixedFileWouldMove
                                : UefiFirmwareVolumeMutationReason.UnknownFileWouldMove,
                        strategy: IsPeiSensitive(file.Type)
                            ? UefiFirmwareVolumeMutationStrategy.RequiresRebase
                            : UefiFirmwareVolumeMutationStrategy.Unsupported);
                }
                if (!IsDataAlignmentValid(destination, context.Layout.Start, file.HeaderSize, file.Attributes))
                {
                    return PlacementPlan.Failure(UefiFirmwareVolumeMutationReason.CandidateAlignmentInvalid);
                }
                int gap = destination - cursor;
                if (!CanRepresentGap(gap))
                {
                    return PlacementPlan.Failure(UefiFirmwareVolumeMutationReason.PaddingCannotRepresentGap);
                }
                if (gap > 0)
                {
                    placements.Add(FilePlacement.Pad(cursor, gap, context.Layout.EraseByte));
                    pads++;
                }
            }
            else
            {
                int originalGap = file.Offset - cursor;
                if (file.Offset >= cursor && CanRepresentGap(originalGap) &&
                    IsDataAlignmentValid(file.Offset, context.Layout.Start, file.HeaderSize, file.Attributes))
                {
                    destination = file.Offset;
                }
                else
                {
                    destination = ChooseMovableDestination(context.Layout.Start, cursor, file);
                    if (destination < 0)
                    {
                        return PlacementPlan.Failure(UefiFirmwareVolumeMutationReason.PaddingCannotRepresentGap);
                    }
                }
                int gap = destination - cursor;
                if (gap > 0)
                {
                    placements.Add(FilePlacement.Pad(cursor, gap, context.Layout.EraseByte));
                    pads++;
                }

                if (purePeim && destination != file.Offset)
                {
                    if (!UefiXipPeRebaser.TryRebasePeim(
                            source, image, file, destination, context.Layout.EraseByte, out rewrittenBytes))
                    {
                        return PlacementPlan.Failure(
                            UefiFirmwareVolumeMutationReason.PeiRebaseNotProvable,
                            UefiFirmwareVolumeMutationStrategy.RequiresRebase);
                    }
                    rebased = true;
                }
            }

            if (destination != file.Offset)
            {
                moved++;
            }
            placements.Add(new(file, destination, rewrittenBytes, IsTarget: false, IsPad: false, IsRebased: rebased));
            cursor = UefiFfsVolumeScanner.Align(
                context.Layout.Start,
                checked(destination + file.Size),
                AmiSecureBootSpecification.FfsAlignmentBytes);
        }

        if (cursor > context.Layout.End)
        {
            return PlacementPlan.Failure(UefiFirmwareVolumeMutationReason.InsufficientSpace);
        }

        return new(
            UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume,
            UefiFirmwareVolumeMutationReason.None,
            placements,
            context.Target.Offset,
            context.Layout.End,
            moved,
            pads);
    }

    private static int ChooseMovableDestination(int volumeStart, int cursor, UefiFfsFileLocation file)
    {
        int candidate = UefiFfsVolumeScanner.Align(volumeStart, cursor, AmiSecureBootSpecification.FfsAlignmentBytes);
        for (int attempt = 0; attempt < 4096; attempt++)
        {
            int gap = candidate - cursor;
            if (CanRepresentGap(gap) && IsDataAlignmentValid(candidate, volumeStart, file.HeaderSize, file.Attributes))
            {
                return candidate;
            }
            candidate = checked(candidate + AmiSecureBootSpecification.FfsAlignmentBytes);
        }
        return -1;
    }

    private static void ApplyInPlace(byte[] output, ReplacementContext context, PlacementPlan plan)
    {
        context.CandidateBytes.CopyTo(output, context.Target.Offset);
        int candidateNext = UefiFfsVolumeScanner.Align(
            context.Layout.Start,
            checked(context.Target.Offset + context.CandidateBytes.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        int eraseEnd = plan.End;
        if (eraseEnd > candidateNext)
        {
            output.AsSpan(candidateNext, eraseEnd - candidateNext).Fill(context.Layout.EraseByte);
        }
        foreach (FilePlacement placement in plan.Placements)
        {
            if (placement.IsPad)
            {
                placement.Bytes!.CopyTo(output, placement.Offset);
            }
        }
    }

    private static void ApplyRebuiltRange(
        byte[] output,
        ReadOnlySpan<byte> source,
        ReplacementContext context,
        PlacementPlan plan)
    {
        output.AsSpan(plan.Start, plan.End - plan.Start).Fill(context.Layout.EraseByte);
        foreach (FilePlacement placement in plan.Placements)
        {
            ReadOnlySpan<byte> bytes = placement.Bytes is null
                ? source.Slice(placement.SourceFile.Offset, placement.SourceFile.Size)
                : placement.Bytes;
            bytes.CopyTo(output.AsSpan(placement.Offset, bytes.Length));
        }
    }

    private static void ValidatePhysicalResult(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        ReplacementContext context,
        PlacementPlan plan,
        CancellationToken token)
    {
        if (output.Length != source.Length ||
            !source[..plan.Start].SequenceEqual(output[..plan.Start]) ||
            !source[plan.End..].SequenceEqual(output[plan.End..]))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        if (!UefiFfsVolumeScanner.TryReadFiles(output, context.Volume, token, out UefiFfsVolumeLayout outputLayout,
                out IReadOnlyList<UefiFfsFileLocation> outputFiles) ||
            outputLayout != context.Layout ||
            outputFiles.Any(file => file.State != FfsFileState.DataValid))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        UefiFfsFileLocation[] candidateMatches = outputFiles.Where(file =>
            file.Type != UefiPiCode.FfsPad &&
            file.Guid == context.Target.Guid &&
            file.State == FfsFileState.DataValid).ToArray();
        if (candidateMatches.Length != 1)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }
        UefiFfsFileLocation candidateFile = candidateMatches[0];
        string candidateSha = Convert.ToHexString(SHA256.HashData(output.Slice(candidateFile.Offset, candidateFile.Size)));
        string expectedCandidateSha = Convert.ToHexString(SHA256.HashData(context.CandidateBytes));
        if (!string.Equals(candidateSha, expectedCandidateSha, StringComparison.Ordinal))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        if (!NonPadFileInventoryEquivalent(source, output, context, outputFiles, plan))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        foreach (FilePlacement placement in plan.Placements)
        {
            if (placement.IsPad && !PadFileMatches(output, placement, context.Layout.EraseByte))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
            }
            if (!placement.IsPad && !placement.IsTarget && IsPositionSensitive(placement.SourceFile) &&
                placement.Offset != placement.SourceFile.Offset && !placement.IsRebased)
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
            }
        }
    }

    private static bool NonPadFileInventoryEquivalent(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        ReplacementContext context,
        IReadOnlyList<UefiFfsFileLocation> outputFiles,
        PlacementPlan plan)
    {
        var expected = new List<FileIdentity>();
        for (int index = 0; index < context.Files.Count; index++)
        {
            UefiFfsFileLocation file = context.Files[index];
            if (file.Type == UefiPiCode.FfsPad || index == context.TargetIndex)
            {
                continue;
            }
            FilePlacement? rewritten = plan.Placements.FirstOrDefault(placement =>
                !placement.IsPad && !placement.IsTarget && placement.SourceFile.Offset == file.Offset &&
                placement.SourceFile.Guid == file.Guid && placement.Bytes is not null);
            expected.Add(rewritten is null
                ? FileIdentity.From(source, file)
                : FileIdentity.FromRewritten(file, rewritten.Bytes!));
        }
        expected.Add(FileIdentity.From(context.CandidateBytes, context.Candidate));

        var actual = new List<FileIdentity>();
        foreach (UefiFfsFileLocation file in outputFiles)
        {
            if (file.Type != UefiPiCode.FfsPad)
            {
                actual.Add(FileIdentity.From(output, file));
            }
        }

        if (expected.Count != actual.Count)
        {
            return false;
        }
        var used = new bool[actual.Count];
        foreach (FileIdentity wanted in expected)
        {
            bool found = false;
            for (int index = 0; index < actual.Count; index++)
            {
                if (!used[index] && wanted.SemanticallyEquals(actual[index]))
                {
                    used[index] = true;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
        }
        return true;
    }

    private static bool PadFileMatches(ReadOnlySpan<byte> output, FilePlacement placement, byte eraseByte)
    {
        if (placement.Bytes is null ||
            !output.Slice(placement.Offset, placement.Bytes.Length).SequenceEqual(placement.Bytes) ||
            !UefiFfsFileParser.TryRead(output, placement.Offset, placement.Offset + placement.Bytes.Length, eraseByte,
                out FfsFileHeaderInfo header))
        {
            return false;
        }
        return header.Type == UefiPiCode.FfsPad && header.Size == placement.Bytes.Length &&
            header.State == FfsFileState.DataValid;
    }

    private static bool HasDuplicateNonPadGuids(IReadOnlyList<UefiFfsFileLocation> files)
    {
        var seen = new HashSet<Guid>();
        foreach (UefiFfsFileLocation file in files)
        {
            if (file.Type != UefiPiCode.FfsPad && !seen.Add(file.Guid))
            {
                return true;
            }
        }
        return false;
    }

    private static bool HasValidVolumeTopFile(IReadOnlyList<UefiFfsFileLocation> files, UefiFfsVolumeLayout layout)
    {
        UefiFfsFileLocation[] vtfs = files.Where(file => file.Guid == VolumeTopFileGuid).ToArray();
        if (vtfs.Length == 0)
        {
            return true;
        }
        if (vtfs.Length != 1)
        {
            return false;
        }
        UefiFfsFileLocation vtf = vtfs[0];
        return vtf.Type != UefiPiCode.FfsPad && checked(vtf.Offset + vtf.Size) == layout.End &&
            vtf.NextOffset == layout.End && files.IndexOf(vtf) == files.Count - 1;
    }

    private static bool IsDataAlignmentValid(int fileOffset, int volumeStart, int headerSize, byte attributes)
    {
        int required = AmiSecureBootSpecification.RequiredDataAlignment(attributes);
        int relativeData = checked(fileOffset - volumeStart + headerSize);
        return relativeData >= 0 && relativeData % required == 0;
    }

    private static bool CanRepresentGap(int gap) =>
        gap == 0 || (gap >= AmiSecureBootSpecification.FfsFileHeaderBytes &&
            gap % AmiSecureBootSpecification.FfsAlignmentBytes == 0 &&
            gap <= AmiSecureBootSpecification.MaximumNormalFfsFileBytes);

    private static bool IsPeiSensitive(byte type) => type is
        FfsSecurityCore or FfsPeiCore or FfsPeim or UefiPiCode.FfsCombinedPeimDriver;

    private static bool IsKnownMovableFileType(byte type) => type is
        UefiPiCode.FfsDriver or FfsApplication or UefiPiCode.FfsMm or UefiPiCode.FfsCombinedMmDxe or
        UefiPiCode.FfsMmStandalone or FfsMmCore or FfsMmCoreStandalone;

    private static bool IsPositionSensitive(UefiFfsFileLocation file) =>
        file.Guid == VolumeTopFileGuid || AmiSecureBootSpecification.IsFixed(file.Attributes) ||
        IsPeiSensitive(file.Type) || !IsKnownMovableFileType(file.Type);

    private static byte[] CreatePadFile(int size, byte eraseByte)
    {
        if (!CanRepresentGap(size))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }

        byte[] pad = new byte[size];
        pad.AsSpan().Fill(eraseByte);
        AmiPadFileGuid.TryWriteBytes(pad);
        pad[AmiSecureBootSpecification.FfsFileChecksumOffset] = AmiSecureBootSpecification.FfsFixedFileChecksum;
        pad[AmiSecureBootSpecification.FfsTypeOffset] = UefiPiCode.FfsPad;
        pad[AmiSecureBootSpecification.FfsAttributesOffset] = 0;
        WriteU24(pad, AmiSecureBootSpecification.FfsSizeOffset, size);
        byte logicalState = AmiSecureBootSpecification.FfsDataValidPrerequisiteMask;
        pad[AmiSecureBootSpecification.FfsStateOffset] = eraseByte == byte.MaxValue
            ? unchecked((byte)~logicalState)
            : logicalState;
        if (!UefiFfsChecksum.TryRecalculate(pad, AmiSecureBootSpecification.FfsFileHeaderBytes))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }
        return pad;
    }

    private static void WriteU24(Span<byte> destination, int offset, int value)
    {
        if (value < 0 || value > AmiSecureBootSpecification.MaximumNormalFfsFileBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
        destination[offset] = unchecked((byte)value);
        destination[offset + 1] = unchecked((byte)(value >> 8));
        destination[offset + 2] = unchecked((byte)(value >> 16));
    }

    private static UefiFirmwareVolumeReplacementPlan ToPublicPlan(PlacementPlan plan, ReplacementContext context) =>
        new(
            plan.Strategy,
            plan.Reason,
            context.Volume.Offset,
            context.Target.Offset,
            context.CandidateBytes.Length,
            plan.MovedFileCount,
            plan.GeneratedPadFileCount);

    private static UefiFirmwareVolumeReplacementPlan Failure(string reason, UefiDriverMutationTarget target, int size) =>
        new(UefiFirmwareVolumeMutationStrategy.Unsupported, reason, target.VolumeOffset, target.FileOffset, size, 0, 0);

    private sealed record ReplacementContext(
        FirmwareVolume Volume,
        UefiFfsVolumeLayout Layout,
        IReadOnlyList<UefiFfsFileLocation> Files,
        UefiFfsFileLocation Target,
        int TargetIndex,
        FfsFileHeaderInfo Candidate,
        byte[] CandidateBytes);

    private sealed record PlacementPlan(
        UefiFirmwareVolumeMutationStrategy Strategy,
        string Reason,
        IReadOnlyList<FilePlacement> Placements,
        int Start,
        int End,
        int MovedFileCount,
        int GeneratedPadFileCount)
    {
        internal bool CanApply => Strategy is UefiFirmwareVolumeMutationStrategy.InPlace or
            UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace or
            UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume;

        internal static PlacementPlan Failure(
            string reason,
            UefiFirmwareVolumeMutationStrategy strategy = UefiFirmwareVolumeMutationStrategy.Unsupported) =>
            new(strategy, reason, [], 0, 0, 0, 0);


    }

    private sealed record FilePlacement(
        UefiFfsFileLocation SourceFile,
        int Offset,
        byte[]? Bytes,
        bool IsTarget,
        bool IsPad = false,
        bool IsRebased = false)
    {
        internal static FilePlacement Pad(int offset, int size, byte eraseByte) =>
            new(default, offset, CreatePadFile(size, eraseByte), IsTarget: false, IsPad: true, IsRebased: false);
    }

    private readonly record struct FileIdentity(
        Guid Guid,
        byte Type,
        byte Attributes,
        int Size,
        int HeaderSize,
        string Sha256)
    {
        internal static FileIdentity From(ReadOnlySpan<byte> source, UefiFfsFileLocation file) =>
            new(file.Guid, file.Type, file.Attributes, file.Size, file.HeaderSize,
                Convert.ToHexString(SHA256.HashData(source.Slice(file.Offset, file.Size))));

        internal static FileIdentity From(ReadOnlySpan<byte> source, FfsFileHeaderInfo file) =>
            new(file.Guid, file.Type, file.Attributes, file.Size, file.HeaderSize,
                Convert.ToHexString(SHA256.HashData(source)));

        internal static FileIdentity FromRewritten(UefiFfsFileLocation file, ReadOnlySpan<byte> bytes) =>
            new(file.Guid, file.Type, file.Attributes, file.Size, file.HeaderSize,
                Convert.ToHexString(SHA256.HashData(bytes)));

        internal bool SemanticallyEquals(FileIdentity other) =>
            Guid == other.Guid && Type == other.Type && Attributes == other.Attributes &&
            Size == other.Size && HeaderSize == other.HeaderSize &&
            string.Equals(Sha256, other.Sha256, StringComparison.Ordinal);
    }
}
