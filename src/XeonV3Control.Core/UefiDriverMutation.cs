using System.Security.Cryptography;

namespace XeonV3Control.Core;

public enum UefiDriverMutationKind
{
    Add,
    Replace,
    Remove
}

public enum UefiDriverMutationFeasibility
{
    InPlace,
    RequiresRepack,
    Unsupported
}

public static class UefiDriverMutationReason
{
    public const string None = nameof(None);
    public const string ImageMismatch = nameof(ImageMismatch);
    public const string DriverNotFound = nameof(DriverNotFound);
    public const string DriverAmbiguous = nameof(DriverAmbiguous);
    public const string DriverChanged = nameof(DriverChanged);
    public const string VolumeNotFound = nameof(VolumeNotFound);
    public const string VolumeIncomplete = nameof(VolumeIncomplete);
    public const string UnsupportedFileSystem = nameof(UnsupportedFileSystem);
    public const string InvalidReplacement = nameof(InvalidReplacement);
    public const string GuidMismatch = nameof(GuidMismatch);
    public const string TypeMismatch = nameof(TypeMismatch);
    public const string DuplicateGuid = nameof(DuplicateGuid);
    public const string FixedFile = nameof(FixedFile);
    public const string InsufficientSpace = nameof(InsufficientSpace);
    public const string AlignmentRequiresRepack = nameof(AlignmentRequiresRepack);
    public const string SlotBoundaryRequiresRepack = nameof(SlotBoundaryRequiresRepack);
}

/// <summary>
/// Validated mutation intent for a future firmware editor. The current product does not execute these plans.
/// </summary>
public sealed record UefiDriverMutationTarget(
    Guid DriverGuid,
    long VolumeOffset,
    long FileOffset,
    string ExpectedSha256)
{
    public static UefiDriverMutationTarget From(UefiDriverInfo driver)
    {
        ArgumentNullException.ThrowIfNull(driver);
        return new(driver.FileGuid, driver.VolumeOffset, driver.FileOffset, driver.Sha256);
    }
}

public sealed record UefiDriverMutationPlan(
    UefiDriverMutationKind Kind,
    UefiDriverMutationFeasibility Feasibility,
    string Reason,
    Guid DriverGuid,
    long VolumeOffset,
    long? ExistingFileOffset,
    long? DestinationOffset,
    int NewFileSize,
    int AvailableBytes);

/// <summary>
/// Pre-validates add/replace/remove operations without modifying firmware bytes.
/// It intentionally exposes no apply method until firmware mutation receives a separate reviewed UI workflow.
/// </summary>
public static class UefiDriverMutationPlanner
{
    public static UefiDriverMutationPlan PlanRemove(
        ReadOnlySpan<byte> source,
        BiosImage image,
        Guid driverGuid,
        CancellationToken token = default)
    {
        EnsureImageMatches(source, image);
        DriverLocationResult location = FindDriver(source, image, driverGuid, token);
        return PlanRemoveAtLocation(location, driverGuid);
    }

    public static UefiDriverMutationPlan PlanRemove(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        EnsureImageMatches(source, image);
        DriverLocationResult location = FindDriver(source, image, target, token);
        return PlanRemoveAtLocation(location, target.DriverGuid);
    }

    private static UefiDriverMutationPlan PlanRemoveAtLocation(
        DriverLocationResult location,
        Guid driverGuid)
    {
        if (location.Status != DriverLocationStatus.Found)
        {
            return Failure(UefiDriverMutationKind.Remove, driverGuid, location);
        }

        UefiFfsFileLocation file = location.File;
        if (AmiSecureBootSpecification.IsFixed(file.Attributes))
        {
            return new(UefiDriverMutationKind.Remove, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.FixedFile, driverGuid, location.Volume.Offset,
                file.Offset, null, 0, 0);
        }

        // PI FFS deletion is a file-state transition; it does not require moving following files.
        return new(
            UefiDriverMutationKind.Remove,
            UefiDriverMutationFeasibility.InPlace,
            UefiDriverMutationReason.None,
            driverGuid,
            location.Volume.Offset,
            file.Offset,
            null,
            0,
            file.Size);
    }

    public static UefiDriverMutationPlan PlanReplace(
        ReadOnlySpan<byte> source,
        BiosImage image,
        Guid driverGuid,
        ReadOnlySpan<byte> replacementFfs,
        CancellationToken token = default)
    {
        EnsureImageMatches(source, image);
        DriverLocationResult location = FindDriver(source, image, driverGuid, token);
        return PlanReplaceAtLocation(location, driverGuid, replacementFfs);
    }

    public static UefiDriverMutationPlan PlanReplace(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        ReadOnlySpan<byte> replacementFfs,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        EnsureImageMatches(source, image);
        return PlanReplaceValidatedSource(source, image, target, replacementFfs, token);
    }

    internal static UefiDriverMutationPlan PlanReplaceValidatedSource(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        ReadOnlySpan<byte> replacementFfs,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(target);
        DriverLocationResult location = FindDriver(source, image, target, token);
        if (location.Status != DriverLocationStatus.Found)
        {
            return new(
                UefiDriverMutationKind.Replace,
                UefiDriverMutationFeasibility.Unsupported,
                location.Status == DriverLocationStatus.Changed
                    ? UefiDriverMutationReason.DriverChanged
                    : UefiDriverMutationReason.DriverNotFound,
                target.DriverGuid,
                target.VolumeOffset,
                target.FileOffset,
                null,
                0,
                0);
        }
        return PlanReplaceAtLocation(location, target.DriverGuid, replacementFfs);
    }

    private static UefiDriverMutationPlan PlanReplaceAtLocation(
        DriverLocationResult location,
        Guid driverGuid,
        ReadOnlySpan<byte> replacementFfs)
    {
        if (location.Status != DriverLocationStatus.Found)
        {
            return Failure(UefiDriverMutationKind.Replace, driverGuid, location);
        }

        UefiFfsFileLocation target = location.File;
        if (!TryReadReplacement(replacementFfs, location.Layout.EraseByte, out FfsFileHeaderInfo replacement))
        {
            return InvalidReplacement(UefiDriverMutationKind.Replace, driverGuid, location.Volume.Offset, target.Offset);
        }
        if (replacement.Guid != driverGuid)
        {
            return new(UefiDriverMutationKind.Replace, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.GuidMismatch, driverGuid, location.Volume.Offset,
                target.Offset, null, replacement.Size, 0);
        }
        if (replacement.Type != target.Type)
        {
            return new(UefiDriverMutationKind.Replace, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.TypeMismatch, driverGuid, location.Volume.Offset,
                target.Offset, null, replacement.Size, 0);
        }
        if (AmiSecureBootSpecification.IsFixed(target.Attributes) &&
            (replacement.Attributes != target.Attributes || replacement.HeaderSize != target.HeaderSize))
        {
            return new(UefiDriverMutationKind.Replace, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.FixedFile, driverGuid, location.Volume.Offset,
                target.Offset, null, replacement.Size, 0);
        }

        int targetIndex = location.Files.IndexOf(target);
        bool hasFollowingFile = targetIndex + 1 < location.Files.Count;
        int availableEnd = hasFollowingFile
            ? location.Files[targetIndex + 1].Offset
            : location.Layout.End;
        int available = checked(availableEnd - target.Offset);
        bool alignmentValid = IsDataAlignmentValid(
            target.Offset,
            location.Layout.Start,
            replacement.HeaderSize,
            replacement.Attributes);
        int replacementNext = UefiFfsVolumeScanner.Align(
            location.Layout.Start,
            checked(target.Offset + replacement.Size),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        bool preservesFollowingBoundary = !hasFollowingFile || replacementNext == availableEnd;
        if (alignmentValid && preservesFollowingBoundary && replacement.Size <= available)
        {
            return new(UefiDriverMutationKind.Replace, UefiDriverMutationFeasibility.InPlace,
                UefiDriverMutationReason.None, driverGuid, location.Volume.Offset,
                target.Offset, target.Offset, replacement.Size, available);
        }

        string reason = !alignmentValid
            ? UefiDriverMutationReason.AlignmentRequiresRepack
            : replacement.Size > available
                ? UefiDriverMutationReason.InsufficientSpace
                : UefiDriverMutationReason.SlotBoundaryRequiresRepack;
        return new(UefiDriverMutationKind.Replace, UefiDriverMutationFeasibility.RequiresRepack,
            reason, driverGuid, location.Volume.Offset, target.Offset, null, replacement.Size, available);
    }

    public static UefiDriverMutationPlan PlanAdd(
        ReadOnlySpan<byte> source,
        BiosImage image,
        long volumeOffset,
        ReadOnlySpan<byte> newDriverFfs,
        CancellationToken token = default)
    {
        EnsureImageMatches(source, image);
        FirmwareVolume? volume = image.Volumes.FirstOrDefault(item => item.Offset == volumeOffset);
        if (volume is null)
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.VolumeNotFound, Guid.Empty, volumeOffset, null, null, 0, 0);
        }
        if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem))
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.UnsupportedFileSystem, Guid.Empty, volumeOffset, null, null, 0, 0);
        }
        if (!UefiFfsVolumeScanner.TryReadFiles(source, volume, token, out UefiFfsVolumeLayout layout,
                out IReadOnlyList<UefiFfsFileLocation> files))
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.VolumeIncomplete, Guid.Empty, volumeOffset, null, null, 0, 0);
        }
        if (!TryReadReplacement(newDriverFfs, layout.EraseByte, out FfsFileHeaderInfo replacement) ||
            !IsDriverType(replacement.Type))
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.InvalidReplacement, Guid.Empty, volumeOffset, null, null, 0, 0);
        }
        if (files.Any(file => file.State == FfsFileState.DataValid && file.Guid == replacement.Guid))
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.DuplicateGuid, replacement.Guid, volumeOffset, null, null,
                replacement.Size, 0);
        }

        int destination = files.Count == 0 ? layout.FirstFileOffset : files[^1].NextOffset;
        int available = checked(layout.End - destination);
        if (!IsDataAlignmentValid(destination, layout.Start, replacement.HeaderSize, replacement.Attributes))
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.RequiresRepack,
                UefiDriverMutationReason.AlignmentRequiresRepack, replacement.Guid, volumeOffset,
                null, null, replacement.Size, available);
        }
        if (replacement.Size > available)
        {
            return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.Unsupported,
                UefiDriverMutationReason.InsufficientSpace, replacement.Guid, volumeOffset,
                null, destination, replacement.Size, available);
        }

        return new(UefiDriverMutationKind.Add, UefiDriverMutationFeasibility.InPlace,
            UefiDriverMutationReason.None, replacement.Guid, volumeOffset, null, destination,
            replacement.Size, available);
    }

    internal static void EnsureImageMatches(ReadOnlySpan<byte> source, BiosImage image)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (source.Length != image.Size)
        {
            throw new InvalidDataException(UefiDriverMutationReason.ImageMismatch);
        }
        string hash = Convert.ToHexString(SHA256.HashData(source));
        if (!string.Equals(hash, image.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(UefiDriverMutationReason.ImageMismatch);
        }
    }

    private static DriverLocationResult FindDriver(
        ReadOnlySpan<byte> source,
        BiosImage image,
        Guid driverGuid,
        CancellationToken token)
    {
        var matches = new List<(FirmwareVolume Volume, UefiFfsVolumeLayout Layout,
            IReadOnlyList<UefiFfsFileLocation> Files, UefiFfsFileLocation File)>();

        foreach (FirmwareVolume volume in image.Volumes)
        {
            token.ThrowIfCancellationRequested();
            if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem))
            {
                continue;
            }
            if (!UefiFfsVolumeScanner.TryReadFiles(source, volume, token, out UefiFfsVolumeLayout layout,
                    out IReadOnlyList<UefiFfsFileLocation> files))
            {
                continue;
            }
            foreach (UefiFfsFileLocation file in files)
            {
                if (file.State == FfsFileState.DataValid && file.Guid == driverGuid && IsDriverType(file.Type))
                {
                    matches.Add((volume, layout, files, file));
                }
            }
        }

        return matches.Count switch
        {
            0 => DriverLocationResult.NotFound,
            1 => new(DriverLocationStatus.Found, matches[0].Volume, matches[0].Layout,
                matches[0].Files, matches[0].File),
            _ => DriverLocationResult.Ambiguous
        };
    }

    private static DriverLocationResult FindDriver(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        CancellationToken token)
    {
        FirmwareVolume? volume = image.Volumes.FirstOrDefault(item => item.Offset == target.VolumeOffset);
        if (volume is null || !UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem) ||
            !UefiFfsVolumeScanner.TryReadFiles(source, volume, token, out UefiFfsVolumeLayout layout,
                out IReadOnlyList<UefiFfsFileLocation> files))
        {
            return DriverLocationResult.NotFound;
        }

        UefiFfsFileLocation[] matches = files
            .Where(file => file.State == FfsFileState.DataValid && file.Guid == target.DriverGuid &&
                file.Offset == target.FileOffset && IsDriverType(file.Type))
            .ToArray();
        if (matches.Length != 1)
        {
            return DriverLocationResult.NotFound;
        }

        UefiFfsFileLocation file = matches[0];
        string actualHash = Convert.ToHexString(SHA256.HashData(source.Slice(file.Offset, file.Size)));
        string expectedHash;
        try
        {
            expectedHash = Sha256Identity.Normalize(target.ExpectedSha256, UefiDriverMutationReason.DriverChanged);
        }
        catch (InvalidDataException)
        {
            return DriverLocationResult.Changed;
        }
        if (!string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
        {
            return DriverLocationResult.Changed;
        }

        return new(DriverLocationStatus.Found, volume, layout, files, file);
    }

    private static bool TryReadReplacement(
        ReadOnlySpan<byte> replacement,
        byte eraseByte,
        out FfsFileHeaderInfo header)
    {
        header = default;
        return replacement.Length >= AmiSecureBootSpecification.FfsFileHeaderBytes &&
               UefiFfsFileParser.TryRead(replacement, 0, replacement.Length, eraseByte, out header) &&
               header.Size == replacement.Length && header.State == FfsFileState.DataValid;
    }

    private static bool IsDataAlignmentValid(int fileOffset, int volumeStart, int headerSize, byte attributes)
    {
        int required = AmiSecureBootSpecification.RequiredDataAlignment(attributes);
        int relativeData = checked(fileOffset - volumeStart + headerSize);
        return relativeData >= 0 && relativeData % required == 0;
    }

    private static bool IsDriverType(byte type) =>
        type is UefiPiCode.FfsDriver or UefiPiCode.FfsCombinedPeimDriver or UefiPiCode.FfsMm or
            UefiPiCode.FfsCombinedMmDxe or UefiPiCode.FfsMmStandalone;

    private static UefiDriverMutationPlan InvalidReplacement(
        UefiDriverMutationKind kind,
        Guid guid,
        long volumeOffset,
        long? fileOffset) =>
        new(kind, UefiDriverMutationFeasibility.Unsupported, UefiDriverMutationReason.InvalidReplacement,
            guid, volumeOffset, fileOffset, null, 0, 0);

    private static UefiDriverMutationPlan Failure(
        UefiDriverMutationKind kind,
        Guid guid,
        DriverLocationResult location) =>
        new(kind, UefiDriverMutationFeasibility.Unsupported,
            location.Status switch
            {
                DriverLocationStatus.Ambiguous => UefiDriverMutationReason.DriverAmbiguous,
                DriverLocationStatus.Changed => UefiDriverMutationReason.DriverChanged,
                _ => UefiDriverMutationReason.DriverNotFound
            },
            guid, 0, null, null, 0, 0);

    private enum DriverLocationStatus
    {
        NotFound,
        Found,
        Ambiguous,
        Changed
    }

    private readonly record struct DriverLocationResult(
        DriverLocationStatus Status,
        FirmwareVolume Volume,
        UefiFfsVolumeLayout Layout,
        IReadOnlyList<UefiFfsFileLocation> Files,
        UefiFfsFileLocation File)
    {
        internal static DriverLocationResult NotFound { get; } =
            new(DriverLocationStatus.NotFound, default!, default, [], default);
        internal static DriverLocationResult Ambiguous { get; } =
            new(DriverLocationStatus.Ambiguous, default!, default, [], default);
        internal static DriverLocationResult Changed { get; } =
            new(DriverLocationStatus.Changed, default!, default, [], default);
    }
}

internal static class UefiFfsFileLocationListExtensions
{
    internal static int IndexOf(this IReadOnlyList<UefiFfsFileLocation> files, UefiFfsFileLocation value)
    {
        for (int index = 0; index < files.Count; index++)
        {
            if (files[index] == value)
            {
                return index;
            }
        }
        return -1;
    }
}
