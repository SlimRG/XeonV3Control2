using System.Security.Cryptography;

namespace XeonV3Control.Core;

internal static class UefiFfsMutationReason
{
    internal const string None = nameof(None);
    internal const string VolumeNotFound = nameof(VolumeNotFound);
    internal const string VolumeIncomplete = nameof(VolumeIncomplete);
    internal const string UnsupportedFileSystem = nameof(UnsupportedFileSystem);
    internal const string FileNotFound = nameof(FileNotFound);
    internal const string FileChanged = nameof(FileChanged);
    internal const string FixedFile = nameof(FixedFile);
}

/// <summary>
/// Exact identity required before an arbitrary FFS file can be transitioned to the PI deleted state.
/// This is intentionally internal: callers must already have independently authorized why the file
/// is safe to remove. The planner only proves that the requested byte range still identifies exactly
/// the expected active FFS and that an in-place state transition is structurally valid.
/// </summary>
internal readonly record struct UefiFfsRemovalTarget(
    Guid FileGuid,
    long VolumeOffset,
    long FileOffset,
    int FileSize,
    byte FileType,
    string ExpectedSha256);

internal readonly record struct UefiFfsRemovalPreflight(
    UefiDriverMutationFeasibility Feasibility,
    string Reason,
    UefiFfsFileLocation File,
    UefiFfsVolumeLayout Layout)
{
    internal bool IsReady =>
        Feasibility == UefiDriverMutationFeasibility.InPlace &&
        string.Equals(Reason, UefiFfsMutationReason.None, StringComparison.Ordinal);
}

/// <summary>
/// Low-level, authorization-agnostic FFS removal preflight. Unlike the public UEFI driver mutation
/// planner this accepts any PI FFS type, because a separately authenticated injected firmware module
/// can be a PEIM or another non-DXE file. It never decides whether a module is malicious/foreign.
/// </summary>
internal static class UefiFfsMutationPlanner
{
    internal static UefiFfsRemovalPreflight PlanRemoveExact(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiFfsRemovalTarget target,
        CancellationToken token = default)
    {
        UefiDriverMutationPlanner.EnsureImageMatches(source, image);
        token.ThrowIfCancellationRequested();

        FirmwareVolume? volume = image.Volumes.SingleOrDefault(item => item.Offset == target.VolumeOffset);
        if (volume is null)
        {
            return Failure(UefiFfsMutationReason.VolumeNotFound);
        }
        if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem))
        {
            return Failure(UefiFfsMutationReason.UnsupportedFileSystem);
        }
        if (!UefiFfsVolumeScanner.TryReadFiles(
                source,
                volume,
                token,
                out UefiFfsVolumeLayout layout,
                out IReadOnlyList<UefiFfsFileLocation> files))
        {
            return Failure(UefiFfsMutationReason.VolumeIncomplete);
        }

        UefiFfsFileLocation file = default;
        int matchCount = 0;
        foreach (UefiFfsFileLocation candidate in files)
        {
            token.ThrowIfCancellationRequested();
            if (candidate.State != FfsFileState.DataValid ||
                candidate.Guid != target.FileGuid ||
                candidate.Offset != target.FileOffset ||
                candidate.Size != target.FileSize ||
                candidate.Type != target.FileType)
            {
                continue;
            }

            file = candidate;
            matchCount++;
            if (matchCount > 1)
            {
                return Failure(UefiFfsMutationReason.FileNotFound);
            }
        }
        if (matchCount != 1)
        {
            return Failure(UefiFfsMutationReason.FileNotFound);
        }

        string expectedHash;
        try
        {
            expectedHash = Sha256Identity.Normalize(target.ExpectedSha256, UefiFfsMutationReason.FileChanged);
        }
        catch (InvalidDataException)
        {
            return Failure(UefiFfsMutationReason.FileChanged);
        }

        string actualHash = Convert.ToHexString(SHA256.HashData(source.Slice(file.Offset, file.Size)));
        if (!string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
        {
            return Failure(UefiFfsMutationReason.FileChanged);
        }
        if (AmiSecureBootSpecification.IsFixed(file.Attributes))
        {
            return new(
                UefiDriverMutationFeasibility.Unsupported,
                UefiFfsMutationReason.FixedFile,
                file,
                layout);
        }

        return new(
            UefiDriverMutationFeasibility.InPlace,
            UefiFfsMutationReason.None,
            file,
            layout);
    }

    private static UefiFfsRemovalPreflight Failure(string reason) =>
        new(UefiDriverMutationFeasibility.Unsupported, reason, default, default);
}
