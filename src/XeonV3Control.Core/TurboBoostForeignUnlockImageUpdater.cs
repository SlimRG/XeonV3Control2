using System.Security.Cryptography;

namespace XeonV3Control.Core;

/// <summary>
/// Executes only a previously authorized <see cref="TurboBoostForeignRemovalOperation.RemoveInjectedFfs"/>
/// operation. Authorization is intentionally recomputed from the exact source bytes immediately before
/// mutation; a caller-supplied Ready plan is never trusted by itself and no clean baseline is required.
/// </summary>
public static class TurboBoostForeignUnlockImageUpdater
{
    /// <summary>
    /// Returns a modified copy with one verified foreign FFS transitioned to the PI Deleted state.
    /// No FFS is moved, repacked, erased, or replaced and the input spans are never modified.
    /// </summary>
    public static byte[] RemoveInjectedFfs(
        ReadOnlySpan<byte> source,
        TurboBoostForeignRemovalPlan plan,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        token.ThrowIfCancellationRequested();
        EnsureExecutablePlanShape(plan);

        FirmwareMutationFileIo.VerifySha256(
            source,
            plan.SourceImageSha256,
            OperationError.TurboBoostForeignSourceChanged);

        BiosImage sourceImage = BiosImageLoader.Analyze(source, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        EnsureCompleteAnalysis(sourceImage);

        TurboBoostForeignRemovalPlan authorizedPlan = Reauthorize(sourceImage, plan);
        TurboBoostUnlockModule targetModule = FindExactForeignTarget(sourceImage, authorizedPlan);
        UefiFfsFileLocation targetFile = ValidateLowLevelTarget(source, sourceImage, targetModule, token, out UefiFfsVolumeLayout layout);

        int stateOffset = checked(targetFile.Offset + AmiSecureBootSpecification.FfsStateOffset);
        byte deletedState = BuildDeletedPhysicalState(source[stateOffset], layout.EraseByte);
        var output = source.ToArray();
        output[stateOffset] = deletedState;

        ValidateResult(
            source,
            output,
            sourceImage,
            targetModule,
            targetFile,
            layout,
            stateOffset,
            token);
        return output;
    }

    /// <summary>
    /// Reads the exact source file once, reauthorizes the plan against those bytes, writes to a unique
    /// side file with write-through semantics, verifies its hash, and never overwrites the source or a
    /// pre-existing destination.
    /// </summary>
    public static async Task<BiosImage> RemoveInjectedFfsFileAsync(
        string sourcePath,
        string destinationPath,
        TurboBoostForeignRemovalPlan plan,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(plan);

        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourcePath, token);
        byte[] updated = RemoveInjectedFfs(source, plan, token);
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
                throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
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

    internal static byte BuildDeletedPhysicalState(byte currentPhysicalState, byte eraseByte)
    {
        if (eraseByte is not (byte.MinValue or byte.MaxValue))
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        byte currentLogicalState = eraseByte == byte.MaxValue
            ? unchecked((byte)~currentPhysicalState)
            : currentPhysicalState;
        if (currentLogicalState != AmiSecureBootSpecification.FfsDataValidPrerequisiteMask)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignRemovalUnsupported);
        }

        byte deletedLogicalState = (byte)(
            currentLogicalState |
            AmiSecureBootSpecification.FfsFileDeletedState);
        byte deletedPhysicalState = eraseByte == byte.MaxValue
            ? unchecked((byte)~deletedLogicalState)
            : deletedLogicalState;

        bool validFlashTransition = eraseByte == byte.MaxValue
            ? (deletedPhysicalState & currentPhysicalState) == deletedPhysicalState
            : (deletedPhysicalState | currentPhysicalState) == deletedPhysicalState;
        if (!validFlashTransition)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }
        return deletedPhysicalState;
    }

    private static void EnsureExecutablePlanShape(TurboBoostForeignRemovalPlan plan)
    {
        if (!plan.CanExecute ||
            plan.Operation != TurboBoostForeignRemovalOperation.RemoveInjectedFfs ||
            plan.Reason != TurboBoostForeignRemovalReason.None ||
            plan.MutationFeasibility != UefiDriverMutationFeasibility.InPlace ||
            plan.FileGuid == Guid.Empty ||
            plan.VolumeOffset < 0 ||
            plan.FileOffset < 0 ||
            plan.FileSize <= 0 ||
            string.IsNullOrWhiteSpace(plan.FfsSha256) ||
            plan.BaselineImageSha256 is not null ||
            plan.BaselineFileGuid is not null ||
            plan.BaselineFileOffset is not null ||
            plan.BaselineFileSize is not null ||
            plan.BaselineFfsSha256 is not null)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignRemovalUnsupported);
        }
    }

    private static void EnsureCompleteAnalysis(BiosImage sourceImage)
    {
        if (sourceImage.TurboBoostUnlock.Incomplete || sourceImage.UefiDrivers.Incomplete)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignRemovalUnsupported);
        }
    }

    private static TurboBoostForeignRemovalPlan Reauthorize(
        BiosImage sourceImage,
        TurboBoostForeignRemovalPlan requestedPlan)
    {
        TurboBoostUnlockModule target = FindExactForeignTarget(sourceImage, requestedPlan);
        TurboBoostForeignRemovalPlan fresh = target.RemovalPlan;
        if (!PlanExecutionIdentityMatches(fresh, requestedPlan) ||
            !fresh.CanExecute ||
            fresh.Operation != TurboBoostForeignRemovalOperation.RemoveInjectedFfs ||
            fresh.Reason != TurboBoostForeignRemovalReason.None ||
            fresh.MutationFeasibility != UefiDriverMutationFeasibility.InPlace)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignRemovalUnsupported);
        }
        return fresh;
    }

    private static bool PlanExecutionIdentityMatches(
        TurboBoostForeignRemovalPlan left,
        TurboBoostForeignRemovalPlan right) =>
        left.Status == right.Status &&
        left.Operation == right.Operation &&
        left.Reason == right.Reason &&
        HashEquals(left.SourceImageSha256, right.SourceImageSha256) &&
        left.FileGuid == right.FileGuid &&
        left.VolumeOffset == right.VolumeOffset &&
        left.FileOffset == right.FileOffset &&
        left.FileSize == right.FileSize &&
        HashEquals(left.FfsSha256, right.FfsSha256) &&
        left.BaselineImageSha256 is null && right.BaselineImageSha256 is null &&
        left.BaselineFileGuid is null && right.BaselineFileGuid is null &&
        left.BaselineFileOffset is null && right.BaselineFileOffset is null &&
        left.BaselineFileSize is null && right.BaselineFileSize is null &&
        left.BaselineFfsSha256 is null && right.BaselineFfsSha256 is null &&
        left.MutationFeasibility == right.MutationFeasibility;

    private static TurboBoostUnlockModule FindExactForeignTarget(
        BiosImage sourceImage,
        TurboBoostForeignRemovalPlan plan)
    {
        TurboBoostUnlockModule[] matches = sourceImage.TurboBoostUnlock.Modules
            .Where(item =>
                item.Disposition == TurboBoostUnlockModuleDisposition.Foreign &&
                item.Verified &&
                item.FileGuid == plan.FileGuid &&
                item.VolumeOffset == plan.VolumeOffset &&
                item.FileOffset == plan.FileOffset &&
                item.FileSize == plan.FileSize &&
                HashEquals(item.FfsSha256, plan.FfsSha256))
            .ToArray();
        if (matches.Length != 1)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignRemovalUnsupported);
        }
        return matches[0];
    }

    private static UefiFfsFileLocation ValidateLowLevelTarget(
        ReadOnlySpan<byte> source,
        BiosImage sourceImage,
        TurboBoostUnlockModule module,
        CancellationToken token,
        out UefiFfsVolumeLayout layout)
    {
        var target = new UefiFfsRemovalTarget(
            module.FileGuid,
            module.VolumeOffset,
            module.FileOffset,
            module.FileSize,
            module.FfsType,
            module.FfsSha256);
        UefiFfsRemovalPreflight lowLevel = UefiFfsMutationPlanner.PlanRemoveExact(
            source, sourceImage, target, token);
        if (!lowLevel.IsReady || lowLevel.File.Offset != module.FileOffset)
        {
            if (string.Equals(lowLevel.Reason, UefiFfsMutationReason.FileChanged, StringComparison.Ordinal))
            {
                throw new InvalidDataException(OperationError.TurboBoostForeignSourceChanged);
            }
            throw new InvalidDataException(OperationError.TurboBoostForeignRemovalUnsupported);
        }

        layout = lowLevel.Layout;
        return lowLevel.File;
    }

    private static void ValidateResult(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        BiosImage sourceImage,
        TurboBoostUnlockModule targetModule,
        UefiFfsFileLocation targetFile,
        UefiFfsVolumeLayout sourceLayout,
        int stateOffset,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (source.Length != output.Length ||
            stateOffset < 0 || stateOffset >= source.Length ||
            source[..stateOffset].SequenceEqual(output[..stateOffset]) is false ||
            source[(stateOffset + 1)..].SequenceEqual(output[(stateOffset + 1)..]) is false ||
            source[stateOffset] == output[stateOffset])
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        FirmwareVolume? targetVolume = sourceImage.Volumes.SingleOrDefault(item => item.Offset == targetModule.VolumeOffset);
        if (targetVolume is null ||
            !UefiFfsVolumeScanner.TryReadFiles(output, targetVolume, token, out UefiFfsVolumeLayout outputLayout,
                out IReadOnlyList<UefiFfsFileLocation> outputFiles) ||
            outputLayout != sourceLayout)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        UefiFfsFileLocation[] deletedMatches = outputFiles.Where(item =>
            item.Guid == targetFile.Guid &&
            item.Type == targetFile.Type &&
            item.Attributes == targetFile.Attributes &&
            item.Offset == targetFile.Offset &&
            item.Size == targetFile.Size &&
            item.HeaderSize == targetFile.HeaderSize &&
            item.NextOffset == targetFile.NextOffset &&
            item.State == FfsFileState.Deleted).ToArray();
        if (deletedMatches.Length != 1)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        BiosImage outputImage = BiosImageLoader.Analyze(output, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(outputImage);
        if (outputImage.TurboBoostUnlock.Incomplete || outputImage.UefiDrivers.Incomplete ||
            outputImage.Size != sourceImage.Size ||
            !TurboBoostForeignUnlockRemovalPlanner.HasCompatibleImageLayout(sourceImage, outputImage))
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        if (outputImage.TurboBoostUnlock.Modules.Any(item =>
                item.FileGuid == targetModule.FileGuid &&
                item.VolumeOffset == targetModule.VolumeOffset &&
                item.FileOffset == targetModule.FileOffset) ||
            outputImage.UefiDrivers.Drivers.Any(item =>
                item.FileGuid == targetModule.FileGuid &&
                item.VolumeOffset == targetModule.VolumeOffset &&
                item.FileOffset == targetModule.FileOffset))
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        TurboBoostUnlockModule[] expectedModules = sourceImage.TurboBoostUnlock.Modules
            .Where(item => !SameLocation(item, targetModule))
            .ToArray();
        if (!ModuleSetsEquivalent(expectedModules, outputImage.TurboBoostUnlock.Modules) ||
            !ModuleSetsEquivalent(sourceImage.TurboBoostUnlock.RetainedUnlockModules, outputImage.TurboBoostUnlock.RetainedUnlockModules) ||
            !sourceImage.TurboBoostUnlock.Microcodes.SequenceEqual(outputImage.TurboBoostUnlock.Microcodes))
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }

        bool sourceHasCpuPatch = sourceImage.TurboBoostUnlock.HasXeonE5V3CpuPatch;
        bool outputHasCpuPatch = outputImage.TurboBoostUnlock.HasXeonE5V3CpuPatch;
        if (sourceHasCpuPatch != outputHasCpuPatch)
        {
            throw new InvalidDataException(OperationError.TurboBoostForeignOutputInvalid);
        }
    }

    private static bool ModuleSetsEquivalent(
        IReadOnlyList<TurboBoostUnlockModule> expected,
        IReadOnlyList<TurboBoostUnlockModule> actual)
    {
        if (expected.Count != actual.Count)
        {
            return false;
        }

        var matched = new bool[actual.Count];
        foreach (TurboBoostUnlockModule left in expected)
        {
            bool found = false;
            for (int index = 0; index < actual.Count; index++)
            {
                if (!matched[index] && ModuleEquivalent(left, actual[index]))
                {
                    matched[index] = true;
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

    private static bool ModuleEquivalent(TurboBoostUnlockModule left, TurboBoostUnlockModule right) =>
        left.FileGuid == right.FileGuid &&
        left.VolumeOffset == right.VolumeOffset &&
        left.FileOffset == right.FileOffset &&
        left.FileSize == right.FileSize &&
        left.FfsType == right.FfsType &&
        HashEquals(left.FfsSha256, right.FfsSha256) &&
        string.Equals(left.Name, right.Name, StringComparison.Ordinal) &&
        left.Disposition == right.Disposition &&
        left.Verified == right.Verified &&
        left.Families.SequenceEqual(right.Families, StringComparer.Ordinal) &&
        left.Evidence.SequenceEqual(right.Evidence);

    private static bool SameLocation(TurboBoostUnlockModule left, TurboBoostUnlockModule right) =>
        left.FileGuid == right.FileGuid &&
        left.VolumeOffset == right.VolumeOffset &&
        left.FileOffset == right.FileOffset &&
        left.FileSize == right.FileSize;

    private static bool HashEquals(string? left, string? right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
