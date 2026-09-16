using System.Security.Cryptography;

namespace XeonV3Control.Core;

/// <summary>
/// Executes only exact, catalog-authorized X99/LGA2011-3 UEFI driver transitions. Physical mutation
/// is independently re-planned immediately before writing and may be in-place, consume adjacent PI
/// FFS padding/free space, or conservatively rebuild one firmware-volume file area. A pure PEIM may
/// move only when the rebuilder proves and performs its strict direct PE32/PE32+ XIP rebase. No FV
/// resize, generic PEI/TE rebase, add/remove primitive, or cross-family replacement is exposed here.
/// </summary>
public static class X99UefiDriverImageUpdater
{
    public static byte[] Apply(
        ReadOnlySpan<byte> source,
        X99UefiDriverUpdatePlan requestedPlan,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(requestedPlan);
        token.ThrowIfCancellationRequested();
        EnsureExecutablePlanShape(requestedPlan);
        FirmwareMutationFileIo.VerifySha256(
            source,
            requestedPlan.SourceImageSha256,
            OperationError.UefiDriverUpdateSourceChanged);

        BiosImage sourceImage = BiosImageLoader.Analyze(source, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        EnsureCompleteAnalysis(sourceImage);

        X99UefiDriverUpdatePlan plan = Reauthorize(source, sourceImage, requestedPlan, token);
        byte[] candidate = X99UefiDriverUpdatePlanner.LoadCandidate(plan.CandidateId!);
        VerifyCandidateIdentity(candidate, plan);

        byte[] output = UefiFirmwareVolumeRebuilder.ApplyReplacement(
            source,
            sourceImage,
            plan.Target,
            candidate,
            plan.MutationStrategy,
            token);

        ValidateResult(source, output, sourceImage, plan, candidate, token);
        return output;
    }

    public static async Task<BiosImage> ApplyFileAsync(
        string sourcePath,
        string destinationPath,
        X99UefiDriverUpdatePlan plan,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(plan);

        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourcePath, token);
        byte[] updated = Apply(source, plan, token);
        string expectedOutputSha256 = Convert.ToHexString(SHA256.HashData(updated));

        string destination = Path.GetFullPath(destinationPath);
        bool committed = false;
        try
        {
            await FirmwareMutationFileIo.WriteNewVerifiedImageAsync(destination, updated, token);
            committed = true;
            BiosImage result = await BiosImageLoader.LoadValidatedAsync(destination, token);
            if (result.Size != updated.LongLength ||
                !string.Equals(result.Sha256, expectedOutputSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
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

    private static void EnsureExecutablePlanShape(X99UefiDriverUpdatePlan plan)
    {
        UefiDriverMutationPlan? mutation = plan.GenericPlan?.Mutation;
        if (!plan.CanApply ||
            plan.Disposition != X99UefiDriverUpdateDisposition.Ready ||
            plan.Reasons.Count != 1 ||
            !string.Equals(plan.Reasons[0], X99UefiDriverUpdateReason.None, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(plan.TransitionId) ||
            string.IsNullOrWhiteSpace(plan.CandidateId) ||
            string.IsNullOrWhiteSpace(plan.CandidateSha256) ||
            string.IsNullOrWhiteSpace(plan.SourceImageSha256) ||
            string.IsNullOrWhiteSpace(plan.Target.ExpectedSha256) ||
            plan.Target.DriverGuid == Guid.Empty ||
            plan.Target.VolumeOffset < 0 ||
            plan.Target.FileOffset < 0 ||
            plan.MutationStrategy is not (UefiFirmwareVolumeMutationStrategy.InPlace or
                UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace or
                UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume) ||
            mutation is null ||
            mutation.Kind != UefiDriverMutationKind.Replace ||
            mutation.Feasibility == UefiDriverMutationFeasibility.Unsupported)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }
    }

    private static void EnsureCompleteAnalysis(BiosImage image)
    {
        if (image.UefiDrivers.Incomplete || image.TurboBoostUnlock.Incomplete)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }
    }

    private static X99UefiDriverUpdatePlan Reauthorize(
        ReadOnlySpan<byte> source,
        BiosImage sourceImage,
        X99UefiDriverUpdatePlan requestedPlan,
        CancellationToken token)
    {
        X99UefiDriverUpdatePlan fresh = X99UefiDriverUpdatePlanner.PlanExact(
            source,
            sourceImage,
            requestedPlan.Target,
            token);
        if (!fresh.CanApply || !PlanIdentityMatches(fresh, requestedPlan))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }
        return fresh;
    }

    private static bool PlanIdentityMatches(
        X99UefiDriverUpdatePlan left,
        X99UefiDriverUpdatePlan right) =>
        left.Disposition == X99UefiDriverUpdateDisposition.Ready &&
        right.Disposition == X99UefiDriverUpdateDisposition.Ready &&
        left.MutationStrategy == right.MutationStrategy &&
        string.Equals(left.SourceImageSha256, right.SourceImageSha256, StringComparison.Ordinal) &&
        string.Equals(left.TransitionId, right.TransitionId, StringComparison.Ordinal) &&
        string.Equals(left.CandidateId, right.CandidateId, StringComparison.Ordinal) &&
        string.Equals(left.CandidateSha256, right.CandidateSha256, StringComparison.Ordinal) &&
        TargetIdentityMatches(left.Target, right.Target) &&
        MutationIdentityMatches(left.GenericPlan?.Mutation, right.GenericPlan?.Mutation);

    private static bool TargetIdentityMatches(
        UefiDriverMutationTarget left,
        UefiDriverMutationTarget right) =>
        left.DriverGuid == right.DriverGuid &&
        left.VolumeOffset == right.VolumeOffset &&
        left.FileOffset == right.FileOffset &&
        string.Equals(left.ExpectedSha256, right.ExpectedSha256, StringComparison.Ordinal);

    private static bool MutationIdentityMatches(
        UefiDriverMutationPlan? left,
        UefiDriverMutationPlan? right) =>
        left is not null && right is not null &&
        left.Kind == right.Kind &&
        left.Feasibility == right.Feasibility &&
        string.Equals(left.Reason, right.Reason, StringComparison.Ordinal) &&
        left.DriverGuid == right.DriverGuid &&
        left.VolumeOffset == right.VolumeOffset &&
        left.ExistingFileOffset == right.ExistingFileOffset &&
        left.DestinationOffset == right.DestinationOffset &&
        left.NewFileSize == right.NewFileSize &&
        left.AvailableBytes == right.AvailableBytes;

    private static void VerifyCandidateIdentity(ReadOnlySpan<byte> candidate, X99UefiDriverUpdatePlan plan)
    {
        FirmwareMutationFileIo.VerifySha256(
            candidate,
            plan.CandidateSha256!,
            OperationError.UefiDriverUpdateCatalog);
    }

    private static void ValidateResult(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        BiosImage sourceImage,
        X99UefiDriverUpdatePlan plan,
        ReadOnlySpan<byte> candidate,
        CancellationToken token)
    {
        if (output.Length != source.Length)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        BiosImage outputImage = BiosImageLoader.Analyze(output, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(outputImage);
        EnsureCompleteAnalysis(outputImage);
        if (sourceImage.Kind != outputImage.Kind ||
            sourceImage.Size != outputImage.Size ||
            !sourceImage.Regions.SequenceEqual(outputImage.Regions) ||
            !sourceImage.Volumes.SequenceEqual(outputImage.Volumes))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        UefiDriverInfo[] updatedTargets = outputImage.UefiDrivers.Drivers.Where(driver =>
            driver.FileGuid == plan.Target.DriverGuid &&
            driver.VolumeOffset == plan.Target.VolumeOffset &&
            string.Equals(driver.Sha256, plan.CandidateSha256, StringComparison.Ordinal)).ToArray();
        if (updatedTargets.Length != 1 ||
            updatedTargets[0].FileSize != candidate.Length ||
            updatedTargets[0].SecurityStatus == UefiDriverSecurityStatus.KnownVulnerable)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }

        bool allowRelocation = plan.MutationStrategy == UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume;
        if (!UnrelatedDriversEquivalent(
                sourceImage.UefiDrivers.Drivers,
                outputImage.UefiDrivers.Drivers,
                plan.Target,
                plan.CandidateSha256!,
                allowRelocation) ||
            !TurboBoostModulesEquivalent(
                sourceImage.TurboBoostUnlock.Modules,
                outputImage.TurboBoostUnlock.Modules,
                allowRelocation) ||
            !sourceImage.TurboBoostUnlock.Microcodes.SequenceEqual(outputImage.TurboBoostUnlock.Microcodes) ||
            sourceImage.TurboBoostUnlock.HasXeonE5V3CpuPatch != outputImage.TurboBoostUnlock.HasXeonE5V3CpuPatch)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateOutputInvalid);
        }
    }

    private static bool UnrelatedDriversEquivalent(
        IReadOnlyList<UefiDriverInfo> source,
        IReadOnlyList<UefiDriverInfo> output,
        UefiDriverMutationTarget target,
        string candidateSha256,
        bool allowRelocation)
    {
        UefiDriverInfo[] expected = source.Where(driver => !IsSourceTarget(driver, target)).ToArray();
        UefiDriverInfo[] actual = output.Where(driver =>
            !(driver.FileGuid == target.DriverGuid &&
              driver.VolumeOffset == target.VolumeOffset &&
              string.Equals(driver.Sha256, candidateSha256, StringComparison.Ordinal))).ToArray();
        if (expected.Length != actual.Length)
        {
            return false;
        }

        var matched = new bool[actual.Length];
        foreach (UefiDriverInfo before in expected)
        {
            bool found = false;
            for (int index = 0; index < actual.Length; index++)
            {
                if (!matched[index] && DriverEquivalent(before, actual[index], allowRelocation))
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

    private static bool IsSourceTarget(UefiDriverInfo driver, UefiDriverMutationTarget target) =>
        driver.FileGuid == target.DriverGuid &&
        driver.VolumeOffset == target.VolumeOffset &&
        driver.FileOffset == target.FileOffset &&
        string.Equals(driver.Sha256, target.ExpectedSha256, StringComparison.Ordinal);

    private static bool DriverEquivalent(UefiDriverInfo left, UefiDriverInfo right, bool allowRelocation) =>
        left.FileGuid == right.FileGuid &&
        left.Kind == right.Kind &&
        string.Equals(left.Name, right.Name, StringComparison.Ordinal) &&
        string.Equals(left.Version, right.Version, StringComparison.Ordinal) &&
        left.BuildNumber == right.BuildNumber &&
        left.VolumeOffset == right.VolumeOffset &&
        left.VolumeFileSystem == right.VolumeFileSystem &&
        (left.FileOffset == right.FileOffset || allowRelocation && !left.FixedLocation) &&
        left.FileSize == right.FileSize &&
        left.FfsHeaderSize == right.FfsHeaderSize &&
        left.FfsType == right.FfsType &&
        left.FfsAttributes == right.FfsAttributes &&
        left.RequiredDataAlignment == right.RequiredDataAlignment &&
        left.FixedLocation == right.FixedLocation &&
        left.SectionCount == right.SectionCount &&
        left.CompressionSectionCount == right.CompressionSectionCount &&
        left.GuidedSectionCount == right.GuidedSectionCount &&
        left.DependencySectionCount == right.DependencySectionCount &&
        string.Equals(left.Sha256, right.Sha256, StringComparison.Ordinal) &&
        left.SecurityStatus == right.SecurityStatus &&
        left.DependencySha256.SequenceEqual(right.DependencySha256, StringComparer.Ordinal) &&
        left.Issues.SequenceEqual(right.Issues, StringComparer.Ordinal) &&
        left.VulnerabilityIds.SequenceEqual(right.VulnerabilityIds, StringComparer.Ordinal) &&
        left.Executables.SequenceEqual(right.Executables);

    private static bool TurboBoostModulesEquivalent(
        IReadOnlyList<TurboBoostUnlockModule> expected,
        IReadOnlyList<TurboBoostUnlockModule> actual,
        bool allowRelocation)
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
                if (!matched[index] && TurboBoostModuleEquivalent(left, actual[index], allowRelocation))
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

    private static bool TurboBoostModuleEquivalent(
        TurboBoostUnlockModule left,
        TurboBoostUnlockModule right,
        bool allowRelocation) =>
        left.FileGuid == right.FileGuid &&
        left.VolumeOffset == right.VolumeOffset &&
        (left.FileOffset == right.FileOffset || allowRelocation) &&
        left.FileSize == right.FileSize &&
        left.FfsType == right.FfsType &&
        string.Equals(left.FfsSha256, right.FfsSha256, StringComparison.Ordinal) &&
        string.Equals(left.Name, right.Name, StringComparison.Ordinal) &&
        left.Disposition == right.Disposition &&
        left.Verified == right.Verified &&
        left.Families.SequenceEqual(right.Families, StringComparer.Ordinal) &&
        left.Evidence.SequenceEqual(right.Evidence);
}
