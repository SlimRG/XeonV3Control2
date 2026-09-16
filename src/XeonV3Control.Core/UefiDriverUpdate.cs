namespace XeonV3Control.Core;

public enum UefiDriverUpdateDisposition
{
    Ready,
    RequiresReview,
    Blocked
}

public static class UefiDriverUpdateReason
{
    public const string None = nameof(None);
    public const string TargetNotFound = nameof(TargetNotFound);
    public const string TargetChanged = nameof(TargetChanged);
    public const string InvalidCandidate = nameof(InvalidCandidate);
    public const string NoChange = nameof(NoChange);
    public const string KnownVulnerableCandidate = nameof(KnownVulnerableCandidate);
    public const string CandidateInspectionIncomplete = nameof(CandidateInspectionIncomplete);
    public const string CandidateRequiresReview = nameof(CandidateRequiresReview);
    public const string ArchitectureMismatch = nameof(ArchitectureMismatch);
    public const string SubsystemMismatch = nameof(SubsystemMismatch);
    public const string ExecutableLayoutChanged = nameof(ExecutableLayoutChanged);
    public const string SectionLayoutChanged = nameof(SectionLayoutChanged);
    public const string DependencyExpressionChanged = nameof(DependencyExpressionChanged);
    public const string NxRegression = nameof(NxRegression);
    public const string DynamicBaseRegression = nameof(DynamicBaseRegression);
    public const string WritableExecutableRegression = nameof(WritableExecutableRegression);
    public const string FfsMetadataChanged = nameof(FfsMetadataChanged);
    public const string VersionOlder = nameof(VersionOlder);
    public const string BuildNumberOlder = nameof(BuildNumberOlder);
    public const string VersionNotComparable = nameof(VersionNotComparable);
    public const string VersionUnchanged = nameof(VersionUnchanged);
    public const string VersionSignalsConflict = nameof(VersionSignalsConflict);
    public const string RepackRequired = nameof(RepackRequired);
    public const string MutationBlocked = nameof(MutationBlocked);
}

/// <summary>
/// High-level update assessment. It never mutates firmware; it validates the exact current
/// driver instance, inspects the candidate, checks compatibility/security regressions and
/// delegates physical placement feasibility to <see cref="UefiDriverMutationPlanner"/>.
/// </summary>
public sealed record UefiDriverUpdatePlan(
    UefiDriverUpdateDisposition Disposition,
    IReadOnlyList<string> Reasons,
    UefiDriverMutationTarget Target,
    UefiDriverInfo? Current,
    UefiDriverInfo? Candidate,
    UefiDriverMutationPlan? Mutation);

public static class UefiDriverUpdatePlanner
{
    public static UefiDriverUpdatePlan Plan(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        ReadOnlySpan<byte> candidateFfs,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(target);
        UefiDriverMutationPlanner.EnsureImageMatches(source, image);

        UefiDriverInfo? current = image.UefiDrivers.Drivers.SingleOrDefault(driver =>
            driver.FileGuid == target.DriverGuid &&
            driver.VolumeOffset == target.VolumeOffset &&
            driver.FileOffset == target.FileOffset);
        if (current is null)
        {
            return Blocked(target, UefiDriverUpdateReason.TargetNotFound);
        }

        string expectedHash;
        try
        {
            expectedHash = Sha256Identity.Normalize(target.ExpectedSha256, UefiDriverUpdateReason.TargetChanged);
        }
        catch (InvalidDataException)
        {
            return Blocked(target, UefiDriverUpdateReason.TargetChanged, current);
        }
        if (!string.Equals(expectedHash, current.Sha256, StringComparison.Ordinal))
        {
            return Blocked(target, UefiDriverUpdateReason.TargetChanged, current);
        }

        FirmwareVolume? volume = image.Volumes.SingleOrDefault(item => item.Offset == target.VolumeOffset);
        if (volume is null ||
            !UefiFfsVolumeScanner.TryGetLayout(source, volume, out UefiFfsVolumeLayout layout) ||
            !UefiDriverInspector.TryInspectFfs(
                candidateFfs,
                layout.EraseByte,
                volume.Offset,
                volume.FileSystem,
                target.FileOffset,
                token,
                out UefiDriverInfo candidate))
        {
            return Blocked(target, UefiDriverUpdateReason.InvalidCandidate, current);
        }

        if (candidate.FileGuid != current.FileGuid || candidate.FfsType != current.FfsType)
        {
            return Blocked(target, UefiDriverUpdateReason.InvalidCandidate, current, candidate);
        }
        if (string.Equals(candidate.Sha256, current.Sha256, StringComparison.Ordinal))
        {
            return Blocked(target, UefiDriverUpdateReason.NoChange, current, candidate);
        }

        var blocked = new HashSet<string>(StringComparer.Ordinal);
        var review = new HashSet<string>(StringComparer.Ordinal);

        EvaluateSecurity(current, candidate, blocked, review);
        EvaluateExecutables(current, candidate, blocked, review);
        EvaluateFfsMetadata(current, candidate, review);
        EvaluateVersion(current, candidate, blocked, review);

        UefiDriverMutationPlan mutation = UefiDriverMutationPlanner.PlanReplaceValidatedSource(
            source,
            image,
            target,
            candidateFfs,
            token);
        if (mutation.Feasibility == UefiDriverMutationFeasibility.Unsupported)
        {
            blocked.Add(UefiDriverUpdateReason.MutationBlocked);
        }
        else if (mutation.Feasibility == UefiDriverMutationFeasibility.RequiresRepack)
        {
            review.Add(UefiDriverUpdateReason.RepackRequired);
        }

        if (blocked.Count != 0)
        {
            return new(
                UefiDriverUpdateDisposition.Blocked,
                Ordered(blocked, review),
                target,
                current,
                candidate,
                mutation);
        }
        if (review.Count != 0)
        {
            return new(
                UefiDriverUpdateDisposition.RequiresReview,
                Ordered(review),
                target,
                current,
                candidate,
                mutation);
        }

        return new(
            UefiDriverUpdateDisposition.Ready,
            [UefiDriverUpdateReason.None],
            target,
            current,
            candidate,
            mutation);
    }

    private static void EvaluateSecurity(
        UefiDriverInfo current,
        UefiDriverInfo candidate,
        HashSet<string> blocked,
        HashSet<string> review)
    {
        if (candidate.SecurityStatus == UefiDriverSecurityStatus.KnownVulnerable)
        {
            blocked.Add(UefiDriverUpdateReason.KnownVulnerableCandidate);
        }
        else if (candidate.SecurityStatus == UefiDriverSecurityStatus.Unknown)
        {
            review.Add(UefiDriverUpdateReason.CandidateInspectionIncomplete);
        }
        else if (candidate.SecurityStatus == UefiDriverSecurityStatus.ReviewRecommended)
        {
            review.Add(UefiDriverUpdateReason.CandidateRequiresReview);
        }

        bool currentWx = current.Executables.Any(executable => executable.WritableExecutableSection);
        bool candidateWx = candidate.Executables.Any(executable => executable.WritableExecutableSection);
        if (!currentWx && candidateWx)
        {
            blocked.Add(UefiDriverUpdateReason.WritableExecutableRegression);
        }
    }

    private static void EvaluateExecutables(
        UefiDriverInfo current,
        UefiDriverInfo candidate,
        HashSet<string> blocked,
        HashSet<string> review)
    {
        HashSet<UefiMachine> currentMachines = KnownMachines(current);
        HashSet<UefiMachine> candidateMachines = KnownMachines(candidate);
        if (currentMachines.Count != 0 && candidateMachines.Count != 0 && !currentMachines.SetEquals(candidateMachines))
        {
            blocked.Add(UefiDriverUpdateReason.ArchitectureMismatch);
        }
        else if ((currentMachines.Count == 0) != (candidateMachines.Count == 0))
        {
            review.Add(UefiDriverUpdateReason.ArchitectureMismatch);
        }

        HashSet<UefiExecutableSubsystem> currentSubsystems = KnownSubsystems(current);
        HashSet<UefiExecutableSubsystem> candidateSubsystems = KnownSubsystems(candidate);
        if (currentSubsystems.Count != 0 && candidateSubsystems.Count != 0 && !currentSubsystems.SetEquals(candidateSubsystems))
        {
            blocked.Add(UefiDriverUpdateReason.SubsystemMismatch);
        }
        else if ((currentSubsystems.Count == 0) != (candidateSubsystems.Count == 0))
        {
            review.Add(UefiDriverUpdateReason.SubsystemMismatch);
        }

        HashSet<UefiExecutableFormat> currentFormats = current.Executables
            .Where(executable => executable.StructurallyValid)
            .Select(executable => executable.Format)
            .ToHashSet();
        HashSet<UefiExecutableFormat> candidateFormats = candidate.Executables
            .Where(executable => executable.StructurallyValid)
            .Select(executable => executable.Format)
            .ToHashSet();
        if (current.Executables.Count != candidate.Executables.Count ||
            current.Executables.Sum(executable => executable.SectionCount) !=
            candidate.Executables.Sum(executable => executable.SectionCount) ||
            !currentFormats.SetEquals(candidateFormats))
        {
            review.Add(UefiDriverUpdateReason.ExecutableLayoutChanged);
        }
        if (current.SectionCount != candidate.SectionCount ||
            current.CompressionSectionCount != candidate.CompressionSectionCount ||
            current.GuidedSectionCount != candidate.GuidedSectionCount ||
            current.DependencySectionCount != candidate.DependencySectionCount)
        {
            review.Add(UefiDriverUpdateReason.SectionLayoutChanged);
        }
        if (!current.DependencySha256.SequenceEqual(candidate.DependencySha256, StringComparer.Ordinal))
        {
            review.Add(UefiDriverUpdateReason.DependencyExpressionChanged);
        }

        foreach (UefiExecutableInfo before in current.Executables.Where(item => item.StructurallyValid))
        {
            UefiExecutableInfo[] after = candidate.Executables
                .Where(item => item.StructurallyValid && item.Machine == before.Machine && item.Subsystem == before.Subsystem)
                .ToArray();
            if (after.Length == 0)
            {
                continue;
            }
            if (before.NxCompatible == true && after.Any(item => item.NxCompatible == false))
            {
                blocked.Add(UefiDriverUpdateReason.NxRegression);
            }
            if (before.DynamicBase == true && after.Any(item => item.DynamicBase == false))
            {
                blocked.Add(UefiDriverUpdateReason.DynamicBaseRegression);
            }
        }
    }

    private static void EvaluateFfsMetadata(
        UefiDriverInfo current,
        UefiDriverInfo candidate,
        HashSet<string> review)
    {
        if (current.FfsAttributes != candidate.FfsAttributes ||
            current.FfsHeaderSize != candidate.FfsHeaderSize ||
            current.RequiredDataAlignment != candidate.RequiredDataAlignment ||
            current.FixedLocation != candidate.FixedLocation)
        {
            review.Add(UefiDriverUpdateReason.FfsMetadataChanged);
        }
    }

    private static void EvaluateVersion(
        UefiDriverInfo current,
        UefiDriverInfo candidate,
        HashSet<string> blocked,
        HashSet<string> review)
    {
        int? versionComparison = CompareVersion(current.Version, candidate.Version);
        int? buildComparison = current.BuildNumber.HasValue && candidate.BuildNumber.HasValue
            ? candidate.BuildNumber.Value.CompareTo(current.BuildNumber.Value)
            : null;

        if (versionComparison < 0)
        {
            blocked.Add(UefiDriverUpdateReason.VersionOlder);
        }
        if (buildComparison < 0)
        {
            blocked.Add(UefiDriverUpdateReason.BuildNumberOlder);
        }
        if (versionComparison.HasValue && buildComparison.HasValue &&
            Math.Sign(versionComparison.Value) != 0 && Math.Sign(buildComparison.Value) != 0 &&
            Math.Sign(versionComparison.Value) != Math.Sign(buildComparison.Value))
        {
            review.Add(UefiDriverUpdateReason.VersionSignalsConflict);
        }

        if (!versionComparison.HasValue && !buildComparison.HasValue)
        {
            review.Add(UefiDriverUpdateReason.VersionNotComparable);
        }
        else if ((versionComparison is null or 0) && (buildComparison is null or 0))
        {
            review.Add(UefiDriverUpdateReason.VersionUnchanged);
        }
    }

    private static int? CompareVersion(string? current, string? candidate)
    {
        return TryParseVersion(current, out Version? currentVersion) &&
               TryParseVersion(candidate, out Version? candidateVersion)
            ? candidateVersion!.CompareTo(currentVersion!)
            : null;
    }

    private static bool TryParseVersion(string? value, out Version? version)
    {
        version = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }
        string normalized = value.Trim();
        if (normalized.Length > 1 && (normalized[0] is 'v' or 'V'))
        {
            normalized = normalized[1..];
        }
        if (normalized.Length == 0 || normalized.Any(character => !char.IsAsciiDigit(character) && character != '.'))
        {
            return false;
        }
        return Version.TryParse(normalized, out version);
    }

    private static HashSet<UefiMachine> KnownMachines(UefiDriverInfo driver) => driver.Executables
        .Where(executable => executable.StructurallyValid && executable.Machine != UefiMachine.Unknown)
        .Select(executable => executable.Machine)
        .ToHashSet();

    private static HashSet<UefiExecutableSubsystem> KnownSubsystems(UefiDriverInfo driver) => driver.Executables
        .Where(executable => executable.StructurallyValid && executable.Subsystem != UefiExecutableSubsystem.Unknown)
        .Select(executable => executable.Subsystem)
        .ToHashSet();

    private static string[] Ordered(params IEnumerable<string>[] groups) => groups
        .SelectMany(group => group)
        .Distinct(StringComparer.Ordinal)
        .OrderBy(reason => reason, StringComparer.Ordinal)
        .ToArray();

    private static UefiDriverUpdatePlan Blocked(
        UefiDriverMutationTarget target,
        string reason,
        UefiDriverInfo? current = null,
        UefiDriverInfo? candidate = null) =>
        new(UefiDriverUpdateDisposition.Blocked, [reason], target, current, candidate, null);
}
