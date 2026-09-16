using System.Security.Cryptography;

namespace XeonV3Control.Core;

public enum TurboBoostUnlockModuleDisposition
{
    Retained,
    Foreign,
    Unclassified
}

public enum TurboBoostForeignRemovalStatus
{
    NotApplicable,
    RequiresBaselineByteAuthorization,
    Ready,
    Unsupported
}

public enum TurboBoostForeignRemovalOperation
{
    None,
    RemoveInjectedFfs,
    RestoreBaselineFfs
}

public enum TurboBoostForeignRemovalReason
{
    None,
    RetainedFamily,
    UnverifiedCandidate,
    AmbiguousFamily,
    DriverNotLocated,
    SourceAnalysisIncomplete,
    BaselineAnalysisIncomplete,
    BaselineContainsUnlock,
    BaselineImageMismatch,
    VolumeLayoutMismatch,
    ComplexTopologyChange,
    InjectionGroupContainsNonForeignFiles,
    BaselineContradiction,
    BaselineTopologyEvidenceInsufficient,
    BaselineByteAuthorizationRequired,
    MutationPlannerRejected
}

public sealed record TurboBoostForeignRemovalPlan(
    TurboBoostForeignRemovalStatus Status,
    TurboBoostForeignRemovalOperation Operation,
    TurboBoostForeignRemovalReason Reason,
    string SourceImageSha256,
    Guid FileGuid,
    long VolumeOffset,
    long FileOffset,
    int FileSize,
    string FfsSha256,
    string? BaselineImageSha256,
    Guid? BaselineFileGuid,
    long? BaselineFileOffset,
    int? BaselineFileSize,
    string? BaselineFfsSha256,
    UefiDriverMutationFeasibility? MutationFeasibility)
{
    public bool TopologyAuthorized => Status is
        TurboBoostForeignRemovalStatus.Ready or
        TurboBoostForeignRemovalStatus.RequiresBaselineByteAuthorization;

    public bool CanExecute => Status == TurboBoostForeignRemovalStatus.Ready;
}

/// <summary>
/// Immutable result of planning foreign Unlock cleanup against exact source and clean-baseline files.
/// Only hashes, paths and plans are retained; firmware byte arrays are released after planning.
/// </summary>
public sealed record TurboBoostForeignRemovalPlanningResult(
    string SourceFilePath,
    string SourceImageSha256,
    string BaselineFilePath,
    string BaselineImageSha256,
    IReadOnlyList<TurboBoostForeignRemovalPlan> Plans);

public sealed record TurboBoostUnlockModule(
    Guid FileGuid,
    long VolumeOffset,
    long FileOffset,
    int FileSize,
    byte FfsType,
    string FfsSha256,
    string? Name,
    IReadOnlyList<string> Families,
    TurboBoostUnlockModuleDisposition Disposition,
    bool Verified,
    IReadOnlyList<TurboBoostUnlockEvidenceKind> Evidence,
    TurboBoostForeignRemovalPlan RemovalPlan);

internal readonly record struct TurboBoostFfsContext(
    Guid FileGuid,
    long VolumeOffset,
    long FileOffset,
    int FileSize,
    byte FfsType,
    byte FfsAttributes,
    string FfsSha256);

internal enum TurboBoostFfsTopologyKind
{
    InjectedSingleton,
    SameIdentityModified,
    ReplacedSingleton,
    Complex
}

internal readonly record struct TurboBoostFfsIdentity(Guid Guid, byte Type);

internal readonly record struct TurboBoostFfsTopologyMatch(
    TurboBoostFfsTopologyKind Kind,
    int BaselineIndex);

internal readonly record struct TurboBoostFfsChangeWindow(
    int SourceStart,
    int SourceCount,
    int BaselineStart,
    int BaselineCount);

internal static class TurboBoostUnlockModulePlanner
{
    internal static TurboBoostUnlockModule[] Build(
        string sourceImageSha256,
        IReadOnlyList<TurboBoostUnlockFinding> findings,
        IReadOnlyDictionary<(long VolumeOffset, long FileOffset), TurboBoostFfsContext> files,
        UefiDriverReport driverReport,
        TurboBoostUnlockIdentityCatalog catalog,
        bool sourceAnalysisIncomplete)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceImageSha256);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(driverReport);
        ArgumentNullException.ThrowIfNull(catalog);

        var modules = new List<TurboBoostUnlockModule>();
        foreach (IGrouping<(long VolumeOffset, long FileOffset), TurboBoostUnlockFinding> group in findings
                     .Where(item => item.VolumeOffset.HasValue && item.FileOffset.HasValue && item.FileGuid.HasValue)
                     .GroupBy(item => (item.VolumeOffset!.Value, item.FileOffset!.Value)))
        {
            if (!files.TryGetValue(group.Key, out TurboBoostFfsContext file))
            {
                continue;
            }

            string[] families = group
                .Select(item => item.Family)
                .Where(family => !string.IsNullOrWhiteSpace(family))
                .Select(family => family!)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(family => family, StringComparer.Ordinal)
                .ToArray();
            TurboBoostUnlockEvidenceKind[] evidence = group
                .Select(item => item.Evidence)
                .Distinct()
                .OrderBy(item => item)
                .ToArray();
            bool verified = evidence.Any(IsVerifiedEvidence);

            TurboBoostUnlockModuleDisposition disposition;
            TurboBoostForeignRemovalReason initialReason;
            if (!verified)
            {
                disposition = TurboBoostUnlockModuleDisposition.Unclassified;
                initialReason = TurboBoostForeignRemovalReason.UnverifiedCandidate;
            }
            else if (families.Length != 1)
            {
                disposition = TurboBoostUnlockModuleDisposition.Unclassified;
                initialReason = TurboBoostForeignRemovalReason.AmbiguousFamily;
            }
            else if (catalog.IsRetainedFamily(families[0]))
            {
                disposition = TurboBoostUnlockModuleDisposition.Retained;
                initialReason = TurboBoostForeignRemovalReason.RetainedFamily;
            }
            else
            {
                disposition = TurboBoostUnlockModuleDisposition.Foreign;
                initialReason = TurboBoostForeignRemovalReason.None;
            }

            UefiDriverInfo? driver = driverReport.Drivers.FirstOrDefault(item =>
                item.VolumeOffset == file.VolumeOffset &&
                item.FileOffset == file.FileOffset &&
                item.FileGuid == file.FileGuid);

            bool directRemovalReady = disposition == TurboBoostUnlockModuleDisposition.Foreign &&
                !sourceAnalysisIncomplete &&
                !AmiSecureBootSpecification.IsFixed(file.FfsAttributes);
            TurboBoostForeignRemovalPlan plan = new(
                directRemovalReady
                    ? TurboBoostForeignRemovalStatus.Ready
                    : disposition == TurboBoostUnlockModuleDisposition.Foreign
                        ? TurboBoostForeignRemovalStatus.Unsupported
                        : TurboBoostForeignRemovalStatus.NotApplicable,
                directRemovalReady
                    ? TurboBoostForeignRemovalOperation.RemoveInjectedFfs
                    : TurboBoostForeignRemovalOperation.None,
                directRemovalReady
                    ? TurboBoostForeignRemovalReason.None
                    : disposition == TurboBoostUnlockModuleDisposition.Foreign
                        ? sourceAnalysisIncomplete
                            ? TurboBoostForeignRemovalReason.SourceAnalysisIncomplete
                            : TurboBoostForeignRemovalReason.MutationPlannerRejected
                        : initialReason,
                sourceImageSha256,
                file.FileGuid,
                file.VolumeOffset,
                file.FileOffset,
                file.FileSize,
                file.FfsSha256,
                null,
                null,
                null,
                null,
                null,
                directRemovalReady ? UefiDriverMutationFeasibility.InPlace : null);

            modules.Add(new(
                file.FileGuid,
                file.VolumeOffset,
                file.FileOffset,
                file.FileSize,
                file.FfsType,
                file.FfsSha256,
                driver?.Name,
                families,
                disposition,
                verified,
                evidence,
                plan));
        }

        return modules
            .OrderBy(item => item.FileOffset)
            .ThenBy(item => item.FileGuid)
            .ToArray();
    }

    internal static bool IsVerifiedEvidence(TurboBoostUnlockEvidenceKind evidence) => evidence is
        TurboBoostUnlockEvidenceKind.ExactFfsIdentity or
        TurboBoostUnlockEvidenceKind.ExactExecutableIdentity or
        TurboBoostUnlockEvidenceKind.KnownFamilySemantics;
}

/// <summary>
/// Prepares optional baseline-comparison plans for verified foreign Turbo Boost Unlock modules.
/// Direct removal of a verified Foreign FFS does not require a baseline; this planner is retained
/// only to classify a module against a known-clean image when a future byte restore may be needed.
/// </summary>
public static class TurboBoostForeignUnlockRemovalPlanner
{
    /// <summary>
    /// Loads the exact source and clean-baseline images once, validates both, and builds topology-bound
    /// cleanup plans. The result keeps no firmware byte buffers alive.
    /// </summary>
    public static async Task<TurboBoostForeignRemovalPlanningResult> PlanFilesAsync(
        string sourcePath,
        string baselinePath,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(baselinePath);

        string sourceFullPath = Path.GetFullPath(sourcePath);
        string baselineFullPath = Path.GetFullPath(baselinePath);
        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourceFullPath, token);
        byte[] baseline = await FirmwareMutationFileIo.ReadImageAsync(baselineFullPath, token);
        token.ThrowIfCancellationRequested();

        BiosImage sourceImage = BiosImageLoader.Analyze(source, sourceFullPath, token);
        BiosImage baselineImage = BiosImageLoader.Analyze(baseline, baselineFullPath, token);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        BiosImageLoader.EnsureValidBiosImage(baselineImage);

        IReadOnlyList<TurboBoostForeignRemovalPlan> plans = PlanAgainstBaseline(
            source, sourceImage, baseline, baselineImage, token);
        return new(
            sourceFullPath,
            sourceImage.Sha256,
            baselineFullPath,
            baselineImage.Sha256,
            plans.ToArray());
    }

    public static IReadOnlyList<TurboBoostForeignRemovalPlan> PlanAgainstBaseline(
        ReadOnlySpan<byte> source,
        BiosImage sourceImage,
        ReadOnlySpan<byte> baseline,
        BiosImage baselineImage,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(sourceImage);
        ArgumentNullException.ThrowIfNull(baselineImage);
        UefiDriverMutationPlanner.EnsureImageMatches(source, sourceImage);
        UefiDriverMutationPlanner.EnsureImageMatches(baseline, baselineImage);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        BiosImageLoader.EnsureValidBiosImage(baselineImage);

        TurboBoostUnlockModule[] foreign = sourceImage.TurboBoostUnlock.Modules
            .Where(item => item.Disposition == TurboBoostUnlockModuleDisposition.Foreign && item.Verified)
            .ToArray();
        if (foreign.Length == 0)
        {
            return [];
        }

        if (sourceImage.TurboBoostUnlock.Incomplete || sourceImage.UefiDrivers.Incomplete)
        {
            return foreign.Select(item => Failure(
                item,
                TurboBoostForeignRemovalReason.SourceAnalysisIncomplete,
                baselineImage.Sha256)).ToArray();
        }

        if (baselineImage.TurboBoostUnlock.Incomplete || baselineImage.UefiDrivers.Incomplete)
        {
            return foreign.Select(item => Failure(
                item,
                TurboBoostForeignRemovalReason.BaselineAnalysisIncomplete,
                baselineImage.Sha256)).ToArray();
        }

        if (baselineImage.Size != sourceImage.Size || !HasCompatibleImageLayout(sourceImage, baselineImage))
        {
            return foreign.Select(item => Failure(
                item,
                TurboBoostForeignRemovalReason.BaselineImageMismatch,
                baselineImage.Sha256)).ToArray();
        }

        if (baselineImage.TurboBoostUnlock.Status != TurboBoostUnlockStatus.NotDetected ||
            baselineImage.TurboBoostUnlock.Modules.Count != 0)
        {
            return foreign.Select(item => Failure(
                item,
                TurboBoostForeignRemovalReason.BaselineContainsUnlock,
                baselineImage.Sha256)).ToArray();
        }

        var result = new List<TurboBoostForeignRemovalPlan>(foreign.Length);
        foreach (TurboBoostUnlockModule module in foreign)
        {
            token.ThrowIfCancellationRequested();
            result.Add(PlanOne(source, sourceImage, baseline, baselineImage, module, token));
        }
        return result;
    }

    internal static TurboBoostFfsTopologyMatch ClassifyTopology(
        IReadOnlyList<TurboBoostFfsIdentity> source,
        IReadOnlyList<TurboBoostFfsIdentity> baseline,
        int targetIndex)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(baseline);
        if ((uint)targetIndex >= (uint)source.Count)
        {
            return new(TurboBoostFfsTopologyKind.Complex, -1);
        }

        IReadOnlyList<(int Source, int Baseline)>? matches = BuildLcsMatches(source, baseline);
        if (matches is null)
        {
            return new(TurboBoostFfsTopologyKind.Complex, -1);
        }

        foreach ((int Source, int Baseline) match in matches)
        {
            if (match.Source == targetIndex)
            {
                return new(TurboBoostFfsTopologyKind.SameIdentityModified, match.Baseline);
            }
        }

        if (!TryGetChangeWindow(matches, source.Count, baseline.Count, targetIndex, out TurboBoostFfsChangeWindow window))
        {
            return new(TurboBoostFfsTopologyKind.Complex, -1);
        }
        if (window.SourceCount == 1 && window.BaselineCount == 0)
        {
            return new(TurboBoostFfsTopologyKind.InjectedSingleton, -1);
        }
        if (window.SourceCount == 1 && window.BaselineCount == 1)
        {
            return new(TurboBoostFfsTopologyKind.ReplacedSingleton, window.BaselineStart);
        }
        return new(TurboBoostFfsTopologyKind.Complex, -1);
    }

    private static bool TryGetChangeWindow(
        IReadOnlyList<(int Source, int Baseline)> matches,
        int sourceCount,
        int baselineCount,
        int targetIndex,
        out TurboBoostFfsChangeWindow window)
    {
        window = default;
        int previousSource = -1;
        int previousBaseline = -1;
        int nextSource = sourceCount;
        int nextBaseline = baselineCount;
        foreach ((int Source, int Baseline) match in matches)
        {
            if (match.Source < targetIndex)
            {
                previousSource = match.Source;
                previousBaseline = match.Baseline;
                continue;
            }
            if (match.Source > targetIndex)
            {
                nextSource = match.Source;
                nextBaseline = match.Baseline;
                break;
            }
        }

        int sourceStart = previousSource + 1;
        int sourceWindowCount = nextSource - sourceStart;
        int baselineStart = previousBaseline + 1;
        int baselineWindowCount = nextBaseline - baselineStart;
        if (targetIndex < sourceStart || targetIndex >= sourceStart + sourceWindowCount)
        {
            return false;
        }

        window = new(sourceStart, sourceWindowCount, baselineStart, baselineWindowCount);
        return true;
    }

    private static IReadOnlyList<(int Source, int Baseline)>? BuildLcsMatches(
        IReadOnlyList<TurboBoostFfsIdentity> source,
        IReadOnlyList<TurboBoostFfsIdentity> baseline)
    {
        const int maximumCells = 1_000_000;
        long cells = (long)(source.Count + 1) * (baseline.Count + 1);
        if (cells > maximumCells)
        {
            return null;
        }

        int columns = baseline.Count + 1;
        var lengths = new int[checked((source.Count + 1) * columns)];
        for (int sourceIndex = source.Count - 1; sourceIndex >= 0; sourceIndex--)
        {
            int row = sourceIndex * columns;
            int nextRow = (sourceIndex + 1) * columns;
            for (int baselineIndex = baseline.Count - 1; baselineIndex >= 0; baselineIndex--)
            {
                lengths[row + baselineIndex] = source[sourceIndex] == baseline[baselineIndex]
                    ? checked(lengths[nextRow + baselineIndex + 1] + 1)
                    : Math.Max(lengths[nextRow + baselineIndex], lengths[row + baselineIndex + 1]);
            }
        }

        var matches = new List<(int Source, int Baseline)>();
        int i = 0;
        int j = 0;
        while (i < source.Count && j < baseline.Count)
        {
            if (source[i] == baseline[j])
            {
                matches.Add((i, j));
                i++;
                j++;
                continue;
            }

            int skipSource = lengths[(i + 1) * columns + j];
            int skipBaseline = lengths[i * columns + j + 1];
            if (skipSource >= skipBaseline)
            {
                i++;
            }
            else
            {
                j++;
            }
        }
        return matches;
    }

    private static TurboBoostForeignRemovalPlan PlanOne(
        ReadOnlySpan<byte> source,
        BiosImage sourceImage,
        ReadOnlySpan<byte> baseline,
        BiosImage baselineImage,
        TurboBoostUnlockModule module,
        CancellationToken token)
    {
        FirmwareVolume? sourceVolume = sourceImage.Volumes.FirstOrDefault(item => item.Offset == module.VolumeOffset);
        if (sourceVolume is null ||
            !UefiFfsVolumeScanner.TryReadFiles(
                source,
                sourceVolume,
                token,
                out UefiFfsVolumeLayout sourceVolumeLayout,
                out IReadOnlyList<UefiFfsFileLocation> sourceFilesRaw))
        {
            return Failure(module, TurboBoostForeignRemovalReason.DriverNotLocated, baselineImage.Sha256);
        }

        UefiFfsFileLocation[] sourceFiles = sourceFilesRaw.Where(IsActiveFile).ToArray();
        int targetIndex = Array.FindIndex(sourceFiles, item =>
            item.Offset == module.FileOffset && item.Guid == module.FileGuid && item.Size == module.FileSize);
        if (targetIndex < 0)
        {
            return Failure(module, TurboBoostForeignRemovalReason.DriverNotLocated, baselineImage.Sha256);
        }

        UefiFfsFileLocation target = sourceFiles[targetIndex];
        if (!HashMatches(source, target, module.FfsSha256))
        {
            return Failure(module, TurboBoostForeignRemovalReason.DriverNotLocated, baselineImage.Sha256);
        }

        FirmwareVolume? baselineVolume = baselineImage.Volumes.FirstOrDefault(item =>
            item.Offset == sourceVolume.Offset &&
            item.Length == sourceVolume.Length &&
            item.FileSystem == sourceVolume.FileSystem);
        if (baselineVolume is null ||
            !UefiFfsVolumeScanner.TryReadFiles(
                baseline,
                baselineVolume,
                token,
                out UefiFfsVolumeLayout baselineVolumeLayout,
                out IReadOnlyList<UefiFfsFileLocation> baselineFilesRaw) ||
            sourceVolumeLayout != baselineVolumeLayout)
        {
            return Failure(module, TurboBoostForeignRemovalReason.VolumeLayoutMismatch, baselineImage.Sha256);
        }

        UefiFfsFileLocation[] baselineFiles = baselineFilesRaw.Where(IsActiveFile).ToArray();
        HashSet<long> retainedOffsets = sourceImage.TurboBoostUnlock.RetainedUnlockModules
            .Where(item => item.Verified && item.VolumeOffset == module.VolumeOffset)
            .Select(item => item.FileOffset)
            .ToHashSet();
        UefiFfsFileLocation[] comparisonSourceFiles = sourceFiles
            .Where(item => !retainedOffsets.Contains(item.Offset))
            .ToArray();
        int comparisonTargetIndex = Array.FindIndex(comparisonSourceFiles, item => item.Offset == module.FileOffset);
        if (comparisonTargetIndex < 0)
        {
            return Failure(module, TurboBoostForeignRemovalReason.DriverNotLocated, baselineImage.Sha256);
        }

        TurboBoostFfsIdentity[] sourceKeys = comparisonSourceFiles.Select(ToIdentity).ToArray();
        TurboBoostFfsIdentity[] baselineKeys = baselineFiles.Select(ToIdentity).ToArray();
        IReadOnlyList<(int Source, int Baseline)>? topologyMatches = BuildLcsMatches(sourceKeys, baselineKeys);
        if (topologyMatches is null)
        {
            return Failure(module, TurboBoostForeignRemovalReason.ComplexTopologyChange, baselineImage.Sha256);
        }

        TurboBoostFfsTopologyMatch topology = ClassifyTopology(sourceKeys, baselineKeys, comparisonTargetIndex);
        bool hasChangeWindow = TryGetChangeWindow(
            topologyMatches,
            sourceKeys.Length,
            baselineKeys.Length,
            comparisonTargetIndex,
            out TurboBoostFfsChangeWindow changeWindow);
        bool verifiedForeignInjectionGroup = false;
        if (topology.Kind == TurboBoostFfsTopologyKind.Complex &&
            hasChangeWindow &&
            changeWindow.SourceCount > 1 &&
            changeWindow.BaselineCount == 0)
        {
            verifiedForeignInjectionGroup = IsVerifiedForeignInjectionGroup(
                comparisonSourceFiles,
                changeWindow,
                sourceImage.TurboBoostUnlock.ForeignUnlockModules);
            if (!verifiedForeignInjectionGroup)
            {
                return Failure(
                    module,
                    TurboBoostForeignRemovalReason.InjectionGroupContainsNonForeignFiles,
                    baselineImage.Sha256);
            }
        }

        if (topology.Kind == TurboBoostFfsTopologyKind.InjectedSingleton || verifiedForeignInjectionGroup)
        {
            if (!hasChangeWindow ||
                !HasStrongInjectionTopologyEvidence(
                    source,
                    baseline,
                    comparisonSourceFiles,
                    baselineFiles,
                    topologyMatches,
                    changeWindow))
            {
                return Failure(
                    module,
                    TurboBoostForeignRemovalReason.BaselineTopologyEvidenceInsufficient,
                    baselineImage.Sha256);
            }
            var targetIdentity = new UefiFfsRemovalTarget(
                module.FileGuid,
                module.VolumeOffset,
                module.FileOffset,
                module.FileSize,
                module.FfsType,
                module.FfsSha256);
            UefiFfsRemovalPreflight lowLevel = UefiFfsMutationPlanner.PlanRemoveExact(
                source,
                sourceImage,
                targetIdentity,
                token);
            if (!lowLevel.IsReady)
            {
                return Failure(module, TurboBoostForeignRemovalReason.MutationPlannerRejected, baselineImage.Sha256);
            }
            if (!module.RemovalPlan.CanExecute ||
                module.RemovalPlan.Operation != TurboBoostForeignRemovalOperation.RemoveInjectedFfs ||
                module.RemovalPlan.MutationFeasibility != UefiDriverMutationFeasibility.InPlace)
            {
                return Failure(module, TurboBoostForeignRemovalReason.MutationPlannerRejected, baselineImage.Sha256);
            }

            // A clean baseline can strengthen topology knowledge, but it is not an execution dependency.
            // Return the source-authorized plan so the executor never reads or copies baseline bytes.
            return module.RemovalPlan;
        }

        if (topology.Kind is TurboBoostFfsTopologyKind.SameIdentityModified or TurboBoostFfsTopologyKind.ReplacedSingleton)
        {
            if ((uint)topology.BaselineIndex >= (uint)baselineFiles.Length)
            {
                return Failure(module, TurboBoostForeignRemovalReason.ComplexTopologyChange, baselineImage.Sha256);
            }

            UefiFfsFileLocation baselineFile = baselineFiles[topology.BaselineIndex];
            string baselineHash = HashOf(baseline, baselineFile);
            if (topology.Kind == TurboBoostFfsTopologyKind.SameIdentityModified &&
                string.Equals(baselineHash, module.FfsSha256, StringComparison.Ordinal))
            {
                return Failure(module, TurboBoostForeignRemovalReason.BaselineContradiction, baselineImage.Sha256);
            }

            // Topology may establish a restore intent for any FFS type, but it is deliberately
            // not a byte-write authorization. Do not reuse the driver-only replacement planner
            // here: a Foreign Unlock can live in a PEIM or another PI FFS type, and replacement
            // feasibility is not meaningful until the baseline byte-authorization gates pass.
            return RequiresBaselineByteAuthorization(
                module,
                baselineImage,
                baselineFile,
                baselineHash,
                null);
        }

        return Failure(module, TurboBoostForeignRemovalReason.ComplexTopologyChange, baselineImage.Sha256);
    }

    private static TurboBoostForeignRemovalPlan RequiresBaselineByteAuthorization(
        TurboBoostUnlockModule module,
        BiosImage baselineImage,
        UefiFfsFileLocation baselineFile,
        string baselineHash,
        UefiDriverMutationFeasibility? feasibility) =>
        new(
            TurboBoostForeignRemovalStatus.RequiresBaselineByteAuthorization,
            TurboBoostForeignRemovalOperation.RestoreBaselineFfs,
            TurboBoostForeignRemovalReason.BaselineByteAuthorizationRequired,
            module.RemovalPlan.SourceImageSha256,
            module.FileGuid,
            module.VolumeOffset,
            module.FileOffset,
            module.FileSize,
            module.FfsSha256,
            baselineImage.Sha256,
            baselineFile.Guid,
            baselineFile.Offset,
            baselineFile.Size,
            baselineHash,
            feasibility);

    private static TurboBoostForeignRemovalPlan Failure(
        TurboBoostUnlockModule module,
        TurboBoostForeignRemovalReason reason,
        string? baselineSha256) =>
        new(
            TurboBoostForeignRemovalStatus.Unsupported,
            TurboBoostForeignRemovalOperation.None,
            reason,
            module.RemovalPlan.SourceImageSha256,
            module.FileGuid,
            module.VolumeOffset,
            module.FileOffset,
            module.FileSize,
            module.FfsSha256,
            baselineSha256,
            null,
            null,
            null,
            null,
            null);

    internal static bool HasCompatibleImageLayout(BiosImage source, BiosImage baseline)
    {
        if (source.Kind != baseline.Kind || source.Regions.Count != baseline.Regions.Count || source.Volumes.Count != baseline.Volumes.Count)
        {
            return false;
        }

        for (int index = 0; index < source.Regions.Count; index++)
        {
            if (source.Regions[index] != baseline.Regions[index])
            {
                return false;
            }
        }
        for (int index = 0; index < source.Volumes.Count; index++)
        {
            FirmwareVolume left = source.Volumes[index];
            FirmwareVolume right = baseline.Volumes[index];
            if (left.Offset != right.Offset || left.Length != right.Length || left.FileSystem != right.FileSystem)
            {
                return false;
            }
        }
        return true;
    }

    private const int MinimumInjectionTopologyAnchors = 3;

    /// <summary>
    /// A clean baseline is topology evidence, not a byte donor. For injected-FFS authorization we still
    /// require a strong local lineage proof: the nearest stock FFS anchors around the change window must
    /// be byte-identical (GUID/type/attributes/header/size/SHA-256). This intentionally rejects loose
    /// same-layout matches from unrelated boards or substantially different BIOS revisions.
    /// </summary>
    private static bool HasStrongInjectionTopologyEvidence(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> baseline,
        IReadOnlyList<UefiFfsFileLocation> sourceFiles,
        IReadOnlyList<UefiFfsFileLocation> baselineFiles,
        IReadOnlyList<(int Source, int Baseline)> matches,
        TurboBoostFfsChangeWindow window)
    {
        if (window.SourceCount <= 0 || window.BaselineCount != 0 ||
            window.SourceStart < 0 || window.SourceStart > sourceFiles.Count - window.SourceCount)
        {
            return false;
        }

        var before = new List<(int Source, int Baseline)>(MinimumInjectionTopologyAnchors);
        var after = new List<(int Source, int Baseline)>(MinimumInjectionTopologyAnchors);
        foreach ((int Source, int Baseline) match in matches)
        {
            if (match.Source < window.SourceStart)
            {
                before.Add(match);
                continue;
            }
            if (match.Source >= window.SourceStart + window.SourceCount)
            {
                after.Add(match);
            }
        }

        before.Reverse();
        int exactAnchors = 0;
        bool beforeAvailable = before.Count != 0;
        bool afterAvailable = after.Count != 0;
        bool nearestBeforeExact = !beforeAvailable;
        bool nearestAfterExact = !afterAvailable;

        for (int index = 0; index < Math.Min(MinimumInjectionTopologyAnchors, before.Count); index++)
        {
            bool exact = IsExactTopologyAnchor(source, baseline, sourceFiles, baselineFiles, before[index]);
            if (index == 0)
            {
                nearestBeforeExact = exact;
            }
            if (!exact)
            {
                break;
            }
            exactAnchors++;
        }
        for (int index = 0; index < Math.Min(MinimumInjectionTopologyAnchors, after.Count); index++)
        {
            bool exact = IsExactTopologyAnchor(source, baseline, sourceFiles, baselineFiles, after[index]);
            if (index == 0)
            {
                nearestAfterExact = exact;
            }
            if (!exact)
            {
                break;
            }
            exactAnchors++;
        }

        if (beforeAvailable && afterAvailable && (!nearestBeforeExact || !nearestAfterExact))
        {
            return false;
        }
        return exactAnchors >= MinimumInjectionTopologyAnchors;
    }

    private static bool IsExactTopologyAnchor(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> baseline,
        IReadOnlyList<UefiFfsFileLocation> sourceFiles,
        IReadOnlyList<UefiFfsFileLocation> baselineFiles,
        (int Source, int Baseline) match)
    {
        if ((uint)match.Source >= (uint)sourceFiles.Count || (uint)match.Baseline >= (uint)baselineFiles.Count)
        {
            return false;
        }

        UefiFfsFileLocation left = sourceFiles[match.Source];
        UefiFfsFileLocation right = baselineFiles[match.Baseline];
        return left.Guid == right.Guid &&
               left.Type == right.Type &&
               left.Attributes == right.Attributes &&
               left.HeaderSize == right.HeaderSize &&
               left.Size == right.Size &&
               string.Equals(HashOf(source, left), HashOf(baseline, right), StringComparison.Ordinal);
    }

    internal static bool IsVerifiedForeignInjectionGroup(
        IReadOnlyList<UefiFfsFileLocation> sourceFiles,
        TurboBoostFfsChangeWindow window,
        IReadOnlyList<TurboBoostUnlockModule> foreignModules)
    {
        if (window.SourceCount <= 1 || window.BaselineCount != 0 ||
            window.SourceStart < 0 || window.SourceStart > sourceFiles.Count - window.SourceCount)
        {
            return false;
        }

        var verifiedForeign = new HashSet<(long FileOffset, Guid FileGuid, int FileSize)>(
            foreignModules
                .Where(item => item.Verified)
                .Select(item => (item.FileOffset, item.FileGuid, item.FileSize)));
        for (int index = window.SourceStart; index < window.SourceStart + window.SourceCount; index++)
        {
            UefiFfsFileLocation file = sourceFiles[index];
            if (!verifiedForeign.Contains((file.Offset, file.Guid, file.Size)))
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsActiveFile(UefiFfsFileLocation file) =>
        file.State == FfsFileState.DataValid && file.Size > 0;

    private static TurboBoostFfsIdentity ToIdentity(UefiFfsFileLocation file) =>
        new(file.Guid, file.Type);

    private static bool HashMatches(ReadOnlySpan<byte> source, UefiFfsFileLocation file, string expected) =>
        string.Equals(HashOf(source, file), expected, StringComparison.Ordinal);

    private static string HashOf(ReadOnlySpan<byte> source, UefiFfsFileLocation file)
    {
        if (file.Offset < 0 || file.Size <= 0 || file.Offset > source.Length - file.Size)
        {
            return string.Empty;
        }
        return Convert.ToHexString(SHA256.HashData(source.Slice(file.Offset, file.Size)));
    }
}
