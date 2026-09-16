using System.Security.Cryptography;
using System.Text.Json;

namespace XeonV3Control.Core;

public enum X99UefiDriverUpdateDisposition
{
    Ready,
    UpToDate,
    RequiresReview,
    Blocked
}

public static class X99UefiDriverUpdateReason
{
    public const string None = nameof(None);
    public const string UnsupportedPlatformEvidence = nameof(UnsupportedPlatformEvidence);
    public const string SourceAnalysisIncomplete = nameof(SourceAnalysisIncomplete);
    public const string ExactTransitionNotCatalogued = nameof(ExactTransitionNotCatalogued);
    public const string CandidateResourceInvalid = nameof(CandidateResourceInvalid);
    public const string GenericPlannerBlocked = nameof(GenericPlannerBlocked);
    public const string GenericReviewNotAuthorized = nameof(GenericReviewNotAuthorized);
    public const string RepackRequired = nameof(RepackRequired);
    public const string PhysicalMutationUnsupported = nameof(PhysicalMutationUnsupported);
    public const string RequiresRebase = nameof(RequiresRebase);
    public const string ReviewOnlyTransition = nameof(ReviewOnlyTransition);
    public const string HardwareAuthorizationRequired = nameof(HardwareAuthorizationRequired);
    public const string BundleAuthorizationRequired = nameof(BundleAuthorizationRequired);
    public const string NoKnownUpgradeChain = nameof(NoKnownUpgradeChain);
    public const string NotApplicableToLga20113Xeon = nameof(NotApplicableToLga20113Xeon);
    public const string NotDxeDriver = nameof(NotDxeDriver);
}

public sealed record X99UefiDriverUpdatePlan(
    X99UefiDriverUpdateDisposition Disposition,
    IReadOnlyList<string> Reasons,
    string Component,
    string? Branch,
    string? TransitionId,
    string? CurrentVersion,
    string? CandidateVersion,
    string? CandidateId,
    string SourceImageSha256,
    UefiDriverMutationTarget Target,
    string? CandidateSha256,
    UefiDriverUpdatePlan? GenericPlan,
    UefiFirmwareVolumeMutationStrategy MutationStrategy = UefiFirmwareVolumeMutationStrategy.Unsupported)
{
    public bool CanApply =>
        Disposition == X99UefiDriverUpdateDisposition.Ready &&
        TransitionId is not null && CandidateId is not null && CandidateSha256 is not null &&
        (GenericPlan?.Disposition is UefiDriverUpdateDisposition.Ready or UefiDriverUpdateDisposition.RequiresReview) &&
        GenericPlan.Mutation?.Feasibility != UefiDriverMutationFeasibility.Unsupported &&
        MutationStrategy is UefiFirmwareVolumeMutationStrategy.InPlace or
            UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace or
            UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume;
}

/// <summary>
/// X99/LGA2011-3 policy layer over the generic UEFI driver update planner. It deliberately uses
/// exact FFS SHA-256 transitions rather than GUID/name/version guesses. The supplied driver corpus
/// has no board provenance, so a same-GUID "newest" module is never sufficient authorization.
/// </summary>
public static class X99UefiDriverUpdatePlanner
{
    private const uint BroadwellEProcessorSignature = 0x000406F1;
    private static readonly HashSet<string> X99Markers = new(StringComparer.Ordinal)
    {
        "X99", "HUANANZHI", "MACHINIST", "JINGSHA"
    };

    public static IReadOnlyList<X99UefiDriverUpdatePlan> Plan(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(image);
        UefiDriverMutationPlanner.EnsureImageMatches(source, image);
        token.ThrowIfCancellationRequested();

        bool platformEvidence = HasX99PlatformEvidence(image);
        bool analysisComplete = !image.UefiDrivers.Incomplete && !image.TurboBoostUnlock.Incomplete;
        var plans = new List<X99UefiDriverUpdatePlan>();

        foreach (UefiDriverInfo driver in image.UefiDrivers.Drivers)
        {
            token.ThrowIfCancellationRequested();
            if (!X99UefiDriverUpdateCatalog.IsManagedGuid(driver.FileGuid))
            {
                continue;
            }

            plans.Add(PlanDriver(source, image, driver, platformEvidence, analysisComplete, token));
        }

        return plans
            .OrderBy(plan => plan.Target.VolumeOffset)
            .ThenBy(plan => plan.Target.FileOffset)
            .ToArray();
    }

    public static X99UefiDriverUpdatePlan PlanExact(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverMutationTarget target,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        IReadOnlyList<X99UefiDriverUpdatePlan> plans = Plan(source, image, token);
        X99UefiDriverUpdatePlan[] matches = plans.Where(plan =>
            plan.Target.DriverGuid == target.DriverGuid &&
            plan.Target.VolumeOffset == target.VolumeOffset &&
            plan.Target.FileOffset == target.FileOffset &&
            string.Equals(plan.Target.ExpectedSha256, target.ExpectedSha256, StringComparison.Ordinal)).ToArray();
        if (matches.Length != 1)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateUnsupported);
        }
        return matches[0];
    }

    internal static byte[] LoadCandidate(string candidateId) =>
        X99UefiDriverUpdateCatalog.LoadCandidate(candidateId);

    internal static bool HasX99PlatformEvidence(BiosImage image)
    {
        ArgumentNullException.ThrowIfNull(image);
        if (image.TurboBoostUnlock.Microcodes.Any(microcode =>
                microcode.ProcessorSignature is TurboBoostUnlockReport.XeonE5V3ProcessorSignature or BroadwellEProcessorSignature))
        {
            return true;
        }

        return image.Markers.Any(marker => X99Markers.Contains(marker));
    }

    private static X99UefiDriverUpdatePlan PlanDriver(
        ReadOnlySpan<byte> source,
        BiosImage image,
        UefiDriverInfo driver,
        bool platformEvidence,
        bool analysisComplete,
        CancellationToken token)
    {
        UefiDriverMutationTarget target = UefiDriverMutationTarget.From(driver);
        X99UefiDriverRestrictedComponent? restricted = X99UefiDriverUpdateCatalog.FindRestriction(driver.FileGuid);
        X99UefiDriverTransition? transition = X99UefiDriverUpdateCatalog.FindTransition(driver.FileGuid, driver.Sha256);
        X99UefiDriverCandidate? currentCandidate = X99UefiDriverUpdateCatalog.FindCandidate(driver.FileGuid, driver.Sha256);

        string component = transition?.Component ?? currentCandidate?.Component ?? restricted?.Component ?? driver.Name ?? driver.FileGuid.ToString("D");
        string? branch = transition?.Branch ?? currentCandidate?.Branch;
        string? currentVersion = transition?.SourceVersion ?? currentCandidate?.Version ?? driver.Version;

        if (!platformEvidence)
        {
            return Simple(X99UefiDriverUpdateDisposition.Blocked, X99UefiDriverUpdateReason.UnsupportedPlatformEvidence,
                component, branch, currentVersion, image.Sha256, target);
        }
        if (!analysisComplete)
        {
            return Simple(X99UefiDriverUpdateDisposition.Blocked, X99UefiDriverUpdateReason.SourceAnalysisIncomplete,
                component, branch, currentVersion, image.Sha256, target);
        }
        if (driver.Kind != UefiDriverKind.Dxe)
        {
            return Simple(X99UefiDriverUpdateDisposition.Blocked, X99UefiDriverUpdateReason.NotDxeDriver,
                component, branch, currentVersion, image.Sha256, target);
        }
        if (currentCandidate is not null)
        {
            return new(
                X99UefiDriverUpdateDisposition.UpToDate,
                [X99UefiDriverUpdateReason.None],
                currentCandidate.Component,
                currentCandidate.Branch,
                null,
                currentCandidate.Version,
                null,
                null,
                image.Sha256,
                target,
                null,
                null);
        }
        if (transition is null)
        {
            string reason = restricted?.Reason ?? X99UefiDriverUpdateReason.ExactTransitionNotCatalogued;
            X99UefiDriverUpdateDisposition disposition = reason == X99UefiDriverUpdateReason.HardwareAuthorizationRequired
                ? X99UefiDriverUpdateDisposition.RequiresReview
                : X99UefiDriverUpdateDisposition.Blocked;
            return Simple(disposition, reason, component, branch, currentVersion, image.Sha256, target);
        }

        X99UefiDriverCandidate candidate = X99UefiDriverUpdateCatalog.GetCandidate(transition.CandidateId);
        byte[] candidateFfs;
        try
        {
            candidateFfs = X99UefiDriverUpdateCatalog.LoadCandidate(candidate.Id);
        }
        catch (InvalidDataException)
        {
            return new(
                X99UefiDriverUpdateDisposition.Blocked,
                [X99UefiDriverUpdateReason.CandidateResourceInvalid],
                transition.Component,
                transition.Branch,
                transition.Id,
                transition.SourceVersion,
                candidate.Version,
                candidate.Id,
                image.Sha256,
                target,
                candidate.Sha256,
                null);
        }

        UefiDriverUpdatePlan generic = UefiDriverUpdatePlanner.Plan(source, image, target, candidateFfs, token);
        if (generic.Disposition == UefiDriverUpdateDisposition.Blocked ||
            generic.Mutation?.Feasibility == UefiDriverMutationFeasibility.Unsupported)
        {
            return WithGeneric(X99UefiDriverUpdateDisposition.Blocked,
                [X99UefiDriverUpdateReason.GenericPlannerBlocked, .. generic.Reasons],
                image, target, transition, candidate, generic, UefiFirmwareVolumeMutationStrategy.Unsupported);
        }

        UefiFirmwareVolumeReplacementPlan physical = UefiFirmwareVolumeRebuilder.PlanReplacement(
            source, image, target, candidateFfs, token);
        if (!physical.CanApply)
        {
            X99UefiDriverUpdateDisposition disposition = physical.Strategy == UefiFirmwareVolumeMutationStrategy.RequiresRebase
                ? X99UefiDriverUpdateDisposition.RequiresReview
                : X99UefiDriverUpdateDisposition.Blocked;
            string highLevelReason = physical.Strategy == UefiFirmwareVolumeMutationStrategy.RequiresRebase
                ? X99UefiDriverUpdateReason.RequiresRebase
                : X99UefiDriverUpdateReason.PhysicalMutationUnsupported;
            return WithGeneric(disposition, [highLevelReason, physical.Reason],
                image, target, transition, candidate, generic, physical.Strategy);
        }

        string[] unauthorizedReview = generic.Reasons
            .Where(reason => reason != UefiDriverUpdateReason.None &&
                !transition.AllowedGenericReviewReasons.Contains(reason, StringComparer.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(reason => reason, StringComparer.Ordinal)
            .ToArray();
        if (unauthorizedReview.Length != 0)
        {
            return WithGeneric(X99UefiDriverUpdateDisposition.Blocked,
                [X99UefiDriverUpdateReason.GenericReviewNotAuthorized, .. unauthorizedReview],
                image, target, transition, candidate, generic, physical.Strategy);
        }
        if (string.Equals(transition.Policy, X99UefiDriverUpdateCatalog.ReviewOnlyPolicy, StringComparison.Ordinal))
        {
            return WithGeneric(X99UefiDriverUpdateDisposition.RequiresReview,
                [X99UefiDriverUpdateReason.ReviewOnlyTransition], image, target, transition, candidate, generic, physical.Strategy);
        }
        if (string.Equals(transition.Policy, X99UefiDriverUpdateCatalog.AutomaticInPlacePolicy, StringComparison.Ordinal) &&
            physical.Strategy != UefiFirmwareVolumeMutationStrategy.InPlace)
        {
            return WithGeneric(X99UefiDriverUpdateDisposition.RequiresReview,
                [X99UefiDriverUpdateReason.RepackRequired], image, target, transition, candidate, generic, physical.Strategy);
        }
        if (!string.Equals(transition.Policy, X99UefiDriverUpdateCatalog.AutomaticInPlacePolicy, StringComparison.Ordinal) &&
            !string.Equals(transition.Policy, X99UefiDriverUpdateCatalog.AutomaticManagedPolicy, StringComparison.Ordinal))
        {
            return WithGeneric(X99UefiDriverUpdateDisposition.Blocked,
                [X99UefiDriverUpdateReason.PhysicalMutationUnsupported], image, target, transition, candidate, generic, physical.Strategy);
        }

        return WithGeneric(X99UefiDriverUpdateDisposition.Ready,
            [X99UefiDriverUpdateReason.None], image, target, transition, candidate, generic, physical.Strategy);
    }

    private static X99UefiDriverUpdatePlan Simple(
        X99UefiDriverUpdateDisposition disposition,
        string reason,
        string component,
        string? branch,
        string? currentVersion,
        string sourceImageSha256,
        UefiDriverMutationTarget target) =>
        new(disposition, [reason], component, branch, null, currentVersion, null, null,
            sourceImageSha256, target, null, null);

    private static X99UefiDriverUpdatePlan WithGeneric(
        X99UefiDriverUpdateDisposition disposition,
        IReadOnlyList<string> reasons,
        BiosImage image,
        UefiDriverMutationTarget target,
        X99UefiDriverTransition transition,
        X99UefiDriverCandidate candidate,
        UefiDriverUpdatePlan generic,
        UefiFirmwareVolumeMutationStrategy strategy) =>
        new(disposition, reasons, transition.Component, transition.Branch, transition.Id,
            transition.SourceVersion, candidate.Version, candidate.Id, image.Sha256, target,
            candidate.Sha256, generic, strategy);
}

internal sealed record X99UefiDriverCandidate(
    string Id,
    string Component,
    string Branch,
    string Version,
    Guid FileGuid,
    string ResourceFile,
    string Sha256,
    int Size);

internal sealed record X99UefiDriverTransition(
    string Id,
    string Component,
    string Branch,
    Guid FileGuid,
    string SourceVersion,
    string SourceSha256,
    string CandidateId,
    string Policy,
    IReadOnlyList<string> AllowedGenericReviewReasons);

internal sealed record X99UefiDriverRestrictedComponent(string Id, string Component, Guid FileGuid, string Reason);

internal sealed record X99UefiDriverUpdateCatalogDocument(
    int SchemaVersion,
    IReadOnlyList<X99UefiDriverCandidate> Candidates,
    IReadOnlyList<X99UefiDriverTransition> Transitions,
    IReadOnlyList<X99UefiDriverRestrictedComponent> RestrictedComponents);

internal static class X99UefiDriverUpdateCatalog
{
    internal const string AutomaticInPlacePolicy = "AutomaticInPlace";
    internal const string AutomaticManagedPolicy = "AutomaticManaged";
    internal const string ReviewOnlyPolicy = "ReviewOnly";
    private const string CatalogFileName = "x99-driver-updates.json";
    private const string CandidateResourceFolder = "Firmware.DriverUpdates";
    private static readonly string CatalogResourceName = EmbeddedResourceNames.File(
        EmbeddedResourceNames.FirmwareFolder, CatalogFileName);
    private static readonly X99UefiDriverUpdateCatalogDocument Document = Load();
    private static readonly IReadOnlyDictionary<string, X99UefiDriverCandidate> CandidatesById =
        Document.Candidates.ToDictionary(item => item.Id, StringComparer.Ordinal);

    internal static bool IsManagedGuid(Guid guid) =>
        Document.Candidates.Any(item => item.FileGuid == guid) ||
        Document.Transitions.Any(item => item.FileGuid == guid) ||
        Document.RestrictedComponents.Any(item => item.FileGuid == guid);

    internal static X99UefiDriverTransition? FindTransition(Guid guid, string sha256) =>
        Document.Transitions.SingleOrDefault(item => item.FileGuid == guid &&
            string.Equals(item.SourceSha256, sha256, StringComparison.Ordinal));

    internal static X99UefiDriverCandidate? FindCandidate(Guid guid, string sha256) =>
        Document.Candidates.SingleOrDefault(item => item.FileGuid == guid &&
            string.Equals(item.Sha256, sha256, StringComparison.Ordinal));

    internal static X99UefiDriverRestrictedComponent? FindRestriction(Guid guid) =>
        Document.RestrictedComponents.SingleOrDefault(item => item.FileGuid == guid);

    internal static X99UefiDriverCandidate GetCandidate(string id) =>
        CandidatesById.TryGetValue(id, out X99UefiDriverCandidate? candidate)
            ? candidate
            : throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);

    internal static byte[] LoadCandidate(string id)
    {
        X99UefiDriverCandidate candidate = GetCandidate(id);
        string resourceName = typeof(X99UefiDriverUpdateCatalog).Namespace + "." +
            CandidateResourceFolder + "." + candidate.ResourceFile;
        using Stream stream = typeof(X99UefiDriverUpdateCatalog).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        if (candidate.Size <= 0 || candidate.Size > UefiDriverInspectionPolicy.MaximumFfsFileBytes)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        }
        byte[] bytes = new byte[candidate.Size];
        try
        {
            stream.ReadExactly(bytes);
        }
        catch (EndOfStreamException error)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog, error);
        }
        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        }
        string hash = Convert.ToHexString(SHA256.HashData(bytes));
        if (!string.Equals(hash, candidate.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        }
        return bytes;
    }

    private static X99UefiDriverUpdateCatalogDocument Load()
    {
        using Stream resource = typeof(X99UefiDriverUpdateCatalog).Assembly.GetManifestResourceStream(CatalogResourceName)
            ?? throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        X99UefiDriverUpdateCatalogDocument document = JsonSerializer.Deserialize<X99UefiDriverUpdateCatalogDocument>(resource)
            ?? throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        Validate(document);
        return document;
    }

    private static void Validate(X99UefiDriverUpdateCatalogDocument document)
    {
        if (document.SchemaVersion != 1 || document.Candidates.Count == 0 || document.Transitions.Count == 0)
        {
            throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var candidateHashes = new HashSet<(Guid Guid, string Hash)>();
        foreach (X99UefiDriverCandidate candidate in document.Candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate.Id) || string.IsNullOrWhiteSpace(candidate.Component) ||
                string.IsNullOrWhiteSpace(candidate.Branch) || string.IsNullOrWhiteSpace(candidate.Version) ||
                candidate.FileGuid == Guid.Empty || string.IsNullOrWhiteSpace(candidate.ResourceFile) ||
                Path.GetFileName(candidate.ResourceFile) != candidate.ResourceFile || candidate.Size <= 0 ||
                !ids.Add(candidate.Id))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
            }
            string hash = Sha256Identity.Normalize(candidate.Sha256, OperationError.UefiDriverUpdateCatalog);
            if (!string.Equals(hash, candidate.Sha256, StringComparison.Ordinal) ||
                !candidateHashes.Add((candidate.FileGuid, hash)))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
            }
        }

        var transitionIds = new HashSet<string>(StringComparer.Ordinal);
        var sourceIdentities = new HashSet<(Guid Guid, string Hash)>();
        string[] automaticInPlaceReviewReasons =
        [
            UefiDriverUpdateReason.VersionNotComparable
        ];
        string[] automaticManagedReviewReasons =
        [
            UefiDriverUpdateReason.VersionNotComparable,
            UefiDriverUpdateReason.ExecutableLayoutChanged,
            UefiDriverUpdateReason.SectionLayoutChanged,
            UefiDriverUpdateReason.RepackRequired
        ];
        string[] reviewOnlyReasons =
        [
            UefiDriverUpdateReason.VersionNotComparable,
            UefiDriverUpdateReason.VersionUnchanged,
            UefiDriverUpdateReason.ExecutableLayoutChanged,
            UefiDriverUpdateReason.SectionLayoutChanged,
            UefiDriverUpdateReason.RepackRequired
        ];
        foreach (X99UefiDriverTransition transition in document.Transitions)
        {
            if (string.IsNullOrWhiteSpace(transition.Id) || string.IsNullOrWhiteSpace(transition.Component) ||
                string.IsNullOrWhiteSpace(transition.Branch) || string.IsNullOrWhiteSpace(transition.SourceVersion) ||
                transition.FileGuid == Guid.Empty || !transitionIds.Add(transition.Id) ||
                transition.Policy is not (AutomaticInPlacePolicy or AutomaticManagedPolicy or ReviewOnlyPolicy) ||
                !document.Candidates.Any(candidate => candidate.Id == transition.CandidateId &&
                    candidate.FileGuid == transition.FileGuid && candidate.Branch == transition.Branch) ||
                transition.AllowedGenericReviewReasons.Distinct(StringComparer.Ordinal).Count() !=
                    transition.AllowedGenericReviewReasons.Count ||
                transition.AllowedGenericReviewReasons.Any(reason =>
                    !(transition.Policy == AutomaticInPlacePolicy
                        ? automaticInPlaceReviewReasons
                        : transition.Policy == AutomaticManagedPolicy
                            ? automaticManagedReviewReasons
                            : reviewOnlyReasons).Contains(reason, StringComparer.Ordinal)))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
            }
            string hash = Sha256Identity.Normalize(transition.SourceSha256, OperationError.UefiDriverUpdateCatalog);
            if (!string.Equals(hash, transition.SourceSha256, StringComparison.Ordinal) ||
                candidateHashes.Contains((transition.FileGuid, hash)) ||
                !sourceIdentities.Add((transition.FileGuid, hash)))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
            }
        }

        string[] allowedRestrictionReasons =
        [
            X99UefiDriverUpdateReason.HardwareAuthorizationRequired,
            X99UefiDriverUpdateReason.BundleAuthorizationRequired,
            X99UefiDriverUpdateReason.NoKnownUpgradeChain,
            X99UefiDriverUpdateReason.NotApplicableToLga20113Xeon
        ];
        var restrictedGuids = new HashSet<Guid>();
        foreach (X99UefiDriverRestrictedComponent restricted in document.RestrictedComponents)
        {
            if (string.IsNullOrWhiteSpace(restricted.Id) || string.IsNullOrWhiteSpace(restricted.Component) || restricted.FileGuid == Guid.Empty ||
                !allowedRestrictionReasons.Contains(restricted.Reason, StringComparer.Ordinal) ||
                !restrictedGuids.Add(restricted.FileGuid))
            {
                throw new InvalidDataException(OperationError.UefiDriverUpdateCatalog);
            }
        }
    }
}
