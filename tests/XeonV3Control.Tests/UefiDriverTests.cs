using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class UefiDriverTests
{
    [TestMethod]
    public async Task ReferenceX99ImageEnumeratesActiveDxeAndMmDrivers()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        UefiDriverReport report = image.UefiDrivers;

        Assert.IsTrue(report.Drivers.Count >= 100, "Expected a substantial DXE/MM inventory in the reference X99 image.");
        Assert.IsTrue(report.Drivers.Any(driver => driver.Kind is UefiDriverKind.Dxe or UefiDriverKind.CombinedPeimDxe));
        Assert.IsTrue(report.Drivers.Any(driver => driver.Kind is UefiDriverKind.Mm or UefiDriverKind.CombinedMmDxe or UefiDriverKind.MmStandalone));
        Assert.IsTrue(report.Drivers.All(driver => driver.FileSize > 0));
        Assert.IsTrue(report.Drivers.All(driver => driver.FileOffset >= 0 && driver.FileOffset + driver.FileSize <= image.Size));
        Assert.IsTrue(report.Drivers.All(driver => driver.Sha256.Length == 64));
        Assert.IsTrue(report.Drivers.All(driver => driver.FfsHeaderSize is AmiSecureBootSpecification.FfsFileHeaderBytes or AmiSecureBootSpecification.FfsExtendedFileHeaderBytes));
        Assert.IsTrue(report.Drivers.All(driver => driver.RequiredDataAlignment > 0));
        Assert.IsTrue(report.Drivers.All(driver => driver.SectionCount >= driver.Executables.Count));
        Assert.IsTrue(report.Drivers.SelectMany(driver => driver.DependencySha256)
            .All(hash => hash.Length == 64 && hash.All(character => Uri.IsHexDigit(character))));
        Assert.IsTrue(report.Drivers.Any(driver => driver.Executables.Count != 0));
        Assert.IsTrue(report.Drivers.Where(driver => driver.Executables.Count != 0)
            .SelectMany(driver => driver.Executables)
            .All(executable => executable.ImageSize > 0 && (!executable.StructurallyValid || executable.SectionCount > 0)));
    }

    [TestMethod]
    public async Task StandardEfiCompressionIsDecodedAndInspected()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        Guid guid = new("91b4d9c1-141c-4824-8d02-3c298e36eb3f");

        UefiDriverInfo driver = image.UefiDrivers.Drivers.Single(item => item.FileGuid == guid);

        Assert.AreEqual(UefiDriverSecurityStatus.NoKnownIssues, driver.SecurityStatus);
        Assert.IsTrue(driver.Executables.Any(executable => executable.Format == UefiExecutableFormat.Pe32));
        Assert.IsFalse(driver.Issues.Contains(UefiDriverIssueCode.InvalidSectionStream, StringComparer.Ordinal));
    }

    [TestMethod]
    public void EfiCompressionHeaderIsValidatedBeforeAllocation()
    {
        byte[] truncated = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(truncated, 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(truncated.AsSpan(sizeof(uint)), 1);

        Assert.IsFalse(EfiCompressionDecoder.TryGetExpandedSize(
            truncated,
            UefiDriverInspectionPolicy.MaximumExpandedSectionBytes,
            out _));

        byte[] oversized = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(oversized, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            oversized.AsSpan(sizeof(uint)),
            checked((uint)UefiDriverInspectionPolicy.MaximumExpandedSectionBytes + 1));

        Assert.IsFalse(EfiCompressionDecoder.TryGetExpandedSize(
            oversized,
            UefiDriverInspectionPolicy.MaximumExpandedSectionBytes,
            out _));
    }

    [TestMethod]
    public async Task OemFreeformPeContainersAreInspectedWithoutFalseSecurityWarning()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        Guid guid = new("a0327fe0-1fda-4e5b-905d-b510c45a61d0");

        UefiDriverInfo driver = image.UefiDrivers.Drivers.Single(item => item.FileGuid == guid);

        Assert.AreEqual(UefiDriverSecurityStatus.NoKnownIssues, driver.SecurityStatus);
        Assert.IsTrue(driver.Executables.Count >= 3);
        Assert.IsFalse(driver.Issues.Contains(UefiDriverIssueCode.MissingExecutable, StringComparer.Ordinal));
        Assert.IsFalse(driver.Issues.Contains(UefiDriverIssueCode.FileTypeSectionRulesViolation, StringComparer.Ordinal));
    }

    [TestMethod]
    public void DxeDriverWithoutExecutableIsReportedForReview()
    {
        byte[] data = FirmwareTests.Image();
        const int firstFileOffset = 72;
        Guid guid = new("a7c1c3e5-6ec8-4e18-97bb-78027ac9379f");
        DriverFfs(guid).CopyTo(data, firstFileOffset);

        BiosImage image = BiosImageLoader.Analyze(data);
        UefiDriverInfo driver = image.UefiDrivers.Drivers.Single(item => item.FileGuid == guid);

        CollectionAssert.Contains(driver.Issues.ToArray(), UefiDriverIssueCode.MissingExecutable);
        CollectionAssert.DoesNotContain(driver.Issues.ToArray(), UefiDriverIssueCode.FileTypeSectionRulesViolation);
        Assert.AreEqual(UefiDriverSecurityStatus.ReviewRecommended, driver.SecurityStatus);
    }

    [TestMethod]
    public void VulnerabilityCatalogRequiresExactGuidAndSha256()
    {
        Guid guid = new("899407d7-99fe-43d8-9a21-79ec328cac21");
        const string hash = "3899216B9855AEF3687F707E1B9E20A9843966C3E3B42AF0E0ECD51617418A22";

        IReadOnlyList<KnownUefiDriverVulnerability> matches =
            UefiDriverVulnerabilityCatalog.Match(guid, hash, []);
        Assert.IsTrue(matches.Any(item => item.Id == "CVE-2023-22449"));
        Assert.IsEmpty(UefiDriverVulnerabilityCatalog.Match(Guid.NewGuid(), hash, []));
        Assert.IsEmpty(UefiDriverVulnerabilityCatalog.Match(guid, new string('0', 64), []));
    }

    [TestMethod]
    public void MutationPlannerValidatesAddReplaceAndRemoveWithoutWritingTheImage()
    {
        byte[] data = FirmwareTests.Image();
        int firstFileOffset = 72; // Synthetic FV header in FirmwareTests.Image is already 8-byte aligned.
        Guid existingGuid = new("11223344-5566-7788-99aa-bbccddeeff00");
        byte[] existing = DriverFfs(existingGuid);
        existing.CopyTo(data, firstFileOffset);
        BiosImage image = BiosImageLoader.Analyze(data);
        byte[] before = data.ToArray();

        UefiDriverMutationPlan remove = UefiDriverMutationPlanner.PlanRemove(data, image, existingGuid);
        Assert.AreEqual(UefiDriverMutationFeasibility.InPlace, remove.Feasibility);
        Assert.IsNull(remove.DestinationOffset);

        byte[] replacement = DriverFfs(existingGuid);
        UefiDriverMutationPlan replace = UefiDriverMutationPlanner.PlanReplace(data, image, existingGuid, replacement);
        Assert.AreEqual(UefiDriverMutationFeasibility.InPlace, replace.Feasibility);
        Assert.AreEqual((long?)firstFileOffset, replace.DestinationOffset);

        Guid addedGuid = new("00112233-4455-6677-8899-aabbccddeeff");
        byte[] added = DriverFfs(addedGuid);
        UefiDriverMutationPlan add = UefiDriverMutationPlanner.PlanAdd(data, image, image.Volumes[0].Offset, added);
        Assert.AreEqual(UefiDriverMutationFeasibility.InPlace, add.Feasibility);
        Assert.AreEqual(addedGuid, add.DriverGuid);

        CollectionAssert.AreEqual(before, data, "Planning must never mutate the source image.");
    }

    [TestMethod]
    public async Task UpdatePlannerUsesExactInstanceIdentityAndDoesNotMutateSource()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] data = File.ReadAllBytes(path);
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        UefiDriverInfo driver = image.UefiDrivers.Drivers.First(item => item.Executables.Count != 0);
        byte[] candidate = data.AsSpan(checked((int)driver.FileOffset), driver.FileSize).ToArray();
        byte[] before = data.ToArray();
        UefiDriverMutationTarget target = UefiDriverMutationTarget.From(driver);

        UefiDriverUpdatePlan plan = UefiDriverUpdatePlanner.Plan(data, image, target, candidate);

        Assert.AreEqual(UefiDriverUpdateDisposition.Blocked, plan.Disposition);
        CollectionAssert.Contains(plan.Reasons.ToArray(), UefiDriverUpdateReason.NoChange);
        Assert.AreEqual(driver.FileGuid, plan.Current?.FileGuid);
        Assert.AreEqual(driver.FileGuid, plan.Candidate?.FileGuid);
        CollectionAssert.AreEqual(before, data, "Update planning must never mutate source firmware bytes.");
    }

    [TestMethod]
    public async Task UpdatePlannerRejectsAStaleSourceImageBeforeCandidateAssessment()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] data = File.ReadAllBytes(path);
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        UefiDriverInfo driver = image.UefiDrivers.Drivers.First(item => item.Executables.Count != 0);
        byte[] candidate = data.AsSpan(checked((int)driver.FileOffset), driver.FileSize).ToArray();
        UefiDriverMutationTarget target = UefiDriverMutationTarget.From(driver);

        data[0] ^= 0x01;

        InvalidDataException error = Assert.Throws<InvalidDataException>(() =>
            UefiDriverUpdatePlanner.Plan(data, image, target, candidate));
        Assert.AreEqual(UefiDriverMutationReason.ImageMismatch, error.Message);
    }

    [TestMethod]
    public void UpdateBackendCanPlanButCannotApplyFirmwareChanges()
    {
        Type planner = typeof(UefiDriverUpdatePlanner);
        var methods = planner.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        Assert.IsTrue(methods.Any(method => method.Name == "Plan"));
        Assert.IsFalse(methods.Any(method =>
            method.Name.Contains("Apply", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Execute", StringComparison.OrdinalIgnoreCase) ||
            method.Name.Contains("Write", StringComparison.OrdinalIgnoreCase)));
    }


    [TestMethod]
    public async Task ReferenceX99ImageReportsReviewedIntelRstCandidateAsUpToDate()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);

        X99UefiDriverUpdatePlan plan = X99UefiDriverUpdatePlanner.Plan(source, image)
            .Single(item => item.Target.DriverGuid == new Guid("91b4d9c1-141c-4824-8d02-3c298e36eb3f"));
        X99UefiDriverUpdatePlan analyzedPlan = image.X99UefiDriverUpdates
            .Single(item => item.Target.DriverGuid == plan.Target.DriverGuid);

        Assert.AreEqual(plan.Disposition, analyzedPlan.Disposition);
        CollectionAssert.AreEqual(plan.Reasons.ToArray(), analyzedPlan.Reasons.ToArray());
        Assert.AreEqual(plan.Component, analyzedPlan.Component);
        Assert.AreEqual(plan.Branch, analyzedPlan.Branch);
        Assert.AreEqual(plan.TransitionId, analyzedPlan.TransitionId);
        Assert.AreEqual(plan.CurrentVersion, analyzedPlan.CurrentVersion);
        Assert.AreEqual(plan.CandidateVersion, analyzedPlan.CandidateVersion);
        Assert.AreEqual(plan.CandidateId, analyzedPlan.CandidateId);
        Assert.AreEqual(plan.SourceImageSha256, analyzedPlan.SourceImageSha256);
        Assert.AreEqual(plan.Target, analyzedPlan.Target);
        Assert.AreEqual(plan.CandidateSha256, analyzedPlan.CandidateSha256);
        Assert.AreEqual(plan.MutationStrategy, analyzedPlan.MutationStrategy);
        Assert.AreEqual(plan.CanApply, analyzedPlan.CanApply);
        Assert.AreEqual(plan.GenericPlan is null, analyzedPlan.GenericPlan is null);
        Assert.AreEqual(X99UefiDriverUpdateDisposition.UpToDate, plan.Disposition);
        Assert.AreEqual("Intel RST RAID EFI", plan.Component);
        Assert.AreEqual("RST", plan.Branch);
        Assert.AreEqual("14.8.0.2377", plan.CurrentVersion);
        Assert.AreEqual(
            "9AE78E96A20D5A95EA616C51B2A4CF93CFE42FAA13FB94F19F3982D2AEAC8872",
            plan.Target.ExpectedSha256);
        Assert.IsFalse(plan.CanApply);
    }

    [TestMethod]
    public async Task ReferenceX99ImageSurfacesControllerPoliciesBeyondTheSingleRstCandidate()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        IReadOnlyList<X99UefiDriverUpdatePlan> plans = image.X99UefiDriverUpdates;

        Assert.IsTrue(image.UefiDrivers.Drivers.Count > plans.Count,
            "The update-policy list must not be presented as the complete UEFI-driver inventory.");
        foreach (Guid guid in new[]
        {
            new Guid("91b4d9c1-141c-4824-8d02-3c298e36eb3f"),
            new Guid("634e8db5-c432-43be-a653-9ca2922cc458"),
            new Guid("c9a6de36-fdff-4faf-8343-85d9e3470f43"),
            new Guid("668706b2-bcfc-4ad4-a185-75e79f3fe169"),
            new Guid("32d4b2dd-1db3-4af9-91b0-fbae6e6ea259")
        })
        {
            Assert.IsTrue(plans.Any(plan => plan.Target.DriverGuid == guid),
                $"Expected an explicit X99 update/restriction policy for {guid:D}.");
        }

        X99UefiDriverUpdatePlan realtek = plans.Single(plan =>
            plan.Target.DriverGuid == new Guid("32d4b2dd-1db3-4af9-91b0-fbae6e6ea259"));
        Assert.AreEqual("Realtek UNDI (RtkUndiDxe)", realtek.Component);
        Assert.AreEqual(X99UefiDriverUpdateDisposition.Blocked, realtek.Disposition);
        CollectionAssert.Contains(realtek.Reasons.ToArray(), X99UefiDriverUpdateReason.NoKnownUpgradeChain);

        X99UefiDriverUpdatePlan nvmeSetup = plans.Single(plan =>
            plan.Target.DriverGuid == new Guid("668706b2-bcfc-4ad4-a185-75e79f3fe169"));
        Assert.AreEqual("AMI NVMe Dynamic Setup", nvmeSetup.Component);
        Assert.AreEqual(X99UefiDriverUpdateDisposition.Blocked, nvmeSetup.Disposition);
        CollectionAssert.Contains(nvmeSetup.Reasons.ToArray(), X99UefiDriverUpdateReason.BundleAuthorizationRequired);

        Assert.IsFalse(plans.Any(plan =>
            plan.Target.DriverGuid == new Guid("5bba83e5-f027-4ca7-bfd0-16358cc9e123")),
            "IccOverClocking must never be mislabeled as an Intel GOP update target.");
    }

    [TestMethod]
    public void X99ControllerCatalogCoversKnownLanAndSataFamiliesWithoutAuthorizingBlindUpdates()
    {
        foreach (Guid guid in new[]
        {
            new Guid("47b9e36f-9300-4be2-b749-e0f34f3cd4ee"), // ASM106xInitDXE
            new Guid("e0b5a13b-3abf-4724-a650-b72eb4f7f68e"), // Atheros LAN UEFI
            new Guid("e730cf73-bb99-42bf-bcb1-11786c3d25ad"), // Atheros LAN
            new Guid("93761039-4c9a-42fe-ae98-5dd5652f931e"), // Killer LAN UEFI
            new Guid("c101a46d-7487-45e8-8743-c7d2f4648a17"), // Killer LAN
            new Guid("793ba4eb-a6e9-4526-996d-79393f51b443")  // OEM RAID Driver
        })
        {
            Assert.IsTrue(X99UefiDriverUpdateCatalog.IsManagedGuid(guid));
        }

        Assert.IsFalse(X99UefiDriverUpdateCatalog.IsManagedGuid(
            new Guid("5bba83e5-f027-4ca7-bfd0-16358cc9e123")));
    }

    [TestMethod]
    public void X99ReviewedRst132TransitionPlansAndExecutesInPlaceWithoutChangingUnrelatedBytes()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rst-13.2.0.2134.ffs"));
        byte[] source = X99DriverImage(oldFfs);
        byte[] sourceBefore = source.ToArray();
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);

        X99UefiDriverUpdatePlan plan = AssertExactlyOne(X99UefiDriverUpdatePlanner.Plan(source, image));
        Assert.AreEqual(X99UefiDriverUpdateDisposition.Ready, plan.Disposition);
        Assert.AreEqual("intel-rst-13.2-to-14.8", plan.TransitionId);
        Assert.AreEqual("13.2.0.2134", plan.CurrentVersion);
        Assert.AreEqual("14.8.0.2377", plan.CandidateVersion);
        Assert.AreEqual("intel-rst-14.8.0.2377", plan.CandidateId);
        Assert.AreEqual(
            "9AE78E96A20D5A95EA616C51B2A4CF93CFE42FAA13FB94F19F3982D2AEAC8872",
            plan.CandidateSha256);
        Assert.IsTrue(plan.CanApply);
        Assert.AreEqual(UefiFirmwareVolumeMutationStrategy.InPlace, plan.MutationStrategy);
        Assert.AreEqual(UefiDriverMutationFeasibility.InPlace, plan.GenericPlan?.Mutation?.Feasibility);

        byte[] candidate = X99UefiDriverUpdatePlanner.LoadCandidate(plan.CandidateId!);
        byte[] output = X99UefiDriverImageUpdater.Apply(source, plan);
        CollectionAssert.AreEqual(sourceBefore, source, "The updater must never mutate the input buffer.");
        Assert.AreEqual(source.Length, output.Length);
        Assert.IsTrue(output.AsSpan(checked((int)plan.Target.FileOffset), candidate.Length).SequenceEqual(candidate));

        int sourceNext = UefiFfsVolumeScanner.Align(
            0,
            checked((int)plan.Target.FileOffset + oldFfs.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        int candidateNext = UefiFfsVolumeScanner.Align(
            0,
            checked((int)plan.Target.FileOffset + candidate.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        int mutationEnd = Math.Max(sourceNext, candidateNext);
        Assert.IsTrue(source.AsSpan(0, checked((int)plan.Target.FileOffset))
            .SequenceEqual(output.AsSpan(0, checked((int)plan.Target.FileOffset))));
        Assert.IsTrue(source.AsSpan(mutationEnd).SequenceEqual(output.AsSpan(mutationEnd)));

        BiosImage updated = BiosImageLoader.Analyze(output);
        BiosImageLoader.EnsureValidBiosImage(updated);
        UefiDriverInfo updatedDriver = updated.UefiDrivers.Drivers.Single(driver =>
            driver.FileGuid == plan.Target.DriverGuid &&
            driver.FileOffset == plan.Target.FileOffset);
        Assert.AreEqual(plan.CandidateSha256, updatedDriver.Sha256);
        X99UefiDriverUpdatePlan updatedPlan = updated.X99UefiDriverUpdates.Single(item =>
            item.Target.DriverGuid == plan.Target.DriverGuid &&
            item.Target.FileOffset == updatedDriver.FileOffset);
        Assert.AreEqual(X99UefiDriverUpdateDisposition.UpToDate, updatedPlan.Disposition);
        Assert.AreEqual("14.8.0.2377", updatedPlan.CurrentVersion);
        Assert.AreEqual(image.TurboBoostUnlock.HasXeonE5V3CpuPatch, updated.TurboBoostUnlock.HasXeonE5V3CpuPatch);
        CollectionAssert.AreEqual(
            image.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray(),
            updated.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray());
    }

    [TestMethod]
    public void X99Rste46To555TransitionExecutesWhenTargetCanGrowIntoFreeTail()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rste-4.6.0.1018.ffs"));
        byte[] source = X99DriverImage(oldFfs);
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);

        X99UefiDriverUpdatePlan plan = AssertExactlyOne(X99UefiDriverUpdatePlanner.Plan(source, image));

        Assert.AreEqual(X99UefiDriverUpdateDisposition.Ready, plan.Disposition);
        Assert.AreEqual("intel-rste-4.6-to-5.5.5", plan.TransitionId);
        Assert.AreEqual("RSTe", plan.Branch);
        Assert.AreEqual("4.6.0.1018", plan.CurrentVersion);
        Assert.AreEqual("5.5.5.1005", plan.CandidateVersion);
        Assert.AreEqual(UefiFirmwareVolumeMutationStrategy.InPlace, plan.MutationStrategy);
        Assert.IsTrue(plan.CanApply);

        byte[] output = X99UefiDriverImageUpdater.Apply(source, plan);
        BiosImage updated = BiosImageLoader.Analyze(output);
        BiosImageLoader.EnsureValidBiosImage(updated);
        UefiDriverInfo replacement = updated.UefiDrivers.Drivers.Single(driver =>
            driver.FileGuid == plan.Target.DriverGuid &&
            string.Equals(driver.Sha256, plan.CandidateSha256, StringComparison.Ordinal));
        Assert.AreEqual(plan.Target.FileOffset, replacement.FileOffset);
        X99UefiDriverUpdatePlan updatedPlan = updated.X99UefiDriverUpdates.Single(item =>
            item.Target.DriverGuid == plan.Target.DriverGuid &&
            item.Target.FileOffset == replacement.FileOffset);
        Assert.AreEqual(X99UefiDriverUpdateDisposition.UpToDate, updatedPlan.Disposition);
        Assert.AreEqual("5.5.5.1005", updatedPlan.CurrentVersion);
        Assert.AreEqual(image.TurboBoostUnlock.HasXeonE5V3CpuPatch,
            updated.TurboBoostUnlock.HasXeonE5V3CpuPatch);
        CollectionAssert.AreEqual(
            image.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray(),
            updated.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray());
    }

    [TestMethod]
    public void X99RsteUpdateConsumesAdjacentPadWithoutMovingFollowingDxe()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rste-4.6.0.1018.ffs"));
        byte[] pad = X99SyntheticFfs(
            new Guid("e4536585-7909-4a60-b5c6-ecdea6ebfb54"),
            UefiPiCode.FfsPad,
            32 * 1024);
        Guid followingGuid = new("66a9e9b3-2d52-4696-8fd4-44c59f70f78b");
        byte[] following = X99SyntheticFfs(followingGuid, UefiPiCode.FfsDriver, 256);
        byte[] source = X99DriverImage(oldFfs, pad, following);
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);
        UefiDriverInfo followingBefore = image.UefiDrivers.Drivers.Single(driver => driver.FileGuid == followingGuid);

        X99UefiDriverUpdatePlan plan = AssertExactlyOne(X99UefiDriverUpdatePlanner.Plan(source, image));

        Assert.AreEqual(X99UefiDriverUpdateDisposition.Ready, plan.Disposition);
        Assert.AreEqual(UefiFirmwareVolumeMutationStrategy.GrowIntoAdjacentFreeSpace, plan.MutationStrategy);
        Assert.IsTrue(plan.CanApply);

        byte[] output = X99UefiDriverImageUpdater.Apply(source, plan);
        BiosImage updated = BiosImageLoader.Analyze(output);
        BiosImageLoader.EnsureValidBiosImage(updated);
        UefiDriverInfo followingAfter = updated.UefiDrivers.Drivers.Single(driver => driver.FileGuid == followingGuid);
        Assert.AreEqual(followingBefore.FileOffset, followingAfter.FileOffset);
        Assert.AreEqual(followingBefore.Sha256, followingAfter.Sha256);
        Assert.IsTrue(source.AsSpan(checked((int)followingBefore.FileOffset))
            .SequenceEqual(output.AsSpan(checked((int)followingAfter.FileOffset))));

        FirmwareVolume volume = updated.Volumes.Single(item => item.Offset == plan.Target.VolumeOffset);
        Assert.IsTrue(UefiFfsVolumeScanner.TryReadFiles(
            output,
            volume,
            CancellationToken.None,
            out _,
            out IReadOnlyList<UefiFfsFileLocation> files));
        Assert.IsTrue(files.Any(file => file.Type == UefiPiCode.FfsPad));
    }

    [TestMethod]
    public void X99RsteUpdateRebuildsFirmwareVolumeWhenOnlyMovableDxeMustShift()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rste-4.6.0.1018.ffs"));
        Guid followingGuid = new("ed0ccca6-8050-4ee2-82f8-9356b5c34c4d");
        byte[] following = X99SyntheticFfs(followingGuid, UefiPiCode.FfsDriver, 256);
        byte[] source = X99DriverImage(oldFfs, following);
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);
        UefiDriverInfo followingBefore = image.UefiDrivers.Drivers.Single(driver => driver.FileGuid == followingGuid);

        X99UefiDriverUpdatePlan plan = AssertExactlyOne(X99UefiDriverUpdatePlanner.Plan(source, image));

        Assert.AreEqual(X99UefiDriverUpdateDisposition.Ready, plan.Disposition);
        Assert.AreEqual(UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume, plan.MutationStrategy);
        Assert.IsTrue(plan.CanApply);

        byte[] output = X99UefiDriverImageUpdater.Apply(source, plan);
        BiosImage updated = BiosImageLoader.Analyze(output);
        BiosImageLoader.EnsureValidBiosImage(updated);
        UefiDriverInfo followingAfter = updated.UefiDrivers.Drivers.Single(driver => driver.FileGuid == followingGuid);
        Assert.IsTrue(followingAfter.FileOffset > followingBefore.FileOffset);
        Assert.AreEqual(followingBefore.Sha256, followingAfter.Sha256);

        const int volumeLength = 512 * 1024;
        Assert.IsTrue(source.AsSpan(volumeLength).SequenceEqual(output.AsSpan(volumeLength)),
            "A firmware-volume rebuild must not change bytes outside the target FV.");
        Assert.AreEqual(image.TurboBoostUnlock.HasXeonE5V3CpuPatch,
            updated.TurboBoostUnlock.HasXeonE5V3CpuPatch);
        CollectionAssert.AreEqual(
            image.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray(),
            updated.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray());
    }

    [TestMethod]
    public void VolumeScannerRejectsOversizedExtendedHeaderWithoutOverflow()
    {
        const int volumeOffset = 0x10000;
        const int volumeLength = 512 * 1024;
        byte[] source = X99SpiDriverImage(volumeOffset, volumeLength);
        BinaryPrimitives.WriteUInt16LittleEndian(
            source.AsSpan(volumeOffset + UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderOffsetOffset),
            0x100);
        BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(volumeOffset + 0x100 + UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderSizeOffset),
            uint.MaxValue);
        FirmwareVolume volume = new(
            volumeOffset,
            volumeLength,
            UefiFirmwareSpecification.StandardFirmwareFileSystems[1],
            true);

        bool parsed = UefiFfsVolumeScanner.TryReadFiles(
            source,
            volume,
            CancellationToken.None,
            out _,
            out _);

        Assert.IsFalse(parsed);
    }

    [TestMethod]
    public void FirmwareVolumeRebuildRequiresRebaseWhenPeimRelocationIsNotProvable()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rste-4.6.0.1018.ffs"));
        Guid peiGuid = new("5b2f46e7-5229-45cc-9d1c-4ea58e61c940");
        byte[] pei = X99SyntheticFfs(peiGuid, type: 0x06, size: 256);
        byte[] source = X99DriverImage(oldFfs, pei);
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);
        UefiDriverInfo targetDriver = image.UefiDrivers.Drivers.Single(driver =>
            driver.FileGuid == new Guid("91b4d9c1-141c-4824-8d02-3c298e36eb3f"));
        UefiDriverMutationTarget target = UefiDriverMutationTarget.From(targetDriver);
        byte[] candidate = X99UefiDriverUpdatePlanner.LoadCandidate("intel-rste-5.5.5.1005");

        UefiFirmwareVolumeReplacementPlan plan = UefiFirmwareVolumeRebuilder.PlanReplacement(
            source,
            image,
            target,
            candidate);

        Assert.AreEqual(UefiFirmwareVolumeMutationStrategy.RequiresRebase, plan.Strategy);
        Assert.AreEqual(UefiFirmwareVolumeMutationReason.PeiRebaseNotProvable, plan.Reason);
        Assert.IsFalse(plan.CanApply);
        Assert.Throws<InvalidDataException>(() => UefiFirmwareVolumeRebuilder.ApplyReplacement(
            source,
            image,
            target,
            candidate,
            UefiFirmwareVolumeMutationStrategy.RequiresRebase));
    }

    [TestMethod]
    public void FirmwareVolumeRebuildRebasesProvableDirectPe32XipPeim()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rste-4.6.0.1018.ffs"));
        const int fullImageLength = BiosImageLoader.MinBiosImageBytes;
        const int volumeOffset = 0x10000;
        const int volumeLength = 512 * 1024;
        const int firstFileRelativeOffset = 72;
        int targetOffset = checked(volumeOffset + firstFileRelativeOffset);
        int peimOffset = UefiFfsVolumeScanner.Align(
            volumeOffset,
            checked(targetOffset + oldFfs.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        Guid peimGuid = new("2e6503aa-39c8-4f7f-a52f-1e9af9650512");
        byte[] peim = X99XipPe32Peim(peimGuid, peimOffset, fullImageLength);
        byte[] source = X99SpiDriverImage(volumeOffset, volumeLength, oldFfs, peim);
        BiosImage image = X99SyntheticSpiBiosImage(source, volumeOffset, volumeLength);
        byte[] candidate = X99UefiDriverUpdatePlanner.LoadCandidate("intel-rste-5.5.5.1005");
        var target = new UefiDriverMutationTarget(
            new Guid("91b4d9c1-141c-4824-8d02-3c298e36eb3f"),
            volumeOffset,
            targetOffset,
            Convert.ToHexString(SHA256.HashData(oldFfs)));

        UefiFirmwareVolumeReplacementPlan plan = UefiFirmwareVolumeRebuilder.PlanReplacement(
            source,
            image,
            target,
            candidate);

        Assert.AreEqual(UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume, plan.Strategy);
        Assert.AreEqual(UefiFirmwareVolumeMutationReason.None, plan.Reason);
        Assert.AreEqual(1, plan.MovedFileCount);
        byte[] output = UefiFirmwareVolumeRebuilder.ApplyReplacement(
            source,
            image,
            target,
            candidate,
            UefiFirmwareVolumeMutationStrategy.RebuildFirmwareVolume);

        FirmwareVolume volume = image.Volumes.Single();
        Assert.IsTrue(UefiFfsVolumeScanner.TryReadFiles(
            output,
            volume,
            CancellationToken.None,
            out UefiFfsVolumeLayout layout,
            out IReadOnlyList<UefiFfsFileLocation> outputFiles));
        Assert.AreEqual(byte.MaxValue, layout.EraseByte);
        UefiFfsFileLocation movedPeim = outputFiles.Single(file => file.Guid == peimGuid);
        Assert.IsTrue(movedPeim.Offset > peimOffset);
        long delta = movedPeim.Offset - peimOffset;

        ulong flashBase = 0x1_0000_0000UL - (ulong)fullImageLength;
        const int pePayloadWithinFfs = AmiSecureBootSpecification.FfsFileHeaderBytes + UefiPiCode.CommonSectionHeaderBytes;
        ulong oldImageBase = flashBase + (ulong)peimOffset + pePayloadWithinFfs;
        ulong newImageBase = flashBase + (ulong)movedPeim.Offset + pePayloadWithinFfs;
        Assert.AreEqual(oldImageBase + (ulong)delta, newImageBase);

        int peStart = checked(movedPeim.Offset + pePayloadWithinFfs);
        const int peHeaderOffset = 0x40;
        int optionalOffset = peStart + peHeaderOffset + UefiPiCode.PeOptionalHeaderOffset;
        uint imageBase = BinaryPrimitives.ReadUInt32LittleEndian(
            output.AsSpan(optionalOffset + 28, sizeof(uint)));
        Assert.AreEqual(checked((uint)newImageBase), imageBase);
        uint relocatedPointer = BinaryPrimitives.ReadUInt32LittleEndian(
            output.AsSpan(peStart + 0x1A0, sizeof(uint)));
        Assert.AreEqual(checked((uint)(newImageBase + 0x1A8)), relocatedPointer);
        Assert.IsTrue(UefiFfsFileParser.TryRead(
            output,
            movedPeim.Offset,
            checked(movedPeim.Offset + movedPeim.Size),
            byte.MaxValue,
            out FfsFileHeaderInfo movedHeader));
        Assert.AreEqual(FfsFileState.DataValid, movedHeader.State);
    }

    [TestMethod]
    public void X99RestrictedDriverClassesCannotBecomeAutomaticByGuidAlone()
    {
        Assert.AreEqual(
            X99UefiDriverUpdateReason.HardwareAuthorizationRequired,
            X99UefiDriverUpdateCatalog.FindRestriction(new Guid("4953f720-006d-41f5-990d-0ac7742abb60"))?.Reason);
        Assert.AreEqual(
            X99UefiDriverUpdateReason.NoKnownUpgradeChain,
            X99UefiDriverUpdateCatalog.FindRestriction(new Guid("2eaa04aa-5eed-4c27-b9ee-26916ec25a8f"))?.Reason);
        Assert.AreEqual(
            X99UefiDriverUpdateReason.BundleAuthorizationRequired,
            X99UefiDriverUpdateCatalog.FindRestriction(new Guid("634e8db5-c432-43be-a653-9ca2922cc458"))?.Reason);
        Assert.AreEqual(
            X99UefiDriverUpdateReason.NoKnownUpgradeChain,
            X99UefiDriverUpdateCatalog.FindRestriction(new Guid("85794f12-c3f3-466e-9726-30dc23ac3e02"))?.Reason);
    }

    [TestMethod]
    public void X99CandidateResourcesAreExactAndCatalogBound()
    {
        byte[] rst = X99UefiDriverUpdateCatalog.LoadCandidate("intel-rst-14.8.0.2377");
        byte[] rste = X99UefiDriverUpdateCatalog.LoadCandidate("intel-rste-5.5.5.1005");

        Assert.AreEqual(87793, rst.Length);
        Assert.AreEqual(104067, rste.Length);
        Assert.AreEqual(
            "9AE78E96A20D5A95EA616C51B2A4CF93CFE42FAA13FB94F19F3982D2AEAC8872",
            Convert.ToHexString(SHA256.HashData(rst)));
        Assert.AreEqual(
            "975764C0A94A14DD476A53CEF2B999555CD49E43FDC4B29D1AB153577F215CB7",
            Convert.ToHexString(SHA256.HashData(rste)));
    }

    [TestMethod]
    public void X99ExecutorRejectsCallerForgedReadyPlan()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rst-13.2.0.2134.ffs"));
        byte[] source = X99DriverImage(oldFfs);
        BiosImage image = BiosImageLoader.Analyze(source);
        X99UefiDriverUpdatePlan plan = AssertExactlyOne(X99UefiDriverUpdatePlanner.Plan(source, image));
        X99UefiDriverUpdatePlan forged = plan with { TransitionId = "forged-transition" };

        InvalidDataException error = Assert.Throws<InvalidDataException>(() =>
            X99UefiDriverImageUpdater.Apply(source, forged));

        Assert.AreEqual(OperationError.UefiDriverUpdateUnsupported, error.Message);
    }

    [TestMethod]
    public async Task X99FileExecutorDoesNotOverwritePreExistingDestination()
    {
        byte[] oldFfs = File.ReadAllBytes(RepositoryTestFiles.Find(
            "tests", "DriverUpdates", "intel-rst-13.2.0.2134.ffs"));
        byte[] source = X99DriverImage(oldFfs);
        BiosImage image = BiosImageLoader.Analyze(source);
        X99UefiDriverUpdatePlan plan = AssertExactlyOne(X99UefiDriverUpdatePlanner.Plan(source, image));
        string sourcePath = Path.Combine(Path.GetTempPath(), "XeonV3Control2-driver-source-" + Guid.NewGuid().ToString("N") + ".bin");
        string destination = Path.Combine(Path.GetTempPath(), "XeonV3Control2-driver-destination-" + Guid.NewGuid().ToString("N") + ".bin");
        byte[] sentinel = [0x58, 0x45, 0x4F, 0x4E];
        await File.WriteAllBytesAsync(sourcePath, source);
        await File.WriteAllBytesAsync(destination, sentinel);
        try
        {
            await Assert.ThrowsAsync<IOException>(() =>
                X99UefiDriverImageUpdater.ApplyFileAsync(sourcePath, destination, plan));
            CollectionAssert.AreEqual(sentinel, await File.ReadAllBytesAsync(destination));
            CollectionAssert.AreEqual(source, await File.ReadAllBytesAsync(sourcePath));
        }
        finally
        {
            File.Delete(sourcePath);
            File.Delete(destination);
        }
    }

    [TestMethod]
    public void MutationPlannerRejectsInPlaceShrinkThatWouldExposeFreeSpaceBeforeFollowingFfs()
    {
        byte[] data = FirmwareTests.Image();
        const int firstFileOffset = 72;
        Guid targetGuid = new("11223344-5566-7788-99aa-bbccddeeff00");
        Guid followingGuid = new("00112233-4455-6677-8899-aabbccddeeff");
        byte[] target = DriverFfs(targetGuid, 32);
        byte[] following = DriverFfs(followingGuid, 24);
        target.CopyTo(data, firstFileOffset);
        following.CopyTo(data, firstFileOffset + 32);
        BiosImage image = BiosImageLoader.Analyze(data);

        UefiDriverMutationPlan plan = UefiDriverMutationPlanner.PlanReplace(
            data,
            image,
            UefiDriverMutationTarget.From(image.UefiDrivers.Drivers.Single(driver => driver.FileGuid == targetGuid)),
            DriverFfs(targetGuid, 24));

        Assert.AreEqual(UefiDriverMutationFeasibility.RequiresRepack, plan.Feasibility);
        Assert.AreEqual(UefiDriverMutationReason.SlotBoundaryRequiresRepack, plan.Reason);
    }

    [TestMethod]
    public void MutationBackendPlansOperationsButCannotApplyThem()
    {
        Type planner = typeof(UefiDriverMutationPlanner);
        var methods = planner.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        Assert.IsTrue(methods.Any(method => method.Name == "PlanAdd"));
        Assert.IsTrue(methods.Any(method => method.Name == "PlanReplace"));
        Assert.IsTrue(methods.Any(method => method.Name == "PlanRemove"));
        Assert.IsFalse(methods
            .Any(method => method.Name.Contains("Apply", StringComparison.OrdinalIgnoreCase) ||
                           method.Name.Contains("Execute", StringComparison.OrdinalIgnoreCase) ||
                           method.Name.Contains("Write", StringComparison.OrdinalIgnoreCase)));
    }

    private static byte[] X99SpiDriverImage(int volumeOffset, int volumeLength, params byte[][] files)
    {
        if (volumeOffset < 0x1000 || volumeLength < 4096 ||
            volumeOffset > BiosImageLoader.MinBiosImageBytes - volumeLength)
        {
            throw new ArgumentOutOfRangeException(nameof(volumeOffset));
        }

        byte[] data = new byte[BiosImageLoader.MinBiosImageBytes];
        data.AsSpan().Fill(byte.MaxValue);
        Span<byte> volume = data.AsSpan(volumeOffset, volumeLength);
        UefiFirmwareSpecification.StandardFirmwareFileSystems[1].TryWriteBytes(
            volume[UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset..]);
        BinaryPrimitives.WriteUInt64LittleEndian(
            volume[UefiFirmwareSpecification.FirmwareVolumeLengthOffset..],
            checked((ulong)volumeLength));
        UefiFirmwareSpecification.FirmwareVolumeSignature.CopyTo(
            volume[UefiFirmwareSpecification.FirmwareVolumeSignatureOffset..]);
        BinaryPrimitives.WriteUInt32LittleEndian(
            volume[UefiFirmwareSpecification.FirmwareVolumeAttributesOffset..],
            UefiFirmwareSpecification.FirmwareVolumeErasePolarityMask);
        BinaryPrimitives.WriteUInt16LittleEndian(
            volume[UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset..], 72);
        BinaryPrimitives.WriteUInt16LittleEndian(
            volume[UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderOffsetOffset..], 0);
        volume[UefiFirmwareSpecification.FirmwareVolumeReservedOffset] = 0;
        volume[UefiFirmwareSpecification.FirmwareVolumeRevisionOffset] = UefiFirmwareSpecification.FirmwareVolumeRevision2;
        BinaryPrimitives.WriteUInt32LittleEndian(
            volume[UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            volume[(UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset + sizeof(uint))..],
            checked((uint)volumeLength));
        volume.Slice(UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset +
            UefiFirmwareSpecification.FirmwareVolumeBlockMapEntryBytes,
            UefiFirmwareSpecification.FirmwareVolumeBlockMapEntryBytes).Clear();

        int cursor = checked(volumeOffset + 72);
        foreach (byte[] file in files)
        {
            file.CopyTo(data, cursor);
            cursor = UefiFfsVolumeScanner.Align(
                volumeOffset,
                checked(cursor + file.Length),
                AmiSecureBootSpecification.FfsAlignmentBytes);
        }
        RecalculateVolumeChecksum(data, volumeOffset);
        return data;
    }

    private static BiosImage X99SyntheticSpiBiosImage(byte[] source, int volumeOffset, int volumeLength)
    {
        string sha = Convert.ToHexString(SHA256.HashData(source));
        return new BiosImage(
            "synthetic-spi.bin",
            source.Length,
            sha,
            ImageKind.IntelSpiImage,
            [new FirmwareVolume(volumeOffset, volumeLength, UefiFirmwareSpecification.StandardFirmwareFileSystems[1], true)],
            [
                new FlashRegion(FlashRegionKind.Descriptor, 0, 0x1000, true),
                new FlashRegion(FlashRegionKind.BIOS, volumeOffset, source.Length - volumeOffset, true)
            ],
            ["X99"],
            []);
    }

    private static byte[] X99XipPe32Peim(Guid guid, int fileOffset, int fullImageLength)
    {
        const int peSize = 0x200;
        const int sectionHeaderBytes = UefiPiCode.CommonSectionHeaderBytes;
        int fileSize = checked(AmiSecureBootSpecification.FfsFileHeaderBytes + sectionHeaderBytes + peSize);
        byte[] file = X99SyntheticFfs(
            guid,
            type: 0x06,
            size: fileSize,
            attributes: AmiSecureBootSpecification.FfsChecksumAttribute);
        Span<byte> section = file.AsSpan(AmiSecureBootSpecification.FfsFileHeaderBytes);
        int sectionSize = checked(sectionHeaderBytes + peSize);
        section[0] = unchecked((byte)sectionSize);
        section[1] = unchecked((byte)(sectionSize >> 8));
        section[2] = unchecked((byte)(sectionSize >> 16));
        section[AmiSecureBootSpecification.SectionTypeOffset] = UefiPiCode.SectionPe32;

        Span<byte> pe = section.Slice(sectionHeaderBytes, peSize);
        // The enclosing erased FFS is 0xFF-filled, but unspecified PE header fields must start at zero.
        pe.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(pe, UefiPiCode.DosMagic);
        BinaryPrimitives.WriteInt32LittleEndian(pe[UefiPiCode.DosPeOffsetOffset..], 0x40);
        const int peOffset = 0x40;
        BinaryPrimitives.WriteUInt32LittleEndian(pe[peOffset..], UefiPiCode.PeSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(pe[(peOffset + UefiPiCode.PeMachineOffset)..], UefiPiCode.PeMachineIa32);
        BinaryPrimitives.WriteUInt16LittleEndian(pe[(peOffset + UefiPiCode.PeNumberOfSectionsOffset)..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(pe[(peOffset + UefiPiCode.PeOptionalHeaderSizeOffset)..], 0xE0);
        int optionalOffset = peOffset + UefiPiCode.PeOptionalHeaderOffset;
        BinaryPrimitives.WriteUInt16LittleEndian(pe[optionalOffset..], UefiPiCode.PeOptionalMagic32);

        ulong flashBase = 0x1_0000_0000UL - checked((ulong)fullImageLength);
        ulong imageBase = checked(flashBase + (ulong)fileOffset +
            AmiSecureBootSpecification.FfsFileHeaderBytes + sectionHeaderBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(optionalOffset + 28)..], checked((uint)imageBase));
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(optionalOffset + 32)..], 0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(optionalOffset + 36)..], 0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(optionalOffset + 56)..], 0x1E0);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(optionalOffset + 60)..], 0x1A0);
        BinaryPrimitives.WriteUInt16LittleEndian(pe[(optionalOffset + UefiPiCode.PeOptionalSubsystemOffset)..],
            UefiPiCode.PeSubsystemEfiBootServiceDriver);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(optionalOffset + 92)..], 16);
        int relocDirectory = optionalOffset + 96 + 5 * 8;
        BinaryPrimitives.WriteUInt32LittleEndian(pe[relocDirectory..], 0x1C0);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(relocDirectory + sizeof(uint))..], 12);

        int sectionTable = optionalOffset + 0xE0;
        WritePeSection(pe, sectionTable, 0x1A0, 0x20, 0x60000020);
        WritePeSection(pe, sectionTable + UefiPiCode.PeSectionHeaderBytes, 0x1C0, 0x20, 0x42000040);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[0x1A0..], checked((uint)(imageBase + 0x1A8)));
        BinaryPrimitives.WriteUInt32LittleEndian(pe[0x1C0..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[0x1C4..], 12);
        BinaryPrimitives.WriteUInt16LittleEndian(pe[0x1C8..], (ushort)((3 << 12) | 0x1A0));
        BinaryPrimitives.WriteUInt16LittleEndian(pe[0x1CA..], 0);

        if (!UefiFfsChecksum.TryRecalculate(file, AmiSecureBootSpecification.FfsFileHeaderBytes))
        {
            throw new InvalidDataException("Synthetic XIP PEIM checksum recalculation failed.");
        }
        return file;
    }

    private static void WritePeSection(Span<byte> pe, int headerOffset, uint rva, uint size, uint characteristics)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(headerOffset + 8)..], size);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(headerOffset + 12)..], rva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(headerOffset + UefiPiCode.PeSectionRawSizeOffset)..], size);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(headerOffset + UefiPiCode.PeSectionRawPointerOffset)..], rva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(headerOffset + UefiPiCode.PeSectionCharacteristicsOffset)..], characteristics);
    }

    private static byte[] X99DriverImage(params byte[][] files)
    {
        ArgumentNullException.ThrowIfNull(files);
        const int volumeLength = 512 * 1024;
        const int firstFileOffset = 72;
        byte[] data = FirmwareTests.Image();
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeLengthOffset),
            checked((ulong)volumeLength));
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeAttributesOffset),
            UefiFirmwareSpecification.FirmwareVolumeErasePolarityMask);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset + sizeof(uint)),
            checked((uint)volumeLength));
        Array.Fill(data, byte.MaxValue, firstFileOffset, volumeLength - firstFileOffset);

        int cursor = firstFileOffset;
        foreach (byte[] file in files)
        {
            ArgumentNullException.ThrowIfNull(file);
            if (file.Length < AmiSecureBootSpecification.FfsFileHeaderBytes || cursor > volumeLength - file.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(files));
            }
            file.CopyTo(data, cursor);
            cursor = UefiFfsVolumeScanner.Align(
                0,
                checked(cursor + file.Length),
                AmiSecureBootSpecification.FfsAlignmentBytes);
        }

        "X99"u8.CopyTo(data.AsSpan(volumeLength + 128));
        RecalculateVolumeChecksum(data);
        return data;
    }

    private static byte[] X99SyntheticFfs(Guid guid, byte type, int size, byte attributes = 0)
    {
        if (size < AmiSecureBootSpecification.FfsFileHeaderBytes ||
            size > AmiSecureBootSpecification.MaximumNormalFfsFileBytes ||
            (attributes & ~AmiSecureBootSpecification.FfsKnownAttributeMask) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(size));
        }

        byte[] file = new byte[size];
        file.AsSpan().Fill(byte.MaxValue);
        guid.TryWriteBytes(file);
        file[AmiSecureBootSpecification.FfsTypeOffset] = type;
        file[AmiSecureBootSpecification.FfsAttributesOffset] = attributes;
        file[AmiSecureBootSpecification.FfsSizeOffset] = unchecked((byte)size);
        file[AmiSecureBootSpecification.FfsSizeOffset + 1] = unchecked((byte)(size >> 8));
        file[AmiSecureBootSpecification.FfsSizeOffset + 2] = unchecked((byte)(size >> 16));
        file[AmiSecureBootSpecification.FfsStateOffset] =
            unchecked((byte)~AmiSecureBootSpecification.FfsDataValidPrerequisiteMask);
        if (!UefiFfsChecksum.TryRecalculate(file, AmiSecureBootSpecification.FfsFileHeaderBytes))
        {
            throw new InvalidDataException("Synthetic FFS checksum recalculation failed.");
        }
        return file;
    }

    private static void RecalculateVolumeChecksum(byte[] data, int volumeOffset = 0)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(volumeOffset + UefiFirmwareSpecification.FirmwareVolumeChecksumOffset),
            0);
        int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
            data.AsSpan(volumeOffset + UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset));
        uint sum = 0;
        for (int offset = 0; offset < headerLength; offset += sizeof(ushort))
        {
            sum += BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(volumeOffset + offset));
        }
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(volumeOffset + UefiFirmwareSpecification.FirmwareVolumeChecksumOffset),
            unchecked((ushort)-sum));
    }

    private static T AssertExactlyOne<T>(IReadOnlyList<T> items)
    {
        Assert.HasCount(1, items);
        return items[0];
    }

    private static byte[] DriverFfs(Guid guid) =>
        DriverFfs(guid, AmiSecureBootSpecification.FfsFileHeaderBytes);

    private static byte[] DriverFfs(Guid guid, int size)
    {
        if (size < AmiSecureBootSpecification.FfsFileHeaderBytes || size >= 0x00FF_FFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(size));
        }
        byte[] file = new byte[size];
        guid.TryWriteBytes(file);
        file[AmiSecureBootSpecification.FfsFileChecksumOffset] = AmiSecureBootSpecification.FfsFixedFileChecksum;
        file[AmiSecureBootSpecification.FfsTypeOffset] = UefiPiCode.FfsDriver;
        file[AmiSecureBootSpecification.FfsAttributesOffset] = 0;
        file[AmiSecureBootSpecification.FfsSizeOffset] = checked((byte)size);
        file[AmiSecureBootSpecification.FfsSizeOffset + 1] = checked((byte)(size >> 8));
        file[AmiSecureBootSpecification.FfsSizeOffset + 2] = checked((byte)(size >> 16));
        file[AmiSecureBootSpecification.FfsStateOffset] =
            AmiSecureBootSpecification.FfsDataValidPrerequisiteMask;

        byte sum = 0;
        for (int index = 0; index < file.Length; index++)
        {
            if (index is AmiSecureBootSpecification.FfsFileChecksumOffset or AmiSecureBootSpecification.FfsStateOffset)
            {
                continue;
            }
            sum = unchecked((byte)(sum + file[index]));
        }
        file[AmiSecureBootSpecification.FfsHeaderChecksumOffset] = unchecked((byte)-sum);
        return file;
    }
}
