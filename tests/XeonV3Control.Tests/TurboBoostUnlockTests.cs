using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class TurboBoostUnlockTests
{
    [TestMethod]
    public async Task ReferenceX99ImageFindsValidated306F2CpuPatchWithoutClaimingUnlock()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        TurboBoostUnlockReport report = image.TurboBoostUnlock;

        Assert.IsFalse(report.Status is TurboBoostUnlockStatus.Detected or TurboBoostUnlockStatus.Possible);
        Assert.IsEmpty(report.Findings);
        Assert.IsEmpty(report.Modules);
        Assert.IsEmpty(report.ForeignUnlockModules);

        IntelMicrocodeInfo patch = AssertExactlyOne(report.XeonE5V3CpuPatches);
        Assert.AreEqual(0x000306F2u, patch.ProcessorSignature);
        Assert.AreEqual(0x0000003Du, patch.UpdateRevision);
        Assert.AreEqual(TurboBoostUnlockReport.XeonE5V3ProcessorFlags, patch.ProcessorFlags);
        Assert.IsTrue(TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(patch));
        Assert.AreEqual(0x8400, patch.Size);
        Assert.AreEqual(new DateOnly(2018, 4, 20), patch.Date);
        Assert.AreEqual(
            "711E1F2274183AD14C0597759CF4BADD27AAFF46734B842BAB2850DDF00A640D",
            patch.Sha256);
        Assert.AreNotEqual(Guid.Empty, patch.FileGuid);

        CpuPatchRemovalPlan plan = AssertExactlyOne(report.CpuPatchRemovalPlans);
        Assert.AreEqual(CpuPatchRemovalPlanStatus.Ready, plan.Status);
        Assert.AreEqual(CpuPatchRemovalReason.Ready, plan.Reason);
        Assert.IsTrue(plan.CanApply);
        Assert.AreEqual(image.Sha256, plan.SourceImageSha256);
        Assert.AreEqual(patch.Sha256, plan.PatchSha256);
        Assert.AreEqual(patch.Offset, plan.PatchOffset);
        Assert.AreEqual(patch.Size, plan.PatchSize);
        Assert.AreEqual(patch.ProcessorFlags, plan.ProcessorFlags);
        Assert.IsTrue(plan.RelativePatchOffset >= AmiSecureBootSpecification.FfsFileHeaderBytes);
        Assert.IsTrue(plan.FileSize > patch.Size);
        Assert.IsTrue(plan.MicrocodeCount > 1);
        Assert.IsTrue(plan.FitOffset >= 0);
        Assert.AreEqual(plan.MicrocodeCount, plan.FitMicrocodeEntryCount);
    }

    [TestMethod]
    public async Task ReferenceX99CpuPatchRemovalProducesValidatedImageAndPreservesOtherMicrocodes()
    {
        string sourcePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(sourcePath);
        CpuPatchRemovalPlan plan = AssertExactlyOne(sourceImage.TurboBoostUnlock.CpuPatchRemovalPlans);
        IntelMicrocodeInfo removed = AssertExactlyOne(sourceImage.TurboBoostUnlock.XeonE5V3CpuPatches);
        string originalFileHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(sourcePath)));
        string destination = Path.Combine(
            Path.GetTempPath(),
            "XeonV3Control2-cpu-patch-" + Guid.NewGuid().ToString("N") + ".bin");

        try
        {
            BiosImage updated = await CpuPatchImageUpdater.RemoveFileAsync(sourcePath, destination, plan);

            Assert.AreEqual(sourceImage.Size, updated.Size);
            Assert.AreNotEqual(sourceImage.Sha256, updated.Sha256);
            Assert.AreEqual(
                "509B6DA151449BEACD6508430BF6B86638E7DEFF8C2034A94677129460CFD137",
                updated.Sha256);
            Assert.IsFalse(updated.TurboBoostUnlock.Microcodes.Any(item =>
                string.Equals(item.Sha256, removed.Sha256, StringComparison.OrdinalIgnoreCase)));
            Assert.IsFalse(updated.TurboBoostUnlock.Microcodes.Any(
                TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch));
            Assert.IsFalse(updated.TurboBoostUnlock.HasXeonE5V3CpuPatch);
            Assert.AreEqual(0, updated.TurboBoostUnlock.RemovableXeonE5V3CpuPatchCount);

            string[] expectedHashes = sourceImage.TurboBoostUnlock.Microcodes
                .Where(item => !string.Equals(item.Sha256, removed.Sha256, StringComparison.OrdinalIgnoreCase))
                .Select(item => item.Sha256)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            string[] actualHashes = updated.TurboBoostUnlock.Microcodes
                .Select(item => item.Sha256)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            CollectionAssert.AreEqual(expectedHashes, actualHashes);

            string sourceHashAfterUpdate = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(sourcePath)));
            Assert.AreEqual(originalFileHash, sourceHashAfterUpdate);
        }
        finally
        {
            File.Delete(destination);
        }
    }

    [TestMethod]
    public async Task CpuPatchRemovalRejectsSourceChangedAfterAnalysisWithoutCreatingOutput()
    {
        string fixture = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        string source = Path.Combine(Path.GetTempPath(), "XeonV3Control2-source-" + Guid.NewGuid().ToString("N") + ".bin");
        string destination = Path.Combine(Path.GetTempPath(), "XeonV3Control2-output-" + Guid.NewGuid().ToString("N") + ".bin");
        File.Copy(fixture, source);

        try
        {
            BiosImage image = await BiosImageLoader.LoadValidatedAsync(source);
            CpuPatchRemovalPlan plan = AssertExactlyOne(image.TurboBoostUnlock.CpuPatchRemovalPlans);
            byte[] changed = await File.ReadAllBytesAsync(source);
            changed[0] ^= 0x01;
            await File.WriteAllBytesAsync(source, changed);

            InvalidDataException error = await Assert.ThrowsAsync<InvalidDataException>(() =>
                CpuPatchImageUpdater.RemoveFileAsync(source, destination, plan));
            Assert.AreEqual(OperationError.CpuPatchSourceChanged, error.Message);
            Assert.IsFalse(File.Exists(destination));
        }
        finally
        {
            File.Delete(source);
            File.Delete(destination);
        }
    }


    [TestMethod]
    public async Task CpuPatchPlannerRefusesFirmwareVolumeWithBrokenHeaderChecksum()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        IntelMicrocodeInfo patch = AssertExactlyOne(image.TurboBoostUnlock.XeonE5V3CpuPatches);
        byte[] damaged = await File.ReadAllBytesAsync(path);

        int checksumOffset = checked((int)patch.VolumeOffset) + UefiFirmwareSpecification.FirmwareVolumeChecksumOffset;
        damaged[checksumOffset] ^= 0x01;
        string sha256 = Convert.ToHexString(SHA256.HashData(damaged));
        CpuPatchRemovalPlan plan = CpuPatchImageUpdater.PlanRemoval(damaged, sha256, patch);

        Assert.AreEqual(CpuPatchRemovalPlanStatus.UnsupportedLayout, plan.Status);
        Assert.AreEqual(CpuPatchRemovalReason.InvalidFirmwareVolume, plan.Reason);
        Assert.IsFalse(plan.CanApply);
    }

    [TestMethod]
    public async Task CpuPatchPlannerRefusesBrokenFitMapping()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        IntelMicrocodeInfo patch = AssertExactlyOne(image.TurboBoostUnlock.XeonE5V3CpuPatches);
        CpuPatchRemovalPlan baseline = AssertExactlyOne(image.TurboBoostUnlock.CpuPatchRemovalPlans);
        byte[] damaged = await File.ReadAllBytesAsync(path);

        damaged[checked((int)baseline.FitOffset) + IntelFirmwareInterfaceTableSpecification.TypeOffset] =
            IntelFirmwareInterfaceTableSpecification.MicrocodeType;
        string sha256 = Convert.ToHexString(SHA256.HashData(damaged));
        CpuPatchRemovalPlan plan = CpuPatchImageUpdater.PlanRemoval(damaged, sha256, patch);

        Assert.AreEqual(CpuPatchRemovalPlanStatus.UnsupportedLayout, plan.Status);
        Assert.AreEqual(CpuPatchRemovalReason.FitUnavailableOrMismatch, plan.Reason);
        Assert.IsFalse(plan.CanApply);
    }

    [TestMethod]
    public async Task CpuPatchPlannerRefusesMicrocodeThatIsNotThe6F06F2TurboBoostTarget()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);
        IntelMicrocodeInfo nonTarget = image.TurboBoostUnlock.Microcodes.First(item =>
            !TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(item));
        byte[] source = await File.ReadAllBytesAsync(path);

        CpuPatchRemovalPlan plan = CpuPatchImageUpdater.PlanRemoval(source, image.Sha256, nonTarget);

        Assert.AreEqual(CpuPatchRemovalPlanStatus.UnsupportedLayout, plan.Status);
        Assert.AreEqual(CpuPatchRemovalReason.NotTurboBoostTarget, plan.Reason);
        Assert.IsFalse(plan.CanApply);
    }

    [TestMethod]
    public void TurboBoostTargetRequiresBoth306F2SignatureAndPlatformMask6F()
    {
        var baseline = new IntelMicrocodeInfo(
            0,
            0x8400,
            0x3D,
            0x04202018,
            new DateOnly(2018, 4, 20),
            TurboBoostUnlockReport.XeonE5V3ProcessorSignature,
            TurboBoostUnlockReport.XeonE5V3ProcessorFlags,
            new string('0', 64),
            0,
            Guid.Empty,
            0,
            0x01);

        Assert.IsTrue(TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(baseline));
        Assert.IsFalse(TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(
            baseline with { ProcessorFlags = 0x01 }));
        Assert.IsFalse(TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(
            baseline with { ProcessorSignature = 0x000306F1 }));
    }

    [TestMethod]
    public void SemanticAnalyzerRequiresTurboUncoreAndOcBehaviorForStrongCandidate()
    {
        byte[] code =
        [
            0xB9, 0xAD, 0x01, 0x00, 0x00, 0x0F, 0x30,
            0xB9, 0x20, 0x06, 0x00, 0x00, 0x0F, 0x30,
            0xB9, 0x50, 0x01, 0x00, 0x00, 0x0F, 0x30
        ];

        TurboBoostMsrEvidence evidence = TurboBoostSemanticAnalyzer.Analyze(code);

        Assert.IsTrue(evidence.IsStrongCandidate);
        CollectionAssert.AreEquivalent(new uint[] { 0x150, 0x1AD, 0x620 }, evidence.RelevantMsrs.ToArray());
        Assert.IsTrue(evidence.WrmsrCount >= 2);
    }

    [TestMethod]
    public void CalibratedKnownFamilyProfileRecognizesDetectorReferenceLeaf()
    {
        string path = RepositoryTestFiles.Find("tests", "TurboUnlock", "ser8989_DXETurboHack_pe.bin");
        byte[] pe = File.ReadAllBytes(path);
        TurboBoostExecutableObserver observer = TurboBoostUnlockInspector.CreateExecutableObserver();
        var observation = new UefiExecutableObservation(
            new Guid("e7df4cfa-9e2e-4232-b86c-c44467a4ab20"),
            0x890000,
            0xBCF590,
            0x07,
            UefiExecutableFormat.Pe32);

        observer.Observe(in observation, pe);

        TurboBoostUnlockFinding finding = AssertExactlyOne(observer.Findings);
        Assert.AreEqual(TurboBoostUnlockEvidenceKind.KnownFamilySemantics, finding.Evidence);
        Assert.AreEqual("ser8989-turbohack", finding.Family);
        Assert.IsTrue(finding.RelevantMsrs.Any(value => value.Contains("0x1AD", StringComparison.OrdinalIgnoreCase)));
        Assert.IsTrue(finding.MarkerHits.Any(value => value.Contains("Ser8989", StringComparison.OrdinalIgnoreCase)));
    }

    [TestMethod]
    public void ForeignCleanupNeverTreatsNearOrGenericHeuristicsAsVerifiedAuthorization()
    {
        Assert.IsFalse(TurboBoostUnlockModulePlanner.IsVerifiedEvidence(
            TurboBoostUnlockEvidenceKind.NearKnownFamilySemantics));
        Assert.IsFalse(TurboBoostUnlockModulePlanner.IsVerifiedEvidence(
            TurboBoostUnlockEvidenceKind.GenericUnlockSemantics));
        Assert.IsTrue(TurboBoostUnlockModulePlanner.IsVerifiedEvidence(
            TurboBoostUnlockEvidenceKind.ExactFfsIdentity));
        Assert.IsTrue(TurboBoostUnlockModulePlanner.IsVerifiedEvidence(
            TurboBoostUnlockEvidenceKind.ExactExecutableIdentity));
        Assert.IsTrue(TurboBoostUnlockModulePlanner.IsVerifiedEvidence(
            TurboBoostUnlockEvidenceKind.KnownFamilySemantics));
    }

    [TestMethod]
    public void CleanupPolicyHasNoRetainedFamilyAndTreatsSer8989AsForeign()
    {
        TurboBoostUnlockIdentityCatalog catalog = TurboBoostUnlockIdentityCatalog.Instance;

        Assert.IsFalse(catalog.IsRetainedFamily("ser8989-turbohack"));
        Assert.IsFalse(catalog.IsRetainedFamily("c-payne"));
        Assert.IsFalse(catalog.IsRetainedFamily("mof-v3-mof"));
        Assert.IsFalse(catalog.IsRetainedFamily("freecableguy-v3x4"));
        Assert.IsFalse(catalog.IsRetainedFamily("randir-mof-powercut"));
        Assert.IsFalse(catalog.IsRetainedFamily("nalex-upt"));
        Assert.IsFalse(catalog.IsRetainedFamily("dufus-v3"));
    }

    [TestMethod]
    public async Task ForeignSer8989RealImagePlansAndExecutesDirectFfsRemovalWithoutBaseline()
    {
        string sourcePath = RepositoryTestFiles.Find(
            "tests", "TurboUnlock", "ForeignCleanup", "jg_x99m_gaming_d4_ser8989_unlock.bin");
        byte[] source = await File.ReadAllBytesAsync(sourcePath);

        BiosImage sourceImage = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        Assert.AreEqual(
            "F4BBB4A7C1AA3EFBB6A7DF75610DD04CFD5306C25D299F67E7E7243243C14D74",
            sourceImage.Sha256);

        TurboBoostUnlockModule module = AssertExactlyOne(sourceImage.TurboBoostUnlock.ForeignUnlockModules);
        Assert.IsTrue(module.Verified);
        Assert.AreEqual(TurboBoostUnlockModuleDisposition.Foreign, module.Disposition);
        CollectionAssert.AreEqual(new[] { "ser8989-turbohack" }, module.Families.ToArray());
        Assert.AreEqual(new Guid("e7df4cfa-9e2e-4232-b86c-c44467a4ab20"), module.FileGuid);
        Assert.AreEqual(0x00890000L, module.VolumeOffset);
        Assert.AreEqual(0x00BCF590L, module.FileOffset);
        Assert.AreEqual(0x0ABA, module.FileSize);
        Assert.AreEqual(
            "A3672509AD0BD51C0F11F0B74E9EDBACDB059E92C64B17D64FE46F92D0AA8AA0",
            module.FfsSha256);

        TurboBoostForeignRemovalPlan plan = module.RemovalPlan;
        Assert.AreEqual(TurboBoostForeignRemovalStatus.Ready, plan.Status);
        Assert.AreEqual(TurboBoostForeignRemovalOperation.RemoveInjectedFfs, plan.Operation);
        Assert.AreEqual(TurboBoostForeignRemovalReason.None, plan.Reason);
        Assert.AreEqual(UefiDriverMutationFeasibility.InPlace, plan.MutationFeasibility);
        Assert.IsTrue(plan.CanExecute);
        Assert.IsNull(plan.BaselineImageSha256);
        Assert.IsNull(plan.BaselineFileGuid);
        Assert.IsNull(plan.BaselineFileOffset);
        Assert.IsNull(plan.BaselineFileSize);
        Assert.IsNull(plan.BaselineFfsSha256);

        byte[] output = TurboBoostForeignUnlockImageUpdater.RemoveInjectedFfs(source, plan);
        Assert.AreEqual(source.Length, output.Length);
        Assert.AreEqual(
            "AD6C2EE18E538CCFDF8E302FB30CF203B3878CC902A0A1C8802E39C4A1600795",
            Convert.ToHexString(SHA256.HashData(output)));

        int changedBytes = 0;
        int changedOffset = -1;
        for (int index = 0; index < source.Length; index++)
        {
            if (source[index] == output[index])
            {
                continue;
            }

            changedBytes++;
            changedOffset = index;
        }
        Assert.AreEqual(1, changedBytes);
        Assert.AreEqual(checked((int)module.FileOffset + AmiSecureBootSpecification.FfsStateOffset), changedOffset);
        Assert.AreEqual(0xF8, source[changedOffset]);
        Assert.AreEqual(0xE8, output[changedOffset]);

        BiosImage outputImage = BiosImageLoader.Analyze(output);
        BiosImageLoader.EnsureValidBiosImage(outputImage);
        Assert.IsEmpty(outputImage.TurboBoostUnlock.ForeignUnlockModules);
        Assert.IsFalse(outputImage.TurboBoostUnlock.Modules.Any(item =>
            item.FileGuid == module.FileGuid && item.FileOffset == module.FileOffset));
        Assert.AreEqual(
            sourceImage.TurboBoostUnlock.HasXeonE5V3CpuPatch,
            outputImage.TurboBoostUnlock.HasXeonE5V3CpuPatch);
        CollectionAssert.AreEqual(
            sourceImage.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray(),
            outputImage.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray());
    }

    [TestMethod]
    public async Task ForeignNalexUptRealImageIsExactForeignAndDirectRemovalTouchesOnlyStateByte()
    {
        string baselinePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        string sourcePath = RepositoryTestFiles.Find(
            "tests", "TurboUnlock", "ForeignCleanup", "8DPV11_nalex_upt.bin");
        byte[] baseline = await File.ReadAllBytesAsync(baselinePath);
        byte[] source = await File.ReadAllBytesAsync(sourcePath);

        BiosImage baselineImage = BiosImageLoader.Analyze(baseline);
        BiosImage sourceImage = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(baselineImage);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        Assert.AreEqual(
            "E1C5C42E0B2FF4F8DC84E95ED628F5750A207C0F13835349673B0C52EC332375",
            baselineImage.Sha256);
        Assert.AreEqual(
            "5342AD0738155EE32FF546E62335FCFF6311A98329553A4AA7C927A959C2E293",
            sourceImage.Sha256);

        TurboBoostUnlockModule module = AssertExactlyOne(sourceImage.TurboBoostUnlock.ForeignUnlockModules);
        Assert.IsTrue(module.Verified);
        Assert.AreEqual(TurboBoostUnlockModuleDisposition.Foreign, module.Disposition);
        CollectionAssert.AreEqual(new[] { "nalex-upt" }, module.Families.ToArray());
        Assert.AreEqual(new Guid("9c81bc4d-a8f5-4d3d-bb75-5aa2e934a034"), module.FileGuid);
        Assert.AreEqual(0x00890000L, module.VolumeOffset);
        Assert.AreEqual(0x008C9AE8L, module.FileOffset);
        Assert.AreEqual(2347, module.FileSize);
        Assert.AreEqual(
            "9068ED21C0BE8524D5B554307D49EA4D44F647CC700FF0D706F477D8BF784D5A",
            module.FfsSha256);
        Assert.IsFalse(baselineImage.TurboBoostUnlock.Modules.Any(item =>
            item.FileGuid == module.FileGuid && item.FfsSha256 == module.FfsSha256));

        TurboBoostForeignRemovalPlan plan = module.RemovalPlan;
        Assert.AreEqual(TurboBoostForeignRemovalStatus.Ready, plan.Status);
        Assert.AreEqual(TurboBoostForeignRemovalOperation.RemoveInjectedFfs, plan.Operation);
        Assert.AreEqual(TurboBoostForeignRemovalReason.None, plan.Reason);
        Assert.AreEqual(UefiDriverMutationFeasibility.InPlace, plan.MutationFeasibility);
        Assert.IsTrue(plan.CanExecute);
        Assert.IsNull(plan.BaselineImageSha256);

        byte[] output = TurboBoostForeignUnlockImageUpdater.RemoveInjectedFfs(source, plan);
        Assert.AreEqual(source.Length, output.Length);
        Assert.AreEqual(
            "E81AD0CE6B83E7413048D3AF9D1349382E91A4BBD16476D0961BC3DE7D35DE57",
            Convert.ToHexString(SHA256.HashData(output)));

        int changedBytes = 0;
        int changedOffset = -1;
        for (int index = 0; index < source.Length; index++)
        {
            if (source[index] == output[index])
            {
                continue;
            }
            changedBytes++;
            changedOffset = index;
        }
        Assert.AreEqual(1, changedBytes);
        Assert.AreEqual(0x008C9AFF, changedOffset);
        Assert.AreEqual(0xF8, source[changedOffset]);
        Assert.AreEqual(0xE8, output[changedOffset]);

        BiosImage outputImage = BiosImageLoader.Analyze(output);
        BiosImageLoader.EnsureValidBiosImage(outputImage);
        Assert.IsFalse(outputImage.TurboBoostUnlock.Modules.Any(item =>
            item.FileGuid == module.FileGuid && item.FfsSha256 == module.FfsSha256));
        Assert.AreNotEqual(baselineImage.Sha256, outputImage.Sha256);
        Assert.AreEqual(
            sourceImage.TurboBoostUnlock.HasXeonE5V3CpuPatch,
            outputImage.TurboBoostUnlock.HasXeonE5V3CpuPatch);
        CollectionAssert.AreEqual(
            sourceImage.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray(),
            outputImage.TurboBoostUnlock.Microcodes.Select(item => item.Sha256).ToArray());
    }

    [TestMethod]
    public async Task ForeignCleanupOptionalBaselinePlanningDoesNotBecomeExecutionDependency()
    {
        string baselinePath = RepositoryTestFiles.Find(
            "tests", "TurboUnlock", "ForeignCleanup", "jg_x99m_gaming_d4_stock.bin");
        string sourcePath = RepositoryTestFiles.Find(
            "tests", "TurboUnlock", "ForeignCleanup", "jg_x99m_gaming_d4_ser8989_unlock.bin");
        string destination = Path.Combine(
            Path.GetTempPath(),
            "XeonV3Control2-foreign-unlock-" + Guid.NewGuid().ToString("N") + ".bin");
        string sourceBefore = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(sourcePath)));
        string baselineBefore = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(baselinePath)));

        try
        {
            TurboBoostForeignRemovalPlanningResult planning =
                await TurboBoostForeignUnlockRemovalPlanner.PlanFilesAsync(sourcePath, baselinePath);
            Assert.AreEqual(Path.GetFullPath(sourcePath), planning.SourceFilePath);
            Assert.AreEqual(Path.GetFullPath(baselinePath), planning.BaselineFilePath);
            Assert.AreEqual(sourceBefore, planning.SourceImageSha256);
            Assert.AreEqual(baselineBefore, planning.BaselineImageSha256);

            TurboBoostForeignRemovalPlan plan = AssertExactlyOne(planning.Plans);
            Assert.IsTrue(plan.CanExecute);
            Assert.AreEqual(TurboBoostForeignRemovalOperation.RemoveInjectedFfs, plan.Operation);
            Assert.IsNull(plan.BaselineImageSha256);
            Assert.IsNull(plan.BaselineFileGuid);
            Assert.IsNull(plan.BaselineFileOffset);
            Assert.IsNull(plan.BaselineFileSize);
            Assert.IsNull(plan.BaselineFfsSha256);

            BiosImage updated = await TurboBoostForeignUnlockImageUpdater.RemoveInjectedFfsFileAsync(
                planning.SourceFilePath,
                destination,
                plan);

            Assert.AreEqual(
                "AD6C2EE18E538CCFDF8E302FB30CF203B3878CC902A0A1C8802E39C4A1600795",
                updated.Sha256);
            Assert.AreEqual(sourceBefore, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(sourcePath))));
            Assert.AreEqual(baselineBefore, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(baselinePath))));
            Assert.IsTrue(File.Exists(destination));
        }
        finally
        {
            File.Delete(destination);
        }
    }

    [TestMethod]
    public void ForeignCleanupTopologySeparatesIndependentInjectedFfsChanges()
    {
        var a = new TurboBoostFfsIdentity(Guid.Parse("11111111-1111-1111-1111-111111111111"), 0x07);
        var foreign = new TurboBoostFfsIdentity(Guid.Parse("22222222-2222-2222-2222-222222222222"), 0x07);
        var b = new TurboBoostFfsIdentity(Guid.Parse("33333333-3333-3333-3333-333333333333"), 0x07);
        var otherInsertion = new TurboBoostFfsIdentity(Guid.Parse("44444444-4444-4444-4444-444444444444"), 0x07);
        var c = new TurboBoostFfsIdentity(Guid.Parse("55555555-5555-5555-5555-555555555555"), 0x07);

        TurboBoostFfsTopologyMatch match = TurboBoostForeignUnlockRemovalPlanner.ClassifyTopology(
            new[] { a, foreign, b, otherInsertion, c },
            new[] { a, b, c },
            1);

        Assert.AreEqual(TurboBoostFfsTopologyKind.InjectedSingleton, match.Kind);
        Assert.AreEqual(-1, match.BaselineIndex);
    }

    [TestMethod]
    public void ForeignCleanupTopologyDistinguishesModifiedAndReplacedStockFfs()
    {
        var a = new TurboBoostFfsIdentity(Guid.Parse("11111111-1111-1111-1111-111111111111"), 0x07);
        var stock = new TurboBoostFfsIdentity(Guid.Parse("22222222-2222-2222-2222-222222222222"), 0x07);
        var replacement = new TurboBoostFfsIdentity(Guid.Parse("99999999-9999-9999-9999-999999999999"), 0x07);
        var b = new TurboBoostFfsIdentity(Guid.Parse("33333333-3333-3333-3333-333333333333"), 0x07);

        TurboBoostFfsTopologyMatch modified = TurboBoostForeignUnlockRemovalPlanner.ClassifyTopology(
            new[] { a, stock, b },
            new[] { a, stock, b },
            1);
        TurboBoostFfsTopologyMatch replaced = TurboBoostForeignUnlockRemovalPlanner.ClassifyTopology(
            new[] { a, replacement, b },
            new[] { a, stock, b },
            1);

        Assert.AreEqual(TurboBoostFfsTopologyKind.SameIdentityModified, modified.Kind);
        Assert.AreEqual(1, modified.BaselineIndex);
        Assert.AreEqual(TurboBoostFfsTopologyKind.ReplacedSingleton, replaced.Kind);
        Assert.AreEqual(1, replaced.BaselineIndex);
    }

    [TestMethod]
    public void ForeignCleanupContiguousInjectionGroupRequiresEveryInsertedFfsToBeVerifiedForeign()
    {
        var foreignA = new UefiFfsFileLocation(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            0x07,
            0,
            0x2000,
            0x180,
            0x18,
            0x2180,
            FfsFileState.DataValid);
        var foreignB = new UefiFfsFileLocation(
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            0x07,
            0,
            0x2180,
            0x180,
            0x18,
            0x2300,
            FfsFileState.DataValid);
        UefiFfsFileLocation[] inserted = [foreignA, foreignB];
        var window = new TurboBoostFfsChangeWindow(0, 2, 0, 0);

        TurboBoostUnlockModule[] complete =
        [
            CreateForeignUnlockModule(foreignA),
            CreateForeignUnlockModule(foreignB)
        ];
        TurboBoostUnlockModule[] incomplete = [CreateForeignUnlockModule(foreignA)];

        Assert.IsTrue(TurboBoostForeignUnlockRemovalPlanner.IsVerifiedForeignInjectionGroup(
            inserted,
            window,
            complete));
        Assert.IsFalse(TurboBoostForeignUnlockRemovalPlanner.IsVerifiedForeignInjectionGroup(
            inserted,
            window,
            incomplete));
    }

    [TestMethod]
    public void ForeignInjectedFfsDeletedStateUsesMinimalPiTransitionForBothErasePolarities()
    {
        Assert.AreEqual(
            0xE8,
            TurboBoostForeignUnlockImageUpdater.BuildDeletedPhysicalState(0xF8, 0xFF));
        Assert.AreEqual(
            0x17,
            TurboBoostForeignUnlockImageUpdater.BuildDeletedPhysicalState(0x07, 0x00));

        InvalidDataException invalid = Assert.Throws<InvalidDataException>(() =>
            TurboBoostForeignUnlockImageUpdater.BuildDeletedPhysicalState(0xF0, 0xFF));
        Assert.AreEqual(OperationError.TurboBoostForeignRemovalUnsupported, invalid.Message);
    }

    [TestMethod]
    public async Task ForeignInjectedFfsExecutorDoesNotTrustCallerSuppliedReadyPlan()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage image = BiosImageLoader.Analyze(source);
        BiosImageLoader.EnsureValidBiosImage(image);
        var forged = new TurboBoostForeignRemovalPlan(
            TurboBoostForeignRemovalStatus.Ready,
            TurboBoostForeignRemovalOperation.RemoveInjectedFfs,
            TurboBoostForeignRemovalReason.None,
            image.Sha256,
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            image.Volumes[0].Offset,
            image.Volumes[0].Offset + 0x100,
            0x180,
            new string('A', 64),
            null,
            null,
            null,
            null,
            null,
            UefiDriverMutationFeasibility.InPlace);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() =>
            TurboBoostForeignUnlockImageUpdater.RemoveInjectedFfs(source, forged));

        Assert.AreEqual(OperationError.TurboBoostForeignRemovalUnsupported, error.Message);
    }

    [TestMethod]
    public void FirmwareMutationShaBindingRejectsMissingExpectedHashWithDomainError()
    {
        InvalidDataException error = Assert.Throws<InvalidDataException>(() =>
            FirmwareMutationFileIo.VerifySha256(
                new byte[] { 0x58, 0x45, 0x4F, 0x4E },
                string.Empty,
                OperationError.CpuPatchSourceChanged));

        Assert.AreEqual(OperationError.CpuPatchSourceChanged, error.Message);
    }

    [TestMethod]
    public async Task CpuPatchRemovalDoesNotDeletePreExistingDestinationOnCommitConflict()
    {
        string sourcePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(sourcePath);
        CpuPatchRemovalPlan plan = AssertExactlyOne(sourceImage.TurboBoostUnlock.CpuPatchRemovalPlans);
        string destination = Path.Combine(
            Path.GetTempPath(),
            "XeonV3Control2-existing-" + Guid.NewGuid().ToString("N") + ".bin");
        byte[] sentinel = [0x58, 0x45, 0x4F, 0x4E];
        await File.WriteAllBytesAsync(destination, sentinel);

        try
        {
            await Assert.ThrowsAsync<IOException>(() =>
                CpuPatchImageUpdater.RemoveFileAsync(sourcePath, destination, plan));
            CollectionAssert.AreEqual(sentinel, await File.ReadAllBytesAsync(destination));
        }
        finally
        {
            File.Delete(destination);
        }
    }

    [TestMethod]
    public void ForeignInjectedFfsExecutorIsManagedReauthorizedAndSingleByteMutationOnly()
    {
        string source = File.ReadAllText(RepositoryTestFiles.Find(
            "src", "XeonV3Control.Core", "TurboBoostForeignUnlockImageUpdater.cs"));

        StringAssert.Contains(source, "FindExactForeignTarget");
        StringAssert.Contains(source, "TurboBoostForeignRemovalPlan fresh = target.RemovalPlan;");
        StringAssert.Contains(source, "BuildDeletedPhysicalState");
        StringAssert.Contains(source, "source[..stateOffset].SequenceEqual");
        StringAssert.Contains(source, "Microcodes.SequenceEqual");
        Assert.IsFalse(source.Contains("PlanAgainstBaseline", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("baselinePath", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("Process.Start", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("MMTool", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("UEFITool", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("DllImport", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("LibraryImport", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("unsafe", StringComparison.Ordinal));
    }

    [TestMethod]
    public void ForeignCleanupRestorePlanCannotExecuteBeforeByteAuthorization()
    {
        var plan = new TurboBoostForeignRemovalPlan(
            TurboBoostForeignRemovalStatus.RequiresBaselineByteAuthorization,
            TurboBoostForeignRemovalOperation.RestoreBaselineFfs,
            TurboBoostForeignRemovalReason.BaselineByteAuthorizationRequired,
            new string('A', 64),
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            0x1000,
            0x2000,
            0x180,
            new string('B', 64),
            new string('C', 64),
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            0x2000,
            0x180,
            new string('D', 64),
            UefiDriverMutationFeasibility.InPlace);

        Assert.IsTrue(plan.TopologyAuthorized);
        Assert.IsFalse(plan.CanExecute);
    }

    [TestMethod]
    public void ForeignCleanupRestoreIntentRequiresSeparateBaselineByteAuthorization()
    {
        string source = File.ReadAllText(RepositoryTestFiles.Find(
            "src", "XeonV3Control.Core", "TurboBoostUnlockCleanup.cs"));

        StringAssert.Contains(source, "RequiresBaselineByteAuthorization");
        StringAssert.Contains(source, "BaselineByteAuthorizationRequired");
        StringAssert.Contains(source, "HasCompatibleImageLayout");
    }

    [TestMethod]
    public void ForeignCleanupRestoreDesignKeepsBaselineByteAuthorizationFailClosed()
    {
        string design = File.ReadAllText(RepositoryTestFiles.Find(
            "docs", "TURBOBOOST-FOREIGN-CLEANUP.md"));
        string planner = File.ReadAllText(RepositoryTestFiles.Find(
            "src", "XeonV3Control.Core", "TurboBoostUnlockCleanup.cs"));

        StringAssert.Contains(design, "Exact platform / firmware lineage");
        StringAssert.Contains(design, "Exact firmware-volume identity");
        StringAssert.Contains(design, "Unambiguous surrounding FFS topology");
        StringAssert.Contains(design, "Byte-range authorization");
        StringAssert.Contains(design, "CPU Patch 6F/06F2");
        StringAssert.Contains(planner, "RequiresBaselineByteAuthorization");
        StringAssert.Contains(planner, "BaselineByteAuthorizationRequired");
        Assert.IsFalse(planner.Contains(
            "TurboBoostForeignRemovalStatus.Ready,\n            TurboBoostForeignRemovalOperation.RestoreBaselineFfs",
            StringComparison.Ordinal));
    }

    [TestMethod]
    public void ForeignCleanupPlannerIsPlanningOnlyAndDoesNotInvokeFirmwareTools()
    {
        string source = File.ReadAllText(RepositoryTestFiles.Find(
            "src", "XeonV3Control.Core", "TurboBoostUnlockCleanup.cs"));

        StringAssert.Contains(source, "PlanAgainstBaseline");
        StringAssert.Contains(source, "RequiresBaselineByteAuthorization");
        StringAssert.Contains(source, "sourceVolumeLayout != baselineVolumeLayout");
        StringAssert.Contains(source, "MinimumInjectionTopologyAnchors = 3");
        StringAssert.Contains(source, "IsExactTopologyAnchor");
        Assert.IsFalse(source.Contains("RequiresCleanBaseline", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("Process.Start", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("MMTool", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("UEFITool", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("WriteAllBytes", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("FileMode.Create", StringComparison.Ordinal));
    }

    [TestMethod]
    public void CpuPatchRemovalIsManagedAndDoesNotInvokeExternalFirmwareTools()
    {
        string inspector = File.ReadAllText(RepositoryTestFiles.Find("src", "XeonV3Control.Core", "TurboBoostUnlock.cs"));
        string updater = File.ReadAllText(RepositoryTestFiles.Find("src", "XeonV3Control.Core", "CpuPatchImageUpdater.cs"));
        string implementation = inspector + updater;

        StringAssert.Contains(implementation, "CpuPatchRemovalPlan");
        StringAssert.Contains(implementation, "CpuPatchImageUpdater");
        Assert.IsFalse(implementation.Contains("Process.Start", StringComparison.Ordinal));
        Assert.IsFalse(implementation.Contains("MMTool", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(implementation.Contains("UEFITool", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(implementation.Contains("DllImport", StringComparison.Ordinal));
        Assert.IsFalse(implementation.Contains("LibraryImport", StringComparison.Ordinal));
        Assert.IsFalse(implementation.Contains("unsafe", StringComparison.Ordinal));
    }

    private static TurboBoostUnlockModule CreateForeignUnlockModule(UefiFfsFileLocation file)
    {
        string hash = new string('A', 64);
        var plan = new TurboBoostForeignRemovalPlan(
            TurboBoostForeignRemovalStatus.Ready,
            TurboBoostForeignRemovalOperation.RemoveInjectedFfs,
            TurboBoostForeignRemovalReason.None,
            new string('B', 64),
            file.Guid,
            0x1000,
            file.Offset,
            file.Size,
            hash,
            null,
            null,
            null,
            null,
            null,
            UefiDriverMutationFeasibility.InPlace);
        return new TurboBoostUnlockModule(
            file.Guid,
            0x1000,
            file.Offset,
            file.Size,
            file.Type,
            hash,
            null,
            ["c-payne"],
            TurboBoostUnlockModuleDisposition.Foreign,
            true,
            [TurboBoostUnlockEvidenceKind.ExactFfsIdentity],
            plan);
    }

    private static T AssertExactlyOne<T>(IReadOnlyList<T> values)
    {
        Assert.AreEqual(1, values.Count);
        return values[0];
    }
}
