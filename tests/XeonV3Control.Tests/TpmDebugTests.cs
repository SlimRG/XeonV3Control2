using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class TpmDebugTests
{
    [TestMethod]
    public async Task ReferenceX99ImageReportsTpmEvidenceOnlyFromImage()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);

        Assert.IsFalse(image.TpmFirmware.DebugDriverInstalled);
        Assert.AreEqual(0, image.TpmFirmware.DebugDriverCopies);
        Assert.IsTrue(image.TpmFirmware.Evidence.Any(item => item.Key == "MSFT0101"));
        Assert.IsTrue(image.TpmFirmware.Evidence.Any(item => item.Key == "TrEE"));
        Assert.IsTrue(image.TpmFirmware.Evidence.Any(item => item.Key == "PTP"));
        Assert.IsTrue(image.TpmFirmware.Descriptor.Available);
        Assert.AreEqual(0x60, image.TpmFirmware.Descriptor.PchStrapBase);
        Assert.AreEqual(21, image.TpmFirmware.Descriptor.DeclaredStrapCount);
        Assert.IsTrue(image.TpmFirmware.Descriptor.PchStraps.Count >= 4);
        Assert.AreEqual(0x3A1B0000u, image.TpmFirmware.Descriptor.PchStraps[0]);
        Assert.AreEqual(0x04250000u, image.TpmFirmware.Descriptor.PchStraps[1]);
        Assert.AreEqual(0x08090118u, image.TpmFirmware.Descriptor.PchStraps[2]);
        Assert.AreEqual(TpmTransportHint.Unknown, image.TpmFirmware.Descriptor.Transport);
    }

    [TestMethod]
    public async Task DebugDriverInstallAndRemovePreserveUnrelatedFirmwareAndImageEvidence()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmFirmwareEvidence[] baselineEvidence = sourceImage.TpmFirmware.Evidence.ToArray();

        Assert.IsFalse(TpmDebugDriverImageUpdater.IsCurrentInstallation(source, sourceImage));

        TpmDebugDriverPlan install = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        Assert.IsTrue(install.CanExecute);
        Assert.AreEqual(TpmDebugDriverMutation.Install, install.Mutation);
        Assert.IsNotNull(install.FileOffset);
        Assert.IsTrue(install.DriverSize > 0);

        byte[] installedBytes = TpmDebugDriverImageUpdater.Apply(source, install);
        BiosImage installed = BiosImageLoader.Analyze(installedBytes);
        BiosImageLoader.EnsureValidBiosImage(installed);

        Assert.AreEqual(source.Length, installedBytes.Length);
        Assert.IsTrue(installed.TpmFirmware.DebugDriverInstalled);
        Assert.AreEqual(1, installed.TpmFirmware.DebugDriverCopies);
        Assert.IsTrue(TpmDebugDriverImageUpdater.IsCurrentInstallation(installedBytes, installed));

        byte[] alteredBytes = installedBytes.ToArray();
        alteredBytes[checked((int)install.FileOffset!.Value + install.DriverSize - 1)] ^= 0x01;
        BiosImage altered = BiosImageLoader.Analyze(alteredBytes);
        BiosImageLoader.EnsureValidBiosImage(altered);
        Assert.IsFalse(TpmDebugDriverImageUpdater.IsCurrentInstallation(alteredBytes, altered),
            "A byte-different debug-driver FFS must not be authorized for direct flashing.");

        CollectionAssert.AreEqual(baselineEvidence, installed.TpmFirmware.Evidence.ToArray(),
            "The debug driver's own strings must not become TPM evidence.");
        AssertOnlyRangeChanged(source, installedBytes, install.FileOffset!.Value, install.DriverSize);
        AssertFfsEndsAtLastSectionAndKeepsExternalErasePadding(installedBytes,
            checked((int)install.FileOffset!.Value), install.DriverSize);

        TpmDebugDriverPlan remove = TpmDebugDriverImageUpdater.Plan(installedBytes, installed);
        Assert.IsTrue(remove.CanExecute);
        Assert.AreEqual(TpmDebugDriverMutation.Remove, remove.Mutation);
        byte[] removedBytes = TpmDebugDriverImageUpdater.Apply(installedBytes, remove);
        BiosImage removed = BiosImageLoader.Analyze(removedBytes);
        BiosImageLoader.EnsureValidBiosImage(removed);

        Assert.IsFalse(removed.TpmFirmware.DebugDriverInstalled);
        Assert.AreEqual(0, removed.TpmFirmware.DebugDriverCopies);
        CollectionAssert.AreEqual(baselineEvidence, removed.TpmFirmware.Evidence.ToArray(),
            "Deleted debug-driver bytes must not become TPM evidence.");
        AssertOnlyRangeChanged(installedBytes, removedBytes, remove.FileOffset!.Value, remove.DriverSize);

        TpmDebugDriverPlan reinstall = TpmDebugDriverImageUpdater.Plan(removedBytes, removed);
        Assert.IsTrue(reinstall.CanExecute);
        Assert.AreEqual(TpmDebugDriverMutation.Install, reinstall.Mutation);
        Assert.AreEqual(install.FileOffset, reinstall.FileOffset, "Removal must reclaim the owned FFS slot.");
        byte[] reinstalledBytes = TpmDebugDriverImageUpdater.Apply(removedBytes, reinstall);
        CollectionAssert.AreEqual(installedBytes, reinstalledBytes,
            "Install -> remove -> install must be byte-for-byte deterministic.");
    }

    private static void AssertFfsEndsAtLastSectionAndKeepsExternalErasePadding(byte[] image, int fileOffset, int fileSize)
    {
        Assert.IsTrue(fileSize >= 24);
        Assert.AreEqual(fileSize, image[fileOffset + 20] | (image[fileOffset + 21] << 8) |
            (image[fileOffset + 22] << 16), "FFS FileSize must equal the actual FFS byte count.");

        int relative = 24;
        int lastSectionEnd = 24;
        while (relative <= fileSize - 4)
        {
            int absolute = checked(fileOffset + relative);
            int sectionSize = image[absolute] | (image[absolute + 1] << 8) | (image[absolute + 2] << 16);
            Assert.IsTrue(sectionSize >= 4, $"Invalid zero/small section at FFS+0x{relative:X}.");
            Assert.IsTrue(relative <= fileSize - sectionSize, $"Section overruns FFS at FFS+0x{relative:X}.");
            lastSectionEnd = checked(relative + sectionSize);
            if (lastSectionEnd == fileSize)
            {
                break;
            }

            relative = checked((lastSectionEnd + 3) & ~3);
        }

        Assert.AreEqual(fileSize, lastSectionEnd,
            "FFS FileSize must end on the last real section, not include alignment padding or a fake zero-sized section.");

        int alignedEnd = checked((fileOffset + fileSize + 7) & ~7);
        for (int index = fileOffset + fileSize; index < alignedEnd; index++)
        {
            Assert.AreEqual(0xFF, image[index],
                $"FFS 8-byte alignment byte at 0x{index:X} must remain outside FileSize and retain erase polarity.");
        }
    }

    private static void AssertOnlyRangeChanged(byte[] before, byte[] after, long offset, int length)
    {
        Assert.AreEqual(before.Length, after.Length);
        int start = checked((int)offset);
        int end = checked(start + length);
        Assert.IsTrue(start >= 0 && end <= before.Length);

        bool changed = false;
        for (int index = 0; index < before.Length; index++)
        {
            if (before[index] == after[index]) continue;
            changed = true;
            Assert.IsTrue(index >= start && index < end,
                $"Unexpected firmware change at 0x{index:X}; expected only [0x{start:X}, 0x{end:X}).");
        }
        Assert.IsTrue(changed);
    }
}
