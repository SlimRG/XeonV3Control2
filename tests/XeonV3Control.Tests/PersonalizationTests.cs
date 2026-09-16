using System.Security.Cryptography;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class PersonalizationTests
{

    [TestMethod]
    public void SectionParserAcceptsUnalignedFinalSectionWithoutTrailingPadding()
    {
        // Section #1 is naturally aligned. Section #2 ends exactly at the stream boundary
        // with a six-byte size and therefore has no trailing four-byte alignment padding.
        byte[] stream =
        [
            0x08, 0x00, 0x00, AmiSecureBootSpecification.RawSectionType,
            0x11, 0x22, 0x33, 0x44,
            0x06, 0x00, 0x00, AmiSecureBootSpecification.RawSectionType,
            0x55, 0x66
        ];

        Assert.IsTrue(AmiLzmaFfsEditor.TryReadSections(
            stream,
            out IReadOnlyList<AmiLzmaFfsEditor.SectionInfo> sections));
        Assert.AreEqual(2, sections.Count);
        Assert.AreEqual(8, sections[1].Offset);
        Assert.AreEqual(6, sections[1].Size);
    }
    [TestMethod]
    public async Task KnownX99ImageExposesBothBootLogosAndStartupBeeper()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);

        Assert.AreEqual(PersonalizationFeatureStatus.Available, image.Personalization.LargeLogo.Status);
        Assert.AreEqual(1200, image.Personalization.LargeLogo.Width);
        Assert.AreEqual(900, image.Personalization.LargeLogo.Height);
        Assert.AreEqual((ushort)8, image.Personalization.LargeLogo.BitsPerPixel);
        Assert.AreEqual(image.Personalization.LargeLogo.BmpBytes, image.Personalization.LargeLogo.BmpData.Length);

        Assert.AreEqual(PersonalizationFeatureStatus.Available, image.Personalization.SmallLogo.Status);
        Assert.AreEqual(400, image.Personalization.SmallLogo.Width);
        Assert.AreEqual(100, image.Personalization.SmallLogo.Height);
        Assert.AreEqual((ushort)4, image.Personalization.SmallLogo.BitsPerPixel);
        Assert.AreEqual(image.Personalization.SmallLogo.BmpBytes, image.Personalization.SmallLogo.BmpData.Length);

        Assert.AreEqual(StartupBeeperStatus.Enabled, image.Personalization.Beeper.Status);
    }


    [TestMethod]
    [DataRow("tests", "8DPV11.bin")]
    [DataRow("tests", "TurboUnlock/ForeignCleanup/8DPV11_nalex_upt.bin")]
    [DataRow("tests", "TurboUnlock/ForeignCleanup/jg_x99m_gaming_d4_stock.bin")]
    [DataRow("tests", "TurboUnlock/ForeignCleanup/jg_x99m_gaming_d4_ser8989_unlock.bin")]
    public async Task StartupBeeperIsLocatedWithoutFixedFunctionOffsets(string directory, string fileName)
    {
        string[] parts = directory.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Append(fileName)
            .ToArray();
        string path = RepositoryTestFiles.Find(parts);
        BiosImage image = await BiosImageLoader.LoadValidatedAsync(path);

        Assert.AreEqual(StartupBeeperStatus.Enabled, image.Personalization.Beeper.Status);
    }

    [TestMethod]
    public async Task ReplacingLargeLogoPreservesSmallLogoAndBeeper()
    {
        string sourcePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(sourcePath);
        byte[] sourceBytes = await File.ReadAllBytesAsync(sourcePath);
        Assert.IsTrue(PersonalizationInspector.TryReadLogoBmp(
            sourceBytes,
            sourceImage,
            BootLogoKind.LargeBoot,
            CancellationToken.None,
            out AmiLzmaFfsEditor.LocatedFile largeLocated,
            out _,
            out byte[] replacement,
            out _));

        // Change a palette entry, not the BMP header or geometry.
        replacement[54] ^= 0x01;
        string replacementHash = Convert.ToHexString(SHA256.HashData(replacement));
        Assert.AreNotEqual(sourceImage.Personalization.LargeLogo.BmpSha256, replacementHash);

        string bmpPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bmp");
        string outputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            await File.WriteAllBytesAsync(bmpPath, replacement);
            BiosImage updated = await PersonalizationImageUpdater.ReplaceBootLogoFileAsync(
                sourcePath,
                outputPath,
                sourceImage,
                BootLogoKind.LargeBoot,
                bmpPath);

            Assert.AreEqual(replacementHash, updated.Personalization.LargeLogo.BmpSha256);
            Assert.AreEqual(sourceImage.Personalization.SmallLogo.BmpSha256, updated.Personalization.SmallLogo.BmpSha256);
            Assert.AreEqual(sourceImage.Personalization.Beeper.Status, updated.Personalization.Beeper.Status);
            Assert.AreNotEqual(sourceImage.Sha256, updated.Sha256);
            Assert.AreEqual(sourceImage.Sha256, (await BiosImageLoader.LoadValidatedAsync(sourcePath)).Sha256);

            byte[] outputBytes = await File.ReadAllBytesAsync(outputPath);
            Assert.IsTrue(sourceBytes.AsSpan(0, largeLocated.File.Offset)
                .SequenceEqual(outputBytes.AsSpan(0, largeLocated.File.Offset)));
            Assert.IsTrue(sourceBytes.AsSpan(largeLocated.File.NextOffset)
                .SequenceEqual(outputBytes.AsSpan(largeLocated.File.NextOffset)));
        }
        finally
        {
            File.Delete(bmpPath);
            File.Delete(outputPath);
        }
    }

    [TestMethod]
    public async Task ConvertingSmallLogoToBlackPreservesLayoutLargeLogoAndBeeper()
    {
        string sourcePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(sourcePath);
        ReadOnlyMemory<byte> template = sourceImage.Personalization.SmallLogo.BmpData;
        byte[] replacement = BootLogoBitmapConverter.CreateBlackTemplate(template.Span);
        string replacementHash = Convert.ToHexString(SHA256.HashData(replacement));

        Assert.AreEqual(template.Length, replacement.Length);
        Assert.AreNotEqual(sourceImage.Personalization.SmallLogo.BmpSha256, replacementHash);
        Assert.IsTrue(PersonalizationInspector.BmpInfo.TryParse(
            replacement, out PersonalizationInspector.BmpInfo convertedInfo));
        Assert.AreEqual(sourceImage.Personalization.SmallLogo.Width, convertedInfo.Width);
        Assert.AreEqual(sourceImage.Personalization.SmallLogo.Height, convertedInfo.Height);
        Assert.AreEqual(sourceImage.Personalization.SmallLogo.BitsPerPixel, convertedInfo.BitsPerPixel);
        Assert.IsTrue(replacement.AsSpan(
            convertedInfo.PixelOffset,
            replacement.Length - convertedInfo.PixelOffset).IndexOfAnyExcept((byte)0) < 0);

        string outputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            BiosImage updated = await PersonalizationImageUpdater.ReplaceBootLogoAsync(
                sourcePath,
                outputPath,
                sourceImage,
                BootLogoKind.SmallAmi,
                replacement);

            Assert.AreEqual(replacementHash, updated.Personalization.SmallLogo.BmpSha256);
            Assert.AreEqual(sourceImage.Personalization.LargeLogo.BmpSha256, updated.Personalization.LargeLogo.BmpSha256);
            Assert.AreEqual(sourceImage.Personalization.Beeper.Status, updated.Personalization.Beeper.Status);
        }
        finally
        {
            File.Delete(outputPath);
        }
    }
    [TestMethod]
    public async Task StartupBeeperCanBeDisabledAndRestoredWithoutChangingLogos()
    {
        string sourcePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage source = await BiosImageLoader.LoadValidatedAsync(sourcePath);
        byte[] sourceBytes = await File.ReadAllBytesAsync(sourcePath);
        Assert.IsTrue(PersonalizationInspector.TryLocateBeeperFunction(
            sourceBytes,
            source,
            CancellationToken.None,
            out AmiLzmaFfsEditor.LocatedFile beeperLocated,
            out AmiLzmaFfsEditor.SectionInfo beeperPeSection,
            out byte[] beeperExpanded,
            out int beeperFunctionOffset,
            out _));
        Assert.IsTrue(PersonalizationInspector.TryBuildBeeperDisablePatches(
            beeperExpanded, beeperPeSection, beeperFunctionOffset, out IReadOnlyList<byte[]> disablePatches));
        Assert.IsTrue(disablePatches.Any(patch => patch.Length == 5 && patch[0] == 0xE9));
        Assert.IsTrue(PersonalizationInspector.TryBuildBeeperEnablePatch(
            beeperExpanded, beeperPeSection, beeperFunctionOffset, out byte[] enablePatch));
        int enabledBodyOffset = beeperPeSection.Offset + beeperPeSection.HeaderSize + beeperFunctionOffset;
        Assert.IsTrue(beeperExpanded.AsSpan(enabledBodyOffset, enablePatch.Length).SequenceEqual(enablePatch));
        string disabledPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        string restoredPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        string redisabledPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            BiosImage disabled = await PersonalizationImageUpdater.SetStartupBeeperDisabledAsync(
                sourcePath,
                disabledPath,
                source,
                disabled: true);
            Assert.AreEqual(StartupBeeperStatus.Disabled, disabled.Personalization.Beeper.Status);
            Assert.AreEqual(source.Personalization.LargeLogo.BmpSha256, disabled.Personalization.LargeLogo.BmpSha256);
            Assert.AreEqual(source.Personalization.SmallLogo.BmpSha256, disabled.Personalization.SmallLogo.BmpSha256);

            byte[] disabledBytes = await File.ReadAllBytesAsync(disabledPath);
            Assert.IsTrue(sourceBytes.AsSpan(0, beeperLocated.File.Offset)
                .SequenceEqual(disabledBytes.AsSpan(0, beeperLocated.File.Offset)));
            Assert.IsTrue(sourceBytes.AsSpan(beeperLocated.File.NextOffset)
                .SequenceEqual(disabledBytes.AsSpan(beeperLocated.File.NextOffset)));

            BiosImage restored = await PersonalizationImageUpdater.SetStartupBeeperDisabledAsync(
                disabledPath,
                restoredPath,
                disabled,
                disabled: false);
            Assert.AreEqual(StartupBeeperStatus.Enabled, restored.Personalization.Beeper.Status);
            Assert.AreEqual(source.Personalization.LargeLogo.BmpSha256, restored.Personalization.LargeLogo.BmpSha256);
            Assert.AreEqual(source.Personalization.SmallLogo.BmpSha256, restored.Personalization.SmallLogo.BmpSha256);

            byte[] restoredBytes = await File.ReadAllBytesAsync(restoredPath);
            Assert.IsTrue(sourceBytes.AsSpan(0, beeperLocated.File.Offset)
                .SequenceEqual(restoredBytes.AsSpan(0, beeperLocated.File.Offset)));
            Assert.IsTrue(sourceBytes.AsSpan(beeperLocated.File.NextOffset)
                .SequenceEqual(restoredBytes.AsSpan(beeperLocated.File.NextOffset)));

            BiosImage redisabled = await PersonalizationImageUpdater.SetStartupBeeperDisabledAsync(
                restoredPath,
                redisabledPath,
                restored,
                disabled: true);
            Assert.AreEqual(StartupBeeperStatus.Disabled, redisabled.Personalization.Beeper.Status);
            Assert.AreEqual(source.Personalization.LargeLogo.BmpSha256, redisabled.Personalization.LargeLogo.BmpSha256);
            Assert.AreEqual(source.Personalization.SmallLogo.BmpSha256, redisabled.Personalization.SmallLogo.BmpSha256);
        }
        finally
        {
            File.Delete(disabledPath);
            File.Delete(restoredPath);
            File.Delete(redisabledPath);
        }
    }

    [TestMethod]
    public async Task LogoReplacementRejectsAValidBmpWithWrongGeometry()
    {
        string sourcePath = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        BiosImage source = await BiosImageLoader.LoadValidatedAsync(sourcePath);
        byte[] sourceBytes = await File.ReadAllBytesAsync(sourcePath);
        Assert.IsTrue(PersonalizationInspector.TryReadLogoBmp(
            sourceBytes,
            source,
            BootLogoKind.SmallAmi,
            CancellationToken.None,
            out _,
            out _,
            out byte[] wrongGeometry,
            out _));

        string bmpPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bmp");
        string outputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            await File.WriteAllBytesAsync(bmpPath, wrongGeometry);
            InvalidDataException error = await Assert.ThrowsAsync<InvalidDataException>(() =>
                PersonalizationImageUpdater.ReplaceBootLogoFileAsync(
                    sourcePath,
                    outputPath,
                    source,
                    BootLogoKind.LargeBoot,
                    bmpPath));
            Assert.AreEqual(OperationError.PersonalizationBmpFormatMismatch, error.Message);
            Assert.IsFalse(File.Exists(outputPath));
        }
        finally
        {
            File.Delete(bmpPath);
            File.Delete(outputPath);
        }
    }
}

