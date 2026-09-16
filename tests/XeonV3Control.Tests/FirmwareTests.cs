using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class FirmwareTests
{
    private const int SyntheticFirmwareVolumeHeaderBytes =
        UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset +
        2 * UefiFirmwareSpecification.FirmwareVolumeBlockMapEntryBytes;
    private const int SyntheticCapsuleHeaderBytes = 32;

    public static byte[] Image(int length = BiosImageLoader.MinBiosImageBytes)
    {
        byte[] data = new byte[length];
        UefiFirmwareSpecification.StandardFirmwareFileSystems[1].TryWriteBytes(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset));
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeLengthOffset),
            checked((ulong)length));
        UefiFirmwareSpecification.FirmwareVolumeSignature.CopyTo(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeSignatureOffset));
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset),
            SyntheticFirmwareVolumeHeaderBytes);
        data[UefiFirmwareSpecification.FirmwareVolumeRevisionOffset] =
            UefiFirmwareSpecification.FirmwareVolumeRevision2;
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset + sizeof(uint)),
            checked((uint)length));
        RecalculateVolumeChecksum(data);
        return data;
    }

    [TestMethod]
    public void ValidImageHasExactHashAndVolume()
    {
        byte[] data = Image();
        BiosImage result = BiosImageLoader.Analyze(data);
        Assert.AreEqual(ImageKind.UefiImage, result.Kind);
        Assert.HasCount(1, result.Volumes);
        Assert.IsEmpty(result.Issues);
        Assert.AreEqual(Convert.ToHexString(SHA256.HashData(data)), result.Sha256);
    }

    [TestMethod]
    public void FvhInstructionLiteralIsNotAMalformedVolume()
    {
        byte[] data = Image();
        const int instructionOffset = 200;
        const int instructionBytes = 64;
        const int embeddedSignatureOffset = 240;
        Array.Fill(data, (byte)0xCC, instructionOffset, instructionBytes);
        UefiFirmwareSpecification.FirmwareVolumeSignature.CopyTo(data.AsSpan(embeddedSignatureOffset));

        BiosImage result = BiosImageLoader.Analyze(data);

        Assert.HasCount(1, result.Volumes);
        Assert.IsEmpty(result.Issues);
    }

    [TestMethod]
    public async Task ReferenceX99ImageExtractsBiosAndBoardIdentityFromFirmwareBytes()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] data = await File.ReadAllBytesAsync(path);

        BiosImage image = BiosImageLoader.Analyze(data);

        Assert.AreEqual("American Megatrends, Inc.", image.FirmwareIdentity.BiosManufacturer);
        Assert.AreEqual("X9F8P Ver:003", image.FirmwareIdentity.BiosVersion);
        Assert.AreEqual("09/06/2022", image.FirmwareIdentity.BiosReleaseDate);
        Assert.AreEqual("Huananzhi", image.FirmwareIdentity.BoardManufacturer);
        Assert.AreEqual("X99-F8D Plus", image.FirmwareIdentity.BoardName);
        Assert.IsNull(image.FirmwareIdentity.BoardVersion);
        Assert.IsNull(image.FirmwareIdentity.BoardSerialNumber);
    }

    [TestMethod]
    public async Task NalexUptImageKeepsBiosAndBoardIdentityWhenFirmwareLayoutMoves()
    {
        string path = RepositoryTestFiles.Find(
            "tests", "TurboUnlock", "ForeignCleanup", "8DPV11_nalex_upt.bin");
        byte[] data = await File.ReadAllBytesAsync(path);

        BiosImage image = BiosImageLoader.Analyze(data);

        Assert.AreEqual("American Megatrends, Inc.", image.FirmwareIdentity.BiosManufacturer);
        Assert.AreEqual("X9F8P Ver:003", image.FirmwareIdentity.BiosVersion);
        Assert.AreEqual("09/06/2022", image.FirmwareIdentity.BiosReleaseDate);
        Assert.AreEqual("Huananzhi", image.FirmwareIdentity.BoardManufacturer);
        Assert.AreEqual("X99-F8D Plus", image.FirmwareIdentity.BoardName);
        Assert.IsNull(image.FirmwareIdentity.BoardVersion);
        Assert.IsNull(image.FirmwareIdentity.BoardSerialNumber);
    }

    [TestMethod]
    public void RejectsEmpty() => Assert.Throws<InvalidDataException>(() => BiosImageLoader.Analyze([]));

    [TestMethod]
    public void RandomFileIsNotBios() =>
        Assert.AreEqual(ImageKind.Unknown, BiosImageLoader.Analyze([1, 2, 3, 4]).Kind);

    [TestMethod]
    public void StrictValidationAcceptsStructurallyValidFirmwareImage() =>
        BiosImageLoader.EnsureValidBiosImage(BiosImageLoader.Analyze(Image()));

    [TestMethod]
    public void StrictValidationRejectsStructurallyInvalidFullSizeInput()
    {
        byte[] data = new byte[BiosImageLoader.MinBiosImageBytes];
        Array.Fill(data, (byte)0xA5);
        BiosImage image = BiosImageLoader.Analyze(data);
        InvalidDataException error = Assert.Throws<InvalidDataException>(() =>
            BiosImageLoader.EnsureValidBiosImage(image));
        Assert.AreEqual(FirmwareValidationError.NotBiosImage, error.Message);
    }

    [TestMethod]
    public void StrictValidationRejectsUndersizedInput()
    {
        BiosImage image = BiosImageLoader.Analyze([1, 2, 3, 4]);
        InvalidDataException error = Assert.Throws<InvalidDataException>(() =>
            BiosImageLoader.EnsureValidBiosImage(image));
        Assert.AreEqual(FirmwareValidationError.ImageSize, error.Message);
    }

    [TestMethod]
    public void StrictValidationRejectsUnknownFirmwareFileSystem()
    {
        byte[] data = Image();
        new Guid("11111111-2222-3333-4444-555555555555").TryWriteBytes(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset));
        RecalculateVolumeChecksum(data);
        BiosImage image = BiosImageLoader.Analyze(data);
        Assert.Throws<InvalidDataException>(() => BiosImageLoader.EnsureValidBiosImage(image));
    }

    [TestMethod]
    public void StrictValidationRejectsInvalidBlockMap()
    {
        byte[] data = Image();
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset), 2);
        RecalculateVolumeChecksum(data);
        BiosImage image = BiosImageLoader.Analyze(data);
        CollectionAssert.Contains(image.Issues.ToArray(), FirmwareValidationError.InvalidVolume);
        Assert.Throws<InvalidDataException>(() => BiosImageLoader.EnsureValidBiosImage(image));
    }

    [TestMethod]
    public void SupportedPickerExtensionsAreExplicitAndNormalized()
    {
        Assert.IsTrue(BiosImageLoader.SupportedFileExtensions.Count > 0);
        Assert.IsTrue(BiosImageLoader.SupportedFileExtensions.All(extension =>
            extension.StartsWith(".", StringComparison.Ordinal) && extension == extension.ToLowerInvariant()));
        CollectionAssert.Contains(BiosImageLoader.SupportedFileExtensions.ToArray(), ".bin");
        CollectionAssert.Contains(BiosImageLoader.SupportedFileExtensions.ToArray(), ".rom");
        Assert.IsTrue(BiosImageLoader.HasSupportedFileExtension("firmware.BIN"));
        Assert.IsTrue(BiosImageLoader.HasSupportedFileExtension("firmware.rom"));
        Assert.IsFalse(BiosImageLoader.HasSupportedFileExtension("firmware.bin.txt"));
        Assert.IsFalse(BiosImageLoader.HasSupportedFileExtension("firmware"));
        Assert.IsFalse(BiosImageLoader.HasSupportedFileExtension(null));
    }

    [TestMethod]
    public void TruncatedVolumeIsReported()
    {
        byte[] truncated = Image()[..512];
        BiosImage result = BiosImageLoader.Analyze(truncated);
        Assert.IsEmpty(result.Volumes);
        CollectionAssert.Contains(result.Issues.ToArray(), FirmwareValidationError.InvalidVolume);
    }

    [TestMethod]
    public void OverflowLengthCannotEscapeBounds()
    {
        byte[] data = Image();
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeLengthOffset), ulong.MaxValue);
        Assert.IsEmpty(BiosImageLoader.Analyze(data).Volumes);
    }

    [TestMethod]
    public void BadChecksumIsNotAcceptedAsHealthy()
    {
        byte[] data = Image();
        data[UefiFirmwareSpecification.FirmwareVolumeChecksumOffset] ^= 1;
        Assert.IsFalse(BiosImageLoader.Analyze(data).Volumes[0].HeaderChecksumValid);
    }

    [TestMethod]
    public void IntelDescriptorRegionsUseRelativeOffsets()
    {
        int descriptorBytes = IntelFlashDescriptorSpecification.DescriptorWindowBytes;
        int biosBytes = 3 * descriptorBytes;
        byte[] data = new byte[descriptorBytes + biosBytes];
        WriteDescriptorHeader(data, regionCount: 2);
        WriteDescriptorRegion(data, 0, startBlock: 0, endBlock: 0);
        WriteDescriptorRegion(data, 1, startBlock: 1, endBlock: 3);
        Image(biosBytes).CopyTo(data, descriptorBytes);

        BiosImage result = BiosImageLoader.Analyze(data);

        Assert.AreEqual(ImageKind.IntelSpiImage, result.Kind);
        Assert.HasCount(2, result.Regions);
        Assert.AreEqual((long)descriptorBytes, result.Regions[1].Offset);
        Assert.IsEmpty(result.Issues);
    }

    [TestMethod]
    public void WellsburgSixRegionDescriptorIsAccepted()
    {
        byte[] data = new byte[BiosImageLoader.MinBiosImageBytes];
        WriteDescriptorHeader(data, regionCount: 6);
        WriteDescriptorRegion(data, 0, startBlock: 0, endBlock: 0);
        uint biosEndBlock = checked((uint)(data.Length / (1 << IntelFlashDescriptorSpecification.RegionAddressShift) - 1));
        WriteDescriptorRegion(data, 1, startBlock: 1, endBlock: biosEndBlock);
        for (int index = 2; index < 6; index++)
        {
            WriteDisabledDescriptorRegion(data, index);
        }
        Image(data.Length - IntelFlashDescriptorSpecification.DescriptorWindowBytes)
            .CopyTo(data, IntelFlashDescriptorSpecification.DescriptorWindowBytes);

        BiosImage result = BiosImageLoader.Analyze(data);

        Assert.AreEqual(ImageKind.IntelSpiImage, result.Kind);
        Assert.HasCount(2, result.Regions);
        Assert.IsFalse(result.Issues.Contains(FirmwareValidationError.InvalidDescriptor));
        BiosImageLoader.EnsureValidBiosImage(result);
    }

    [TestMethod]
    public void DescriptorCannotReferencePastEnd()
    {
        byte[] data = new byte[IntelFlashDescriptorSpecification.DescriptorWindowBytes];
        WriteDescriptorHeader(data, regionCount: 1);
        WriteDescriptorRegion(data, 0, startBlock: 0, endBlock: 1);

        CollectionAssert.Contains(
            BiosImageLoader.Analyze(data).Issues.ToArray(),
            FirmwareValidationError.RegionOutsideImage);
    }

    [TestMethod]
    public void CapsuleRetainsContainerOffsets()
    {
        int payloadBytes = IntelFlashDescriptorSpecification.DescriptorWindowBytes;
        byte[] data = new byte[SyntheticCapsuleHeaderBytes + payloadBytes];
        UefiFirmwareSpecification.CapsuleGuids[0].TryWriteBytes(data);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.CapsuleHeaderSizeOffset),
            SyntheticCapsuleHeaderBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.CapsuleImageSizeOffset),
            checked((uint)data.Length));
        Image(payloadBytes).CopyTo(data, SyntheticCapsuleHeaderBytes);

        BiosImage image = BiosImageLoader.Analyze(data);

        Assert.AreEqual(ImageKind.Capsule, image.Kind);
        Assert.AreEqual((long)SyntheticCapsuleHeaderBytes, image.Volumes[0].Offset);
    }

    [TestMethod]
    public void ArbitraryInputDoesNotThrowOrHang()
    {
        var random = new Random(481);
        for (int length = 1; length < 10000; length += 73)
        {
            byte[] data = new byte[length];
            random.NextBytes(data);
            _ = BiosImageLoader.Analyze(data);
        }
    }

    [TestMethod]
    public void TranslationsHaveCompleteKeyParityAndSystemFallback()
    {
        var baseline = new LocalizationCatalog(LocalizationCatalog.DefaultCulture);
        Assert.IsTrue(LocalizationCatalog.SupportedCultures.Count > 0);
        foreach (string culture in LocalizationCatalog.SupportedCultures)
        {
            var catalog = new LocalizationCatalog(culture);
            CollectionAssert.AreEquivalent(baseline.Keys.ToArray(), catalog.Keys.ToArray());
            foreach (string key in baseline.Keys)
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(catalog[key]));
            }
            foreach (string navigationKey in new[] { "NavSource", "NavAnalysis", "NavSecureBoot", "NavDrivers" })
            {
                Assert.IsFalse(StartsWithSectionNumber(catalog[navigationKey]));
            }
        }

        Assert.AreEqual(LocalizationCatalog.DefaultCulture, new LocalizationCatalog("de-DE").Language);
        Assert.AreEqual("ru-RU", new LocalizationCatalog("ru-UA").Language);
        Assert.AreEqual("uk-UA", new LocalizationCatalog("uk-RU").Language);
        Assert.AreEqual("zh-CN", new LocalizationCatalog("zh-Hant").Language);
        Assert.AreEqual("uk-UA", new LocalizationCatalog("uk-RU").Culture.Name);
    }

    [TestMethod]
    public async Task TwoMatchingReadsAreSavedAndLoaded()
    {
        string path = TemporaryBiosPath();
        try
        {
            var provider = new Reader(Image(), Image());
            VerifiedFirmwareDump result = await VerifiedDump.CreateAsync(provider, path);
            Assert.AreEqual(2, provider.Reads);
            Assert.AreEqual(Path.GetFullPath(path), result.Image.FilePath);
            Assert.AreEqual(result.Image.Sha256, (await BiosImageLoader.LoadAsync(path)).Sha256);
            Assert.AreEqual(FirmwareReadScope.BiosRegion, result.Scope);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task MismatchedReadsNeverPublishAnImage()
    {
        string path = TemporaryBiosPath();
        byte[] changed = Image();
        changed[100] = 1;
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            VerifiedDump.CreateAsync(new Reader(Image(), changed), path));
        Assert.IsFalse(File.Exists(path));
    }

    [TestMethod]
    public async Task MalformedMatchingDumpsAreRejected()
    {
        string path = TemporaryBiosPath();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            VerifiedDump.CreateAsync(new Reader([0, 1], [0, 1]), path));
        Assert.IsFalse(File.Exists(path));
    }

    [TestMethod]
    public async Task ExistingFileIsNeverOverwritten()
    {
        string path = TemporaryBiosPath();
        try
        {
            await File.WriteAllTextAsync(path, "preserve");
            await Assert.ThrowsAsync<IOException>(() =>
                VerifiedDump.CreateAsync(new Reader(Image(), Image()), path));
            Assert.AreEqual("preserve", await File.ReadAllTextAsync(path));
            Assert.IsEmpty(Directory.GetFiles(
                Path.GetDirectoryName(path)!,
                Path.GetFileName(path) + ".*.partial"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task CancelledDumpLeavesNoOutput()
    {
        string path = TemporaryBiosPath();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            VerifiedDump.CreateAsync(
                new Reader(Image(), Image()),
                path,
                cancellationToken: cancellation.Token));
        Assert.IsFalse(File.Exists(path));
    }

    private static string TemporaryBiosPath() =>
        Path.Combine(Path.GetTempPath(), Guid.NewGuid() + BiosImageLoader.SupportedFileExtensions[0]);

    private static void RecalculateVolumeChecksum(byte[] data)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeChecksumOffset), 0);
        int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset));
        uint sum = 0;
        for (int offset = 0; offset < headerLength; offset += sizeof(ushort))
        {
            sum += BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset));
        }
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(UefiFirmwareSpecification.FirmwareVolumeChecksumOffset),
            unchecked((ushort)-sum));
    }

    private static void WriteDescriptorHeader(byte[] data, int regionCount)
    {
        if (regionCount is < 1 or > IntelFlashDescriptorSpecification.MaximumRegionCount)
        {
            throw new ArgumentOutOfRangeException(nameof(regionCount));
        }

        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(IntelFlashDescriptorSpecification.SignatureOffset),
            IntelFlashDescriptorSpecification.Signature);
        uint regionTableBase = checked((uint)(
            IntelFlashDescriptorSpecification.MinimumRegionTableOffset /
            IntelFlashDescriptorSpecification.RegionTableAddressUnitBytes));
        uint flashMap0 =
            (regionTableBase << IntelFlashDescriptorSpecification.RegionBaseFieldShift) |
            (checked((uint)(regionCount - IntelFlashDescriptorSpecification.RegionCountBias)) <<
             IntelFlashDescriptorSpecification.RegionCountFieldShift);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(IntelFlashDescriptorSpecification.FlashMap0Offset),
            flashMap0);
    }

    private static void WriteDescriptorRegion(byte[] data, int index, uint startBlock, uint endBlock)
    {
        uint value =
            (startBlock & IntelFlashDescriptorSpecification.RegionAddressFieldMask) |
            ((endBlock & IntelFlashDescriptorSpecification.RegionAddressFieldMask) << 16);
        int offset = IntelFlashDescriptorSpecification.MinimumRegionTableOffset +
            index * IntelFlashDescriptorSpecification.RegionEntryBytes;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
    }

    private static void WriteDisabledDescriptorRegion(byte[] data, int index) =>
        WriteDescriptorRegion(
            data,
            index,
            IntelFlashDescriptorSpecification.RegionAddressFieldMask,
            0);

    private static bool StartsWithSectionNumber(string value) =>
        value.Length >= 2 && char.IsDigit(value[0]) && value[1] == '.';

    private sealed class Reader(byte[] first, byte[] second) : IFirmwareReader
    {
        public int Reads { get; private set; }
        public FirmwareCapabilities Capabilities => new(true, false, FirmwareReadScope.BiosRegion);

        public FirmwareReadSnapshot ReadFirmware(IProgress<double>? progress, CancellationToken cancellationToken)
        {
            _ = progress;
            cancellationToken.ThrowIfCancellationRequested();
            byte[] data = ++Reads == 1 ? first : second;
            return new FirmwareReadSnapshot(
                data,
                FirmwareReadScope.BiosRegion,
                [new FirmwareRegionReadStatus(FlashRegionKind.BIOS, 0, data.Length, true)]);
        }
    }
}
