using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class SecureBootTests
{
    private const string LegacyX99Fixture = "8DPV11.bin";
    [TestMethod]
    public void OldX99ImageIsRepairedWithSafePlatformKeyAndMicrosoft2023()
    {
        byte[] original = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        BiosImage parsed = BiosImageLoader.Analyze(original);
        BiosImageLoader.EnsureValidBiosImage(parsed);
        Assert.AreEqual(ImageKind.IntelSpiImage, parsed.Kind);
        Assert.IsTrue(parsed.Regions.Any(region => region.Kind == FlashRegionKind.BIOS && region.WithinImage));

        SecureBootReport before = SecureBootInspector.Inspect(original);
        CollectionAssert.AreEquivalent(SecureBootInspector.Catalog.Select(c => c.Sha256).ToArray(),
            before.Missing2023.Select(c => c.Sha256).ToArray());

        byte[] updated = SecureBootImageUpdater.Update(original);
        SecureBootReport after = SecureBootInspector.Inspect(updated);
        BiosImage updatedImage = BiosImageLoader.Analyze(updated);
        BiosImageLoader.EnsureValidBiosImage(updatedImage);
        Assert.AreEqual(original.Length, updated.Length);
        Assert.AreEqual(0, after.Missing2023.Count);
        Assert.AreEqual(0, after.InvalidCertificateCount);
        Assert.IsFalse(after.HasLegacy);
        Assert.IsFalse(after.HasTestKey);
        Assert.IsFalse(after.HasDangerousCertificate);

        string[] actualMicrosoft = after.Certificates
            .Where(certificate => certificate.OfficialMicrosoft)
            .Select(certificate => certificate.Sha256)
            .Order()
            .ToArray();
        string[] expectedMicrosoft = SecureBootInspector.Catalog
            .Select(certificate => certificate.Sha256)
            .Order()
            .ToArray();
        CollectionAssert.AreEqual(expectedMicrosoft, actualMicrosoft);

        FirmwareCertificate platformKey = after.Certificates.Single(certificate => !certificate.OfficialMicrosoft);
        StringAssert.Contains(platformKey.Name, "Xeon V3 Control 2 Platform Key");
        Assert.IsFalse(platformKey.TestKey);
        Assert.IsTrue(platformKey.StrongPublicKey);
        Assert.AreEqual(CertificateSignatureAlgorithmStatus.Strong, platformKey.SignatureAlgorithmStatus);
        Assert.AreEqual(CertificateSignatureStatus.Verified, platformKey.SignatureStatus);
        Assert.AreEqual(SecureBootInspector.Catalog.Count + 1, after.Certificates.Count);
        Assert.IsFalse(after.Certificates.Any(certificate => certificate.Name.Contains("ASUSTeK", StringComparison.OrdinalIgnoreCase)));
        Assert.IsNotNull(updatedImage.ManagedSecureBoot);
        SecureBootReport managedAfter = updatedImage.ManagedSecureBoot!;
        Assert.IsFalse(managedAfter.HasLegacy);
        Assert.IsFalse(managedAfter.HasTestKey);
        Assert.IsFalse(managedAfter.HasDangerousCertificate);
        Assert.AreEqual(0, managedAfter.Missing2023.Count);
        Assert.IsTrue(before.HasLegacy);
        Assert.IsTrue(before.HasTestKey);

        InvalidDataException alreadyRepaired = Assert.Throws<InvalidDataException>(
            () => SecureBootImageUpdater.Update(updated));
        Assert.AreEqual(OperationError.CertificatesCurrent, alreadyRepaired.Message);
    }

    [TestMethod]
    public void UnrelatedLegacyCertificateCopyDoesNotInvalidateManagedStoreUpdate()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        BiosImage parsed = BiosImageLoader.Analyze(image);
        FlashRegion me = parsed.Regions.Single(region =>
            region.Kind == FlashRegionKind.ME && region.WithinImage);
        var (kekOffset, eraseByte) = FindActiveFfsFile(image, AmiSecureBootSpecification.KekFile);
        Assert.IsTrue(UefiFfsFileParser.TryRead(
            image,
            kekOffset,
            image.Length,
            eraseByte,
            out FfsFileHeaderInfo kekHeader));

        int strayOffset = checked((int)me.Offset + UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes);
        Assert.IsTrue(strayOffset + kekHeader.Size <= me.Offset + me.Length);
        image.AsSpan(kekOffset, kekHeader.Size).CopyTo(image.AsSpan(strayOffset, kekHeader.Size));
        Assert.IsTrue(SecureBootInspector.Inspect(image).HasLegacy);

        byte[] updated = SecureBootImageUpdater.Update(image);
        SecureBootReport broadReport = SecureBootInspector.Inspect(updated);
        BiosImage updatedImage = BiosImageLoader.Analyze(updated);

        Assert.IsTrue(broadReport.HasLegacy,
            "The unrelated ME copy intentionally remains and must not be treated as an active Secure Boot store.");
        Assert.AreEqual(0, broadReport.Missing2023.Count);
        Assert.IsNotNull(updatedImage.ManagedSecureBoot);
        SecureBootReport managedReport = updatedImage.ManagedSecureBoot!;
        Assert.IsFalse(managedReport.HasLegacy,
            "The UI-facing managed Secure Boot state must ignore inactive/unrelated certificate copies.");
        Assert.IsFalse(managedReport.HasTestKey);
        Assert.AreEqual(0, managedReport.Missing2023.Count);
    }

    [TestMethod]
    public void UnrelatedMalformedCompressedSectionDoesNotBlockManagedStoreUpdate()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        BiosImage parsed = BiosImageLoader.Analyze(image);
        FlashRegion me = parsed.Regions.Single(region =>
            region.Kind == FlashRegionKind.ME && region.WithinImage);
        int sectionStart = checked((int)me.Offset + UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes);
        Span<byte> section = image.AsSpan(sectionStart, AmiSecureBootSpecification.GuidedSectionHeaderBytes);
        section.Clear();
        WriteU24(section, 0, AmiSecureBootSpecification.GuidedSectionHeaderBytes);
        section[AmiSecureBootSpecification.SectionTypeOffset] = AmiSecureBootSpecification.GuidedSectionType;
        AmiSecureBootSpecification.LzmaGuidedSectionDefinition.ToByteArray().AsSpan().CopyTo(
            section[AmiSecureBootSpecification.GuidedSectionDefinitionOffset..]);
        BinaryPrimitives.WriteUInt16LittleEndian(
            section[AmiSecureBootSpecification.GuidedSectionDataOffsetOffset..],
            AmiSecureBootSpecification.GuidedSectionHeaderBytes);
        Assert.IsTrue(SecureBootInspector.Inspect(image).Incomplete);

        byte[] updated = SecureBootImageUpdater.Update(image);

        Assert.AreEqual(image.Length, updated.Length);
        Assert.IsTrue(SecureBootInspector.Inspect(updated).Incomplete,
            "Unrelated malformed data remains visible to the broad read-only inspector.");
    }

    [TestMethod]
    public void MirroredBiosRegionStoresAreAllRepairedWithTheSamePlatformKey()
    {
        byte[] original = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        BiosImage fullImage = BiosImageLoader.Analyze(original);
        FlashRegion bios = fullImage.Regions.Single(region =>
            region.Kind == FlashRegionKind.BIOS && region.WithinImage);
        byte[] biosRegion = original
            .AsSpan(checked((int)bios.Offset), checked((int)bios.Length))
            .ToArray();
        byte[] mirroredDump = new byte[checked(biosRegion.Length * 2)];
        biosRegion.CopyTo(mirroredDump, 0);
        biosRegion.CopyTo(mirroredDump, biosRegion.Length);

        BiosImage dump = BiosImageLoader.Analyze(mirroredDump);
        BiosImageLoader.EnsureValidBiosImage(dump);
        Assert.AreEqual(ImageKind.UefiImage, dump.Kind);
        Assert.HasCount(0, dump.Regions);
        Assert.IsTrue(dump.SecureBoot.HasLegacy);
        Assert.IsTrue(dump.SecureBoot.HasTestKey);

        byte[] updated = SecureBootImageUpdater.Update(mirroredDump);

        string? platformKeyHash = null;
        for (int copy = 0; copy < 2; copy++)
        {
            SecureBootReport report = SecureBootInspector.Inspect(
                updated.AsSpan(copy * biosRegion.Length, biosRegion.Length));
            Assert.IsFalse(report.HasLegacy);
            Assert.IsFalse(report.HasTestKey);
            Assert.AreEqual(0, report.Missing2023.Count);
            Assert.AreEqual(0, report.InvalidCertificateCount);

            FirmwareCertificate platformKey = report.Certificates.Single(certificate => !certificate.OfficialMicrosoft);
            Assert.IsTrue(platformKey.StrongPublicKey);
            Assert.AreEqual(CertificateSignatureStatus.Verified, platformKey.SignatureStatus);
            platformKeyHash ??= platformKey.Sha256;
            Assert.AreEqual(platformKeyHash, platformKey.Sha256);
        }
    }

    [TestMethod]
    public void InspectorChecksCertificateIdentitySignatureAndKeyStrength()
    {
        byte[] original = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        SecureBootReport report = SecureBootInspector.Inspect(original);

        FirmwareCertificate testKey = report.Certificates.Single(certificate => certificate.TestKey);
        Assert.AreEqual(CertificateSignatureStatus.Verified, testKey.SignatureStatus);
        Assert.IsTrue(testKey.StrongPublicKey);
        Assert.AreEqual(CertificateSignatureAlgorithmStatus.Strong, testKey.SignatureAlgorithmStatus);
        Assert.AreEqual("RSA", testKey.PublicKeyAlgorithm);
        Assert.IsTrue(testKey.PublicKeyBits >= SecureBootInspectionPolicy.MinimumRsaBits);

        FirmwareCertificate[] microsoft = report.Certificates.Where(certificate => certificate.OfficialMicrosoft).ToArray();
        Assert.AreEqual(3, microsoft.Length);
        Assert.IsTrue(microsoft.All(certificate => certificate.StrongPublicKey));
        Assert.IsTrue(microsoft.All(certificate =>
            certificate.SignatureAlgorithmStatus == CertificateSignatureAlgorithmStatus.Strong));
        Assert.IsTrue(microsoft.All(certificate => certificate.SignatureStatus == CertificateSignatureStatus.IssuerUnavailable));
        Assert.IsFalse(report.HasCertificateIntegrityFailure);
        Assert.IsFalse(report.HasCertificateCryptographicWarning);
        Assert.AreEqual(0, report.InvalidCertificateCount);
    }

    [TestMethod]
    public void SignatureAlgorithmPolicySeparatesStrengthFromVerificationSupport()
    {
        Assert.AreEqual(CertificateSignatureAlgorithmStatus.Strong,
            CertificateSignatureAlgorithms.Classify(CertificateSignatureAlgorithms.RsaSha256));
        Assert.AreEqual(CertificateSignatureAlgorithmStatus.Weak,
            CertificateSignatureAlgorithms.Classify(CertificateSignatureAlgorithms.RsaSha1));
        Assert.AreEqual(CertificateSignatureAlgorithmStatus.Weak,
            CertificateSignatureAlgorithms.Classify(CertificateSignatureAlgorithms.RsaMd5));
        Assert.AreEqual(CertificateSignatureAlgorithmStatus.Unsupported,
            CertificateSignatureAlgorithms.Classify("1.2.3.4.5"));

        Assert.IsTrue(CertificateSignatureAlgorithms.TryGetVerificationHash(
            CertificateSignatureAlgorithms.RsaSha1, out System.Security.Cryptography.HashAlgorithmName weakHash));
        Assert.AreEqual(System.Security.Cryptography.HashAlgorithmName.SHA1, weakHash);
    }

    [TestMethod]
    public void IssuerUnavailableDoesNotBecomeAnIntegrityOrCryptographicWarning()
    {
        var certificate = new FirmwareCertificate(
            "Reference",
            new string('A', Sha256Identity.HexCharacterCount),
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(1),
            false,
            false,
            false,
            false,
            "SPI",
            "sha256RSA",
            "RSA",
            SecureBootInspectionPolicy.MinimumRsaBits,
            true,
            CertificateSignatureAlgorithmStatus.Strong,
            CertificateSignatureStatus.IssuerUnavailable);
        var report = new SecureBootReport([certificate], [], false, 0);

        Assert.IsFalse(report.HasCertificateIntegrityFailure);
        Assert.IsFalse(report.HasCertificateCryptographicWarning);
    }


    [TestMethod]
    public void MutationPolicyMatchesUpdaterSafetyBoundary()
    {
        Assert.IsFalse(SecureBootMutationPolicy.CanModify(new SecureBootReport([], [], true, 0)));
        Assert.IsFalse(SecureBootMutationPolicy.CanModify(new SecureBootReport([], [], false, 1)));

        var weakButParseable = new FirmwareCertificate(
            "OEM reference",
            new string('B', Sha256Identity.HexCharacterCount),
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(1),
            false,
            false,
            false,
            false,
            "SPI",
            "sha1RSA",
            "RSA",
            SecureBootInspectionPolicy.MinimumRsaBits,
            true,
            CertificateSignatureAlgorithmStatus.Weak,
            CertificateSignatureStatus.IssuerUnavailable);
        var warningOnly = new SecureBootReport([weakButParseable], [], false, 0);

        Assert.IsTrue(warningOnly.HasCertificateCryptographicWarning);
        Assert.IsTrue(SecureBootMutationPolicy.CanModify(warningOnly),
            "A non-integrity cryptographic warning must remain visible but does not make the parsed layout unsafe to rewrite.");
    }

    [TestMethod]
    public void UserSuppliedDangerousCertificateCorpusIsRecognized()
    {
        string[] names =
        [
            "28f8aaadbce1d50d7ab10fdcdb8dcbd619e1929d4baee9404cc068f8d8e47095.cer",
            "617f9a3582de92b19a14bf45cd7041950f365b1e49bac2633fd02bb106902c8d.cer",
            "cca4e3f3170230030dc3e33d1e3fa7d1383de8b3367430892e93cbccde034ce0.cer"
        ];

        foreach (string name in names)
        {
            byte[] certificate = File.ReadAllBytes(FindDangerousCertificateFixture(name));
            SecureBootReport report = SecureBootInspector.Inspect(BuildX509SignatureList(certificate));

            Assert.HasCount(1, report.Certificates, name);
            Assert.IsTrue(report.Certificates[0].Dangerous, name);
        }

        byte[] ami = File.ReadAllBytes(FindDangerousCertificateFixture(names[1]));
        SecureBootReport amiReport = SecureBootInspector.Inspect(BuildX509SignatureList(ami));
        Assert.IsTrue(amiReport.HasTestKey);

        byte[] grub = File.ReadAllBytes(FindDangerousCertificateFixture(names[0]));
        SecureBootReport grubReport = SecureBootInspector.Inspect(BuildX509SignatureList(grub));
        Assert.IsTrue(grubReport.HasDangerousNonTestCertificate);
    }

    [TestMethod]
    public void DangerousCertificateHeuristicDoesNotDependOnlyOnKnownHashes()
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=grub",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, critical: true));
        var eku = new OidCollection { new("1.3.6.1.5.5.7.3.3") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, critical: false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        byte[] der = certificate.Export(X509ContentType.Cert);
        string hash = Convert.ToHexString(SHA256.HashData(der));
        Assert.IsFalse(new[]
        {
            "28F8AAADBCE1D50D7AB10FDCDB8DCBD619E1929D4BAEE9404CC068F8D8E47095",
            "617F9A3582DE92B19A14BF45CD7041950F365B1E49BAC2633FD02BB106902C8D",
            "CCA4E3F3170230030DC3E33D1E3FA7D1383DE8B3367430892E93CBCCDE034CE0"
        }.Contains(hash, StringComparer.Ordinal));

        SecureBootReport report = SecureBootInspector.Inspect(BuildX509SignatureList(der));

        Assert.HasCount(1, report.Certificates);
        Assert.IsTrue(report.Certificates[0].Dangerous);
        Assert.IsFalse(report.Certificates[0].TestKey);
    }

    [TestMethod]
    public void BundledCertificateCatalogProvidesVerifiedDisplayNames()
    {
        Assert.IsTrue(SecureBootInspector.Catalog.All(certificate => !string.IsNullOrWhiteSpace(certificate.DisplayName)));
        Assert.IsTrue(SecureBootInspector.Catalog.All(certificate =>
            string.Equals(Path.GetExtension(certificate.File), SecureBootCertificateResources.CertificateFileExtension,
                StringComparison.OrdinalIgnoreCase)));
    }

    [TestMethod]
    public void TestPkRemovalPreservesOtherCertificatesAndImageStructure()
    {
        byte[] original = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        SecureBootReport before = SecureBootInspector.Inspect(original);
        Assert.IsTrue(before.HasTestKey);

        byte[] sanitized = SecureBootImageUpdater.RemoveTestKeys(original);
        SecureBootReport after = SecureBootInspector.Inspect(sanitized);
        Assert.AreEqual(original.Length, sanitized.Length);
        Assert.IsFalse(after.HasTestKey);

        string[] expectedRemaining = before.Certificates.Where(certificate => !certificate.TestKey)
            .Select(certificate => certificate.Sha256).Order().ToArray();
        string[] actualRemaining = after.Certificates.Select(certificate => certificate.Sha256).Order().ToArray();
        CollectionAssert.AreEqual(expectedRemaining, actualRemaining);

        BiosImage parsed = BiosImageLoader.Analyze(sanitized);
        BiosImageLoader.EnsureValidBiosImage(parsed);
        Assert.Throws<InvalidDataException>(() => SecureBootImageUpdater.RemoveTestKeys(sanitized));
    }


    [TestMethod]
    public void EmbeddedFfsLikeGuidDoesNotBecomeASecureBootFile()
    {
        byte[] original = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        byte[] targetGuid = AmiSecureBootSpecification.KekFile.ToByteArray();
        int realTarget = original.AsSpan().IndexOf(targetGuid);
        Assert.IsTrue(realTarget > 0);

        int carrierLength = checked(AmiSecureBootSpecification.FfsFileHeaderBytes * 2);
        byte[] erasedRun = Enumerable.Repeat(byte.MaxValue, carrierLength).ToArray();
        int relativeRun = original.AsSpan(0, realTarget).LastIndexOf(erasedRun);
        Assert.IsTrue(relativeRun >= 0);

        Span<byte> fakeHeader = original.AsSpan(relativeRun, AmiSecureBootSpecification.FfsFileHeaderBytes);
        targetGuid.AsSpan().CopyTo(fakeHeader);
        fakeHeader[AmiSecureBootSpecification.FfsTypeOffset] = AmiSecureBootSpecification.FfsFreeformFileType;
        fakeHeader[AmiSecureBootSpecification.FfsSizeOffset] = AmiSecureBootSpecification.FfsFileHeaderBytes;
        fakeHeader[AmiSecureBootSpecification.FfsSizeOffset + 1] = 0;
        fakeHeader[AmiSecureBootSpecification.FfsSizeOffset + 2] = 0;

        byte[] updated = SecureBootImageUpdater.Update(original);
        SecureBootReport report = SecureBootInspector.Inspect(updated);

        Assert.AreEqual(0, report.Missing2023.Count);
        Assert.AreEqual(0, report.InvalidCertificateCount);
    }


    [TestMethod]
    public void MalformedLzmaSectionIsContainedByInspector()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        int sectionStart = FindGuidedLzmaSection(image, AmiSecureBootSpecification.LzmaGuidedSectionDefinition);
        int sectionSize = ReadU24(image, sectionStart);
        int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            image.AsSpan(sectionStart + AmiSecureBootSpecification.GuidedSectionDataOffsetOffset));
        int compressedOffset = checked(sectionStart + dataOffset + AmiSecureBootSpecification.LzmaHeaderBytes);
        int compressedLength = checked(sectionSize - dataOffset - AmiSecureBootSpecification.LzmaHeaderBytes);
        image.AsSpan(compressedOffset, compressedLength).Fill(byte.MaxValue);

        SecureBootReport report = SecureBootInspector.Inspect(image);

        Assert.IsTrue(report.Incomplete);
    }

    [TestMethod]
    public void MalformedSecureBootLzmaBlocksMutationAtValidationBoundary()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        var (kekFile, _) = FindActiveFfsFile(image, AmiSecureBootSpecification.KekFile);
        int sectionStart = checked(kekFile + AmiSecureBootSpecification.FfsFileHeaderBytes);
        int sectionSize = ReadU24(image, sectionStart);
        int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            image.AsSpan(sectionStart + AmiSecureBootSpecification.GuidedSectionDataOffsetOffset));
        int compressedOffset = checked(sectionStart + dataOffset + AmiSecureBootSpecification.LzmaHeaderBytes);
        int compressedLength = checked(sectionSize - dataOffset - AmiSecureBootSpecification.LzmaHeaderBytes);
        image.AsSpan(compressedOffset, compressedLength).Fill(byte.MaxValue);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => SecureBootImageUpdater.Update(image));

        Assert.AreEqual(OperationError.CertificateVerification, error.Message);
    }


    [TestMethod]
    public void MarkedForUpdateSecureBootFileBlocksMutation()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        var (kekFile, eraseByte) = FindActiveFfsFile(image, AmiSecureBootSpecification.KekFile);
        image[kekFile + AmiSecureBootSpecification.FfsStateOffset] = EncodeFfsState(
            AmiSecureBootSpecification.FfsDataValidPrerequisiteMask |
            AmiSecureBootSpecification.FfsFileMarkedForUpdateState,
            eraseByte);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => SecureBootImageUpdater.Update(image));

        Assert.AreEqual(OperationError.UnsupportedSecureBootLayout, error.Message);
    }

    [TestMethod]
    public void InvalidFixedFfsFileChecksumBlocksMutation()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        var (kekFile, _) = FindActiveFfsFile(image, AmiSecureBootSpecification.KekFile);
        Assert.AreEqual(
            AmiSecureBootSpecification.FfsFixedFileChecksum,
            image[kekFile + AmiSecureBootSpecification.FfsFileChecksumOffset]);
        image[kekFile + AmiSecureBootSpecification.FfsFileChecksumOffset]++;

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => SecureBootImageUpdater.Update(image));

        Assert.AreEqual(OperationError.UnsupportedSecureBootLayout, error.Message);
    }

    [TestMethod]
    public void PiFfsDataAlignmentAttributesDecodeToSpecifiedByteBoundaries()
    {
        Assert.AreEqual(1, AmiSecureBootSpecification.RequiredDataAlignment(0));
        Assert.AreEqual(65536, AmiSecureBootSpecification.RequiredDataAlignment(
            AmiSecureBootSpecification.FfsDataAlignmentAttributeMask));
        Assert.AreEqual(131072, AmiSecureBootSpecification.RequiredDataAlignment(
            AmiSecureBootSpecification.FfsDataAlignment2Attribute));
        Assert.AreEqual(16777216, AmiSecureBootSpecification.RequiredDataAlignment(
            (byte)(AmiSecureBootSpecification.FfsDataAlignment2Attribute |
                   AmiSecureBootSpecification.FfsDataAlignmentAttributeMask)));
    }

    [TestMethod]
    public void FixedFfsFileThatWouldMoveBlocksMutation()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        var (dbFile, eraseByte) = FindActiveFfsFile(image, AmiSecureBootSpecification.DbFile);
        Assert.IsTrue(UefiFfsFileParser.TryRead(image, dbFile, image.Length, eraseByte, out FfsFileHeaderInfo header));
        image[dbFile + AmiSecureBootSpecification.FfsAttributesOffset] |= AmiSecureBootSpecification.FfsFixedAttribute;
        FixSyntheticHeaderChecksum(image.AsSpan(dbFile, header.HeaderSize), header.HeaderSize);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => SecureBootImageUpdater.Update(image));

        Assert.AreEqual(OperationError.UnsupportedSecureBootLayout, error.Message);
    }

    [TestMethod]
    public void MisalignedFfsDataAttributeBlocksMutation()
    {
        byte[] image = File.ReadAllBytes(FindFixture(LegacyX99Fixture));
        var (dbFile, eraseByte) = FindActiveFfsFile(image, AmiSecureBootSpecification.DbFile);
        Assert.IsTrue(UefiFfsFileParser.TryRead(image, dbFile, image.Length, eraseByte, out FfsFileHeaderInfo header));
        image[dbFile + AmiSecureBootSpecification.FfsAttributesOffset] =
            (byte)((image[dbFile + AmiSecureBootSpecification.FfsAttributesOffset] &
                    ~AmiSecureBootSpecification.FfsDataAlignmentAttributeMask) |
                   (2 << AmiSecureBootSpecification.FfsDataAlignmentFieldShift));
        FixSyntheticHeaderChecksum(image.AsSpan(dbFile, header.HeaderSize), header.HeaderSize);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => SecureBootImageUpdater.Update(image));

        Assert.AreEqual(OperationError.UnsupportedSecureBootLayout, error.Message);
    }

    [TestMethod]
    public void Ffs2LargeFileUsesZeroSizeMarkerAndExtendedSize()
    {
        const int PayloadBytes = 8;
        int fileSize = checked(AmiSecureBootSpecification.FfsExtendedFileHeaderBytes + PayloadBytes);
        byte[] file = new byte[fileSize];
        AmiSecureBootSpecification.KekFile.ToByteArray().CopyTo(file, 0);
        file[AmiSecureBootSpecification.FfsTypeOffset] = AmiSecureBootSpecification.FfsFreeformFileType;
        file[AmiSecureBootSpecification.FfsAttributesOffset] = AmiSecureBootSpecification.FfsLargeFileAttribute;
        BinaryPrimitives.WriteUInt64LittleEndian(
            file.AsSpan(AmiSecureBootSpecification.FfsExtendedSizeOffset),
            checked((ulong)fileSize));
        file[AmiSecureBootSpecification.FfsStateOffset] = EncodeFfsState(
            AmiSecureBootSpecification.FfsDataValidPrerequisiteMask,
            AmiSecureBootSpecification.ErasedFlashByte);
        file[AmiSecureBootSpecification.FfsFileChecksumOffset] = AmiSecureBootSpecification.FfsFixedFileChecksum;
        FixSyntheticHeaderChecksum(file, AmiSecureBootSpecification.FfsExtendedFileHeaderBytes);

        bool parsed = UefiFfsFileParser.TryRead(
            file,
            0,
            file.Length,
            AmiSecureBootSpecification.ErasedFlashByte,
            out FfsFileHeaderInfo header);

        Assert.IsTrue(parsed);
        Assert.AreEqual(fileSize, header.Size);
        Assert.AreEqual(AmiSecureBootSpecification.FfsExtendedFileHeaderBytes, header.HeaderSize);
        Assert.AreEqual(FfsFileState.DataValid, header.State);
    }

    [TestMethod]
    public void ChecksummedFfsFileRejectsModifiedPayload()
    {
        const int PayloadBytes = 8;
        int fileSize = checked(AmiSecureBootSpecification.FfsFileHeaderBytes + PayloadBytes);
        byte[] file = new byte[fileSize];
        AmiSecureBootSpecification.DbFile.ToByteArray().CopyTo(file, 0);
        file[AmiSecureBootSpecification.FfsTypeOffset] = AmiSecureBootSpecification.FfsFreeformFileType;
        file[AmiSecureBootSpecification.FfsAttributesOffset] = AmiSecureBootSpecification.FfsChecksumAttribute;
        WriteU24(file, AmiSecureBootSpecification.FfsSizeOffset, fileSize);
        file[AmiSecureBootSpecification.FfsStateOffset] = EncodeFfsState(
            AmiSecureBootSpecification.FfsDataValidPrerequisiteMask,
            AmiSecureBootSpecification.ErasedFlashByte);
        for (int index = AmiSecureBootSpecification.FfsFileHeaderBytes; index < file.Length; index++)
        {
            file[index] = unchecked((byte)index);
        }
        FixSyntheticFileChecksum(file, AmiSecureBootSpecification.FfsFileHeaderBytes);
        FixSyntheticHeaderChecksum(file, AmiSecureBootSpecification.FfsFileHeaderBytes);

        Assert.IsTrue(UefiFfsFileParser.TryRead(
            file, 0, file.Length, AmiSecureBootSpecification.ErasedFlashByte, out _));

        file[^1] ^= byte.MaxValue;

        Assert.IsFalse(UefiFfsFileParser.TryRead(
            file, 0, file.Length, AmiSecureBootSpecification.ErasedFlashByte, out _));
    }

    [TestMethod]
    public void Ffs2RejectsSectionStyleExtendedSizeMarker()
    {
        byte[] file = new byte[AmiSecureBootSpecification.FfsExtendedFileHeaderBytes];
        AmiSecureBootSpecification.KekFile.ToByteArray().CopyTo(file, 0);
        file[AmiSecureBootSpecification.FfsTypeOffset] = AmiSecureBootSpecification.FfsFreeformFileType;
        file[AmiSecureBootSpecification.FfsAttributesOffset] = AmiSecureBootSpecification.FfsLargeFileAttribute;
        WriteU24(file, AmiSecureBootSpecification.FfsSizeOffset, AmiSecureBootSpecification.U24ExtendedSizeMarker);
        BinaryPrimitives.WriteUInt64LittleEndian(
            file.AsSpan(AmiSecureBootSpecification.FfsExtendedSizeOffset),
            checked((ulong)file.Length));
        file[AmiSecureBootSpecification.FfsStateOffset] = EncodeFfsState(
            AmiSecureBootSpecification.FfsDataValidPrerequisiteMask,
            AmiSecureBootSpecification.ErasedFlashByte);
        file[AmiSecureBootSpecification.FfsFileChecksumOffset] = AmiSecureBootSpecification.FfsFixedFileChecksum;
        FixSyntheticHeaderChecksum(file, AmiSecureBootSpecification.FfsExtendedFileHeaderBytes);

        bool parsed = UefiFfsFileParser.TryRead(
            file,
            0,
            file.Length,
            AmiSecureBootSpecification.ErasedFlashByte,
            out _);

        Assert.IsFalse(parsed);
    }

    [TestMethod]
    public void RandomX509GuidOccurrenceIsNotReportedAsIncompleteSignatureData()
    {
        byte[] data = new byte[BiosImageLoader.MinBiosImageBytes];
        EfiSignatureDatabaseSpecification.X509SignatureType.ToByteArray()
            .CopyTo(data, UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes);

        SecureBootReport report = SecureBootInspector.Inspect(data);

        Assert.IsFalse(report.Incomplete);
        Assert.AreEqual(0, report.InvalidCertificateCount);
        Assert.HasCount(0, report.Certificates);
    }



    private static (int Offset, byte EraseByte) FindActiveFfsFile(byte[] image, Guid guid)
    {
        BiosImage parsed = BiosImageLoader.Analyze(image);
        foreach (FirmwareVolume volume in parsed.Volumes)
        {
            int volumeOffset = checked((int)volume.Offset);
            int volumeEnd = checked(volumeOffset + (int)volume.Length);
            uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(
                image.AsSpan(volumeOffset + UefiFirmwareSpecification.FirmwareVolumeAttributesOffset));
            byte eraseByte = (attributes & UefiFirmwareSpecification.FirmwareVolumeErasePolarityMask) != 0
                ? byte.MaxValue
                : byte.MinValue;

            int search = volumeOffset;
            byte[] guidBytes = guid.ToByteArray();
            while (search <= volumeEnd - guidBytes.Length)
            {
                int relative = image.AsSpan(search, volumeEnd - search).IndexOf(guidBytes);
                if (relative < 0)
                {
                    break;
                }
                int candidate = checked(search + relative);
                if (UefiFfsFileParser.TryRead(image, candidate, volumeEnd, eraseByte, out FfsFileHeaderInfo header) &&
                    header.Guid == guid && header.State == FfsFileState.DataValid)
                {
                    return (candidate, eraseByte);
                }
                search = checked(candidate + guidBytes.Length);
            }
        }

        Assert.Fail($"Expected active FFS file {guid} in the firmware fixture.");
        return default;
    }

    private static byte EncodeFfsState(int logicalState, byte eraseByte)
    {
        byte value = checked((byte)logicalState);
        return eraseByte == byte.MaxValue ? unchecked((byte)~value) : value;
    }

    private static void FixSyntheticFileChecksum(Span<byte> file, int headerSize)
    {
        byte sum = 0;
        foreach (byte value in file[headerSize..])
        {
            sum = unchecked((byte)(sum + value));
        }
        file[AmiSecureBootSpecification.FfsFileChecksumOffset] = unchecked((byte)(0 - sum));
    }

    private static void FixSyntheticHeaderChecksum(Span<byte> file, int headerSize)
    {
        file[AmiSecureBootSpecification.FfsHeaderChecksumOffset] = 0;
        byte sum = 0;
        for (int index = 0; index < headerSize; index++)
        {
            if (index is AmiSecureBootSpecification.FfsFileChecksumOffset or AmiSecureBootSpecification.FfsStateOffset)
            {
                continue;
            }
            sum = unchecked((byte)(sum + file[index]));
        }
        file[AmiSecureBootSpecification.FfsHeaderChecksumOffset] = unchecked((byte)(0 - sum));
    }

    private static void WriteU24(Span<byte> data, int offset, int value)
    {
        data[offset] = unchecked((byte)value);
        data[offset + 1] = unchecked((byte)(value >> 8));
        data[offset + 2] = unchecked((byte)(value >> 16));
    }

    private static int FindGuidedLzmaSection(byte[] image, Guid definition)
    {
        byte[] guid = definition.ToByteArray();
        int search = 0;
        while (search <= image.Length - guid.Length)
        {
            int relative = image.AsSpan(search).IndexOf(guid);
            if (relative < 0)
            {
                break;
            }
            int guidOffset = checked(search + relative);
            int sectionStart = guidOffset - AmiSecureBootSpecification.GuidedSectionDefinitionOffset;
            if (sectionStart >= 0 &&
                image.Length - sectionStart >= AmiSecureBootSpecification.GuidedSectionHeaderBytes &&
                image[sectionStart + AmiSecureBootSpecification.SectionTypeOffset] == AmiSecureBootSpecification.GuidedSectionType)
            {
                int sectionSize = ReadU24(image, sectionStart);
                int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.AsSpan(sectionStart + AmiSecureBootSpecification.GuidedSectionDataOffsetOffset));
                if (sectionSize != AmiSecureBootSpecification.U24ExtendedSizeMarker &&
                    sectionSize <= image.Length - sectionStart &&
                    dataOffset >= AmiSecureBootSpecification.GuidedSectionHeaderBytes &&
                    dataOffset <= sectionSize - AmiSecureBootSpecification.LzmaHeaderBytes)
                {
                    return sectionStart;
                }
            }

            search = checked(guidOffset + guid.Length);
        }

        Assert.Fail("Expected a structurally valid LZMA guided section in the firmware fixture.");
        return -1;
    }

    private static int ReadU24(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;

    private static byte[] BuildX509SignatureList(byte[] certificate)
    {
        int signatureSize = checked(EfiSignatureDatabaseSpecification.SignatureOwnerBytes + certificate.Length);
        int listSize = checked(EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes + signatureSize);
        var data = new byte[listSize];
        EfiSignatureDatabaseSpecification.X509SignatureType.ToByteArray().CopyTo(data, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(EfiSignatureDatabaseSpecification.SignatureListSizeOffset),
            checked((uint)listSize));
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(EfiSignatureDatabaseSpecification.SignatureHeaderSizeOffset),
            0);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(EfiSignatureDatabaseSpecification.SignatureSizeOffset),
            checked((uint)signatureSize));
        EfiSignatureDatabaseSpecification.XeonV3ControlCertificateOwner.ToByteArray().CopyTo(
            data,
            EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes);
        certificate.CopyTo(
            data,
            EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes +
                EfiSignatureDatabaseSpecification.SignatureOwnerBytes);
        return data;
    }

    private static string FindDangerousCertificateFixture(string name)
    {
        for (DirectoryInfo? folder = new(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            string candidate = Path.Combine(folder.FullName, "tests", "DangerousSecureBootCerts", name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException(name);
    }

    private static string FindFixture(string name)
    {
        for (DirectoryInfo? folder = new(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            string candidate = Path.Combine(folder.FullName, "tests", name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException(name);
    }
}
