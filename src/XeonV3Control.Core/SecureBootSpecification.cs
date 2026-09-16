using System.Security.Cryptography;

namespace XeonV3Control.Core;

/// <summary>UEFI signature-database structures used by the Secure Boot inspector/updater.</summary>
internal static class EfiSignatureDatabaseSpecification
{
    internal static readonly Guid X509SignatureType = new("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
    internal static readonly Guid MicrosoftCertificateOwner = new("77fa9abd-0359-4d32-bd60-28f4e78f784b");
    internal static Guid XeonV3ControlCertificateOwner { get; } = new("a5c7eb95-d7c9-4644-9dde-2ff3505988b1");

    internal const int SignatureTypeOffset = 0;
    internal const int SignatureListSizeOffset = 16;
    internal const int SignatureHeaderSizeOffset = 20;
    internal const int SignatureSizeOffset = 24;
    internal const int SignatureListFixedHeaderBytes = 28;
    internal const int SignatureOwnerBytes = 16;
    internal const int MinimumX509SignatureBytes = SignatureOwnerBytes + 1;
}

/// <summary>AMI/UEFI FFS layout used by the narrowly-scoped X99 Secure Boot image editor.</summary>
internal static class AmiSecureBootSpecification
{
    internal static readonly Guid PlatformKeyFile = new("cc0f8a3f-3dea-4376-9679-5426ba0a907e");
    internal static readonly Guid KekFile = new("9fe7de69-0aea-470a-b50a-139813649189");
    internal static readonly Guid DbFile = new("fbf95065-427f-47b3-8077-d13c60710998");
    internal static readonly Guid LzmaGuidedSectionDefinition = new("ee4e5898-3914-4259-9d6e-dc7bd79403cf");

    internal const int FfsFileHeaderBytes = 24;
    internal const int FfsExtendedFileHeaderBytes = 32;
    internal const int FfsNameBytes = 16;
    internal const int FfsHeaderChecksumOffset = 16;
    internal const int FfsFileChecksumOffset = 17;
    internal const int FfsTypeOffset = 18;
    internal const int FfsAttributesOffset = 19;
    internal const int FfsSizeOffset = 20;
    internal const int FfsStateOffset = 23;
    internal const int FfsExtendedSizeOffset = FfsFileHeaderBytes;
    internal const byte FfsFreeformFileType = 0x02;
    internal const byte FfsLargeFileAttribute = 0x01;
    internal const byte FfsDataAlignment2Attribute = 0x02;
    internal const byte FfsFixedAttribute = 0x04;
    internal const byte FfsDataAlignmentAttributeMask = 0x38;
    internal const byte FfsChecksumAttribute = 0x40;
    internal const byte FfsKnownAttributeMask =
        FfsLargeFileAttribute | FfsDataAlignment2Attribute | FfsFixedAttribute |
        FfsDataAlignmentAttributeMask | FfsChecksumAttribute;
    internal const int FfsDataAlignmentFieldShift = 3;

    // PI FFS_ATTRIB_DATA_ALIGNMENT / FFS_ATTRIB_DATA_ALIGNMENT2 encodings.
    // These are specification-defined byte alignments for the beginning of file data,
    // relative to the containing firmware-volume base.
    private static readonly int[] BaseDataAlignments =
        [1, 16, 128, 512, 1024, 4096, 32768, 65536];
    private static readonly int[] ExtendedDataAlignments =
        [131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216];
    internal const byte FfsFixedFileChecksum = 0xAA;
    internal const int FfsAlignmentBytes = 8;
    internal const byte ErasedFlashByte = 0xFF;

    // UEFI PI firmware-file state bits. State is normalized against the containing FV erase polarity before use.
    internal const byte FfsFileHeaderConstructionState = 0x01;
    internal const byte FfsFileHeaderValidState = 0x02;
    internal const byte FfsFileDataValidState = 0x04;
    internal const byte FfsFileMarkedForUpdateState = 0x08;
    internal const byte FfsFileDeletedState = 0x10;
    internal const byte FfsFileHeaderInvalidState = 0x20;
    internal const byte FfsKnownStateMask = 0x3F;
    internal const byte FfsDataValidPrerequisiteMask =
        FfsFileHeaderConstructionState | FfsFileHeaderValidState | FfsFileDataValidState;

    // EFI_FFS_FILE_HEADER2 requires Size[3] to be zero; ExtendedSize carries the actual size.
    internal const int FfsLargeFileSizeMarker = 0;

    internal const int SectionHeaderBytes = 4;
    internal const int SectionTypeOffset = 3;
    internal const int GuidedSectionDefinitionOffset = SectionHeaderBytes;
    internal const int GuidedSectionDefinitionBytes = 16;
    internal const int GuidedSectionDataOffsetOffset = 20;
    internal const int GuidedSectionHeaderBytes = 24;
    internal const byte GuidedSectionType = 0x02;
    internal const byte RawSectionType = 0x19;

    internal const int LzmaPropertiesBytes = 5;
    internal const int LzmaUncompressedSizeBytes = sizeof(long);
    internal const int LzmaHeaderBytes = LzmaPropertiesBytes + LzmaUncompressedSizeBytes;
    internal const int LzmaUncompressedSizeOffset = LzmaPropertiesBytes;
    internal const int LzmaDictionarySizeOffset = 1;
    internal const byte MaximumValidLzmaPropertiesByte = 224;

    // Common section headers use 0xFFFFFF as the extended-size marker. FFS file headers do not.
    internal const int U24ExtendedSizeMarker = 0xFFFFFF;
    internal const int MaximumNormalU24Size = U24ExtendedSizeMarker - 1;
    internal const int MaximumNormalFfsFileBytes = U24ExtendedSizeMarker;

    internal static int RequiredDataAlignment(byte attributes)
    {
        int index = (attributes & FfsDataAlignmentAttributeMask) >> FfsDataAlignmentFieldShift;
        return (attributes & FfsDataAlignment2Attribute) != 0
            ? ExtendedDataAlignments[index]
            : BaseDataAlignments[index];
    }

    internal static bool IsFixed(byte attributes) => (attributes & FfsFixedAttribute) != 0;
}

/// <summary>Defensive resource limits for parsing untrusted firmware images.</summary>
public static class SecureBootCertificatePolicy
{
    public const int ExpiryWarningMonths = 6;
}


/// <summary>Single source of truth for whether automatic Secure Boot mutation is allowed.</summary>
public static class SecureBootMutationPolicy
{
    public static bool CanModify(SecureBootReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return !report.Incomplete && !report.HasCertificateIntegrityFailure;
    }

    public static void EnsureCanModify(SecureBootReport report)
    {
        if (!CanModify(report))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }
    }
}

internal static class SecureBootInspectionPolicy
{
    // Defensive parser budgets for untrusted firmware. These are product safety limits, not UEFI format limits.
    internal const int MaximumSignatureEntryBytes = 16 * 1024;
    internal const int MaximumSignatureListBytes = 16 * 1024 * 1024;
    internal const int MaximumSignatureLists = 4096;
    internal const int MaximumCertificateEntries = 8192;
    internal const int MaximumCompressedSections = 1024;
    internal const int MaximumCompressionDepth = 4;
    internal const int MaximumExpandedSectionBytes = 16 * 1024 * 1024;
    internal const int TotalExpansionBudgetBytes = 64 * 1024 * 1024;
    internal const int DecoderReadBufferBytes = 64 * 1024;

    internal const int MinimumRsaBits = 2048;
    internal const int MinimumEcdsaBits = 256;
    internal const int MinimumDsaBits = 2048;
    internal const int FallbackCertificateNameHashCharacters = 12;
}


internal static class EfiSignatureListValidation
{
    internal static bool IsValidX509List(int availableBytes, uint listSize, uint headerSize, uint signatureSize)
    {
        if (availableBytes < EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes)
        {
            return false;
        }

        uint fixedHeader = EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes;
        if (listSize < fixedHeader ||
            listSize > (uint)Math.Min(availableBytes, SecureBootInspectionPolicy.MaximumSignatureListBytes) ||
            headerSize > listSize - fixedHeader ||
            signatureSize < EfiSignatureDatabaseSpecification.MinimumX509SignatureBytes ||
            signatureSize > SecureBootInspectionPolicy.MaximumSignatureEntryBytes)
        {
            return false;
        }

        return (listSize - fixedHeader - headerSize) % signatureSize == 0;
    }
}

/// <summary>Mutation limits for the supported AMI X99 Secure Boot storage layout.</summary>
internal static class SecureBootRepairPolicy
{
    internal const int FileWriteBufferBytes = 64 * 1024;
    internal const int CertificateGrowthCapacityHintBytes = 8 * 1024;
    internal const int MaximumEditableRawSectionBytes = 4 * 1024 * 1024;
    internal const int PlatformKeyRsaBits = 2048;
    internal const string PlatformKeySubject = "CN=Xeon V3 Control 2 Platform Key";
    internal static DateTimeOffset PlatformKeyNotBeforeUtc { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal static DateTimeOffset PlatformKeyNotAfterUtc { get; } = new(2099, 12, 31, 23, 59, 59, TimeSpan.Zero);

    internal const int LzmaDictionaryBytes = 1 << 24;
    // Defensive mutation budget; a real firmware volume should be orders of magnitude below this.
    internal const int MaximumFilesPerFirmwareVolume = 65_536;
}

internal static class SecureBootCertificateRoles
{
    internal const string Kek = "KEK";
    internal const string Db = "db";

    internal static bool IsSupported(string? role) =>
        string.Equals(role, Kek, StringComparison.Ordinal) ||
        string.Equals(role, Db, StringComparison.Ordinal);
}

internal static class CertificateSignatureAlgorithms
{
    internal const string RsaMd5 = "1.2.840.113549.1.1.4";
    internal const string RsaSha1 = "1.2.840.113549.1.1.5";
    internal const string RsaSha256 = "1.2.840.113549.1.1.11";
    internal const string RsaSha384 = "1.2.840.113549.1.1.12";
    internal const string RsaSha512 = "1.2.840.113549.1.1.13";
    internal const string EcdsaSha1 = "1.2.840.10045.4.1";
    internal const string EcdsaSha256 = "1.2.840.10045.4.3.2";
    internal const string EcdsaSha384 = "1.2.840.10045.4.3.3";
    internal const string EcdsaSha512 = "1.2.840.10045.4.3.4";
    internal const string RsaOidPrefix = "1.2.840.113549.1.1.";
    internal const string EcdsaOidPrefix = "1.2.840.10045.4.";

    internal static CertificateSignatureAlgorithmStatus Classify(string? oid) => oid switch
    {
        RsaSha256 or RsaSha384 or RsaSha512 or EcdsaSha256 or EcdsaSha384 or EcdsaSha512 =>
            CertificateSignatureAlgorithmStatus.Strong,
        RsaMd5 or RsaSha1 or EcdsaSha1 => CertificateSignatureAlgorithmStatus.Weak,
        _ => CertificateSignatureAlgorithmStatus.Unsupported
    };

    internal static bool TryGetVerificationHash(string oid, out HashAlgorithmName hash)
    {
        hash = oid switch
        {
            RsaMd5 => HashAlgorithmName.MD5,
            RsaSha1 or EcdsaSha1 => HashAlgorithmName.SHA1,
            RsaSha256 or EcdsaSha256 => HashAlgorithmName.SHA256,
            RsaSha384 or EcdsaSha384 => HashAlgorithmName.SHA384,
            RsaSha512 or EcdsaSha512 => HashAlgorithmName.SHA512,
            _ => default
        };
        return !string.IsNullOrEmpty(hash.Name);
    }
}

internal static class SecureBootCertificateResources
{
    internal const string CatalogFileName = "catalog.json";
    internal const string KnownIdentityFileName = "known-identities.json";
    internal const string CertificateFileExtension = ".der";
    internal const string RootLocation = "SPI";
    internal static readonly string Prefix = EmbeddedResourceNames.FolderPrefix(EmbeddedResourceNames.CertificatesFolder);
}
