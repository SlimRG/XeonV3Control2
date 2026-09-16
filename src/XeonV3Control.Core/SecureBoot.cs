using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SharpCompress.Compressors.LZMA;

namespace XeonV3Control.Core;

public sealed record BundledCertificate(
    string File,
    string Role,
    string Sha256,
    bool Modern,
    string DisplayName);

internal sealed record BundledCertificateCatalogEntry(string File, string Role, string Sha256, bool Modern);
internal sealed record KnownCertificateIdentity(
    string Sha256,
    bool OfficialMicrosoft,
    bool Modern,
    bool TestKey,
    bool Dangerous);

public enum CertificateSignatureStatus
{
    IssuerUnavailable,
    Verified,
    Invalid,
    UnsupportedAlgorithm
}

public enum CertificateSignatureAlgorithmStatus
{
    Strong,
    Weak,
    Unsupported
}

public sealed record FirmwareCertificate(
    string Name,
    string Sha256,
    DateTime NotBeforeUtc,
    DateTime ExpiresUtc,
    bool OfficialMicrosoft,
    bool Modern,
    bool TestKey,
    bool Dangerous,
    string Location,
    string SignatureAlgorithm,
    string PublicKeyAlgorithm,
    int PublicKeyBits,
    bool StrongPublicKey,
    CertificateSignatureAlgorithmStatus SignatureAlgorithmStatus,
    CertificateSignatureStatus SignatureStatus);

public sealed record SecureBootReport(
    IReadOnlyList<FirmwareCertificate> Certificates,
    IReadOnlyList<BundledCertificate> Missing2023,
    bool Incomplete,
    int InvalidCertificateCount)
{
    public static SecureBootReport Empty { get; } = new([], [], false, 0);
    public bool HasLegacy => Certificates.Any(certificate => certificate.OfficialMicrosoft && !certificate.Modern);
    public bool HasTestKey => Certificates.Any(certificate => certificate.TestKey);
    public bool HasDangerousCertificate => Certificates.Any(certificate => certificate.Dangerous);
    public bool HasDangerousNonTestCertificate => Certificates.Any(certificate => certificate.Dangerous && !certificate.TestKey);
    public bool HasCertificateIntegrityFailure => InvalidCertificateCount > 0 ||
        Certificates.Any(certificate => certificate.SignatureStatus == CertificateSignatureStatus.Invalid);
    public bool HasCertificateCryptographicWarning => Certificates.Any(certificate =>
        !certificate.StrongPublicKey ||
        certificate.SignatureAlgorithmStatus != CertificateSignatureAlgorithmStatus.Strong);
}

/// <summary>Inspects stored EFI X.509 signature lists, not the running machine's trust state.</summary>
public static class SecureBootInspector
{
    private static readonly byte[] X509Type = EfiSignatureDatabaseSpecification.X509SignatureType.ToByteArray();
    private static readonly byte[] LzmaType = AmiSecureBootSpecification.LzmaGuidedSectionDefinition.ToByteArray();
    private static readonly IReadOnlyList<BundledCertificate> CatalogValue = LoadCatalog();
    private static readonly IReadOnlyDictionary<string, BundledCertificate> CatalogByHash =
        CatalogValue.ToDictionary(certificate => certificate.Sha256, StringComparer.Ordinal);
    private static readonly IReadOnlyDictionary<string, KnownCertificateIdentity> KnownIdentities = LoadKnownIdentities();

    public static IReadOnlyList<BundledCertificate> Catalog => CatalogValue;

    private static byte[] Resource(string file)
    {
        if (string.IsNullOrWhiteSpace(file) ||
            !string.Equals(file, Path.GetFileName(file), StringComparison.Ordinal))
        {
            throw new InvalidDataException(OperationError.CertificateCatalog);
        }

        using Stream stream = typeof(SecureBootInspector).Assembly.GetManifestResourceStream(SecureBootCertificateResources.Prefix + file)
            ?? throw new InvalidDataException(OperationError.CertificateCatalog);
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    public static byte[] CertificateBytes(BundledCertificate item)
    {
        ArgumentNullException.ThrowIfNull(item);
        byte[] bytes = Resource(item.File);
        if (!Sha256Identity.Matches(bytes, item.Sha256))
        {
            throw new CryptographicException(OperationError.CertificateHash);
        }
        return bytes;
    }

    public static SecureBootReport Inspect(ReadOnlySpan<byte> image, CancellationToken token = default)
    {
        var found = new Dictionary<string, FirmwareCertificate>(StringComparer.Ordinal);
        bool incomplete = false;
        int invalidCertificates = 0;
        int expansionBudget = SecureBootInspectionPolicy.TotalExpansionBudgetBytes;
        int sections = 0;
        int lists = 0;
        int certificateEntries = 0;

        Scan(image, SecureBootCertificateResources.RootLocation, 0);

        return new SecureBootReport(
            found.Values
                .OrderByDescending(certificate => certificate.OfficialMicrosoft)
                .ThenBy(certificate => certificate.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            CatalogValue.Where(certificate => certificate.Modern && !found.ContainsKey(certificate.Sha256)).ToArray(),
            incomplete,
            invalidCertificates);

        void Scan(ReadOnlySpan<byte> data, string location, int depth)
        {
            ScanSignatureLists(data, location);
            ScanCompressedSections(data, location, depth);
        }

        void ScanSignatureLists(ReadOnlySpan<byte> data, string location)
        {
            int position = 0;
            while (position <= data.Length - EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes)
            {
                token.ThrowIfCancellationRequested();
                int match = data[position..].IndexOf(X509Type);
                if (match < 0)
                {
                    break;
                }

                int start = position + match;
                position = start + EfiSignatureDatabaseSpecification.SignatureOwnerBytes;
                if (data.Length - start < EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes)
                {
                    continue;
                }

                ReadOnlySpan<byte> list = data[start..];
                uint listSize = ReadUInt32(list, EfiSignatureDatabaseSpecification.SignatureListSizeOffset);
                uint headerSize = ReadUInt32(list, EfiSignatureDatabaseSpecification.SignatureHeaderSizeOffset);
                uint signatureSize = ReadUInt32(list, EfiSignatureDatabaseSpecification.SignatureSizeOffset);

                // The GUID is searched in untrusted firmware bytes and may occur inside unrelated data.
                // Only structurally valid EFI_SIGNATURE_LIST candidates consume the parsing budget.
                if (!EfiSignatureListValidation.IsValidX509List(list.Length, listSize, headerSize, signatureSize))
                {
                    continue;
                }

                if (++lists > SecureBootInspectionPolicy.MaximumSignatureLists)
                {
                    incomplete = true;
                    return;
                }

                int listEnd = checked((int)listSize);
                int entrySize = checked((int)signatureSize);
                int entryOffset = EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes + checked((int)headerSize);
                for (; entryOffset < listEnd; entryOffset += entrySize)
                {
                    token.ThrowIfCancellationRequested();
                    if (++certificateEntries > SecureBootInspectionPolicy.MaximumCertificateEntries)
                    {
                        incomplete = true;
                        return;
                    }

                    try
                    {
                        ReadOnlySpan<byte> der = list.Slice(
                            entryOffset + EfiSignatureDatabaseSpecification.SignatureOwnerBytes,
                            entrySize - EfiSignatureDatabaseSpecification.SignatureOwnerBytes);
                        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
                        string hash = Convert.ToHexString(SHA256.HashData(der));
                        CatalogByHash.TryGetValue(hash, out BundledCertificate? bundled);
                        KnownIdentities.TryGetValue(hash, out KnownCertificateIdentity? known);
                        string signatureOid = certificate.SignatureAlgorithm.Value ?? string.Empty;
                        (string keyAlgorithm, int keyBits, bool strongKey) = PublicKeyInfo(certificate);
                        // Exact identities make known field samples deterministic, while conservative metadata
                        // heuristics catch future reissued test/development keys without deleting arbitrary OEM CAs.
                        bool testKey = known?.TestKey == true || HasExplicitUnsafeMarker(certificate);
                        bool dangerous = known?.Dangerous == true || testKey || LooksLikeBootloaderDevelopmentCertificate(certificate);

                        found.TryAdd(hash, new FirmwareCertificate(
                            CertificateDisplayName(certificate, hash),
                            hash,
                            certificate.NotBefore.ToUniversalTime(),
                            certificate.NotAfter.ToUniversalTime(),
                            bundled is not null || known?.OfficialMicrosoft == true,
                            bundled?.Modern ?? known?.Modern ?? false,
                            testKey,
                            dangerous,
                            FormatLocation(location, start + entryOffset + EfiSignatureDatabaseSpecification.SignatureOwnerBytes),
                            certificate.SignatureAlgorithm.FriendlyName ?? signatureOid,
                            keyAlgorithm,
                            keyBits,
                            strongKey,
                            CertificateSignatureAlgorithms.Classify(signatureOid),
                            VerifySelfSignature(certificate, signatureOid)));
                    }
                    catch (CryptographicException)
                    {
                        invalidCertificates++;
                        incomplete = true;
                    }
                }

                position = start + listEnd;
            }
        }

        void ScanCompressedSections(ReadOnlySpan<byte> data, string location, int depth)
        {
            int position = 0;
            while (position <= data.Length - AmiSecureBootSpecification.GuidedSectionDefinitionBytes)
            {
                token.ThrowIfCancellationRequested();
                int match = data[position..].IndexOf(LzmaType);
                if (match < 0)
                {
                    break;
                }

                int guidOffset = position + match;
                position = guidOffset + AmiSecureBootSpecification.GuidedSectionDefinitionBytes;
                int sectionStart = guidOffset - AmiSecureBootSpecification.GuidedSectionDefinitionOffset;
                if (sectionStart < 0 ||
                    data.Length - sectionStart < AmiSecureBootSpecification.GuidedSectionHeaderBytes ||
                    data[sectionStart + AmiSecureBootSpecification.SectionTypeOffset] != AmiSecureBootSpecification.GuidedSectionType)
                {
                    continue;
                }

                int sectionSize = ReadU24(data, sectionStart);
                int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    data[(sectionStart + AmiSecureBootSpecification.GuidedSectionDataOffsetOffset)..]);
                if (sectionSize == AmiSecureBootSpecification.U24ExtendedSizeMarker ||
                    sectionSize > data.Length - sectionStart ||
                    dataOffset < AmiSecureBootSpecification.GuidedSectionHeaderBytes ||
                    dataOffset > sectionSize - AmiSecureBootSpecification.LzmaHeaderBytes)
                {
                    incomplete = true;
                    continue;
                }

                ReadOnlySpan<byte> payload = data.Slice(sectionStart + dataOffset, sectionSize - dataOffset);
                long expandedLength = BinaryPrimitives.ReadInt64LittleEndian(
                    payload[AmiSecureBootSpecification.LzmaUncompressedSizeOffset..]);
                uint dictionarySize = ReadUInt32(payload, AmiSecureBootSpecification.LzmaDictionarySizeOffset);

                if (depth >= SecureBootInspectionPolicy.MaximumCompressionDepth ||
                    ++sections > SecureBootInspectionPolicy.MaximumCompressedSections ||
                    expandedLength < 1 ||
                    expandedLength > SecureBootInspectionPolicy.MaximumExpandedSectionBytes ||
                    expandedLength > expansionBudget ||
                    dictionarySize > SecureBootInspectionPolicy.MaximumExpandedSectionBytes ||
                    payload[0] > AmiSecureBootSpecification.MaximumValidLzmaPropertiesByte)
                {
                    incomplete = true;
                    continue;
                }

                expansionBudget -= checked((int)expandedLength);
                try
                {
                    using var input = new MemoryStream(payload[AmiSecureBootSpecification.LzmaHeaderBytes..].ToArray(), writable: false);
                    using var decoder = LzmaStream.Create(
                        payload[..AmiSecureBootSpecification.LzmaPropertiesBytes].ToArray(),
                        input,
                        input.Length,
                        expandedLength);
                    var expanded = new byte[checked((int)expandedLength)];
                    ReadExactly(decoder, expanded, token);
                    Scan(expanded, FormatCompressedLocation(location, sectionStart), depth + 1);
                }
                catch (Exception error) when (IsExpectedCompressionFailure(error))
                {
                    incomplete = true;
                }
            }
        }
    }

    private static void ReadExactly(Stream input, Span<byte> output, CancellationToken token)
    {
        int written = 0;
        while (written < output.Length)
        {
            token.ThrowIfCancellationRequested();
            int count = input.Read(output[written..Math.Min(output.Length, written + SecureBootInspectionPolicy.DecoderReadBufferBytes)]);
            if (count == 0)
            {
                throw new InvalidDataException(OperationError.CompressedSectionTruncated);
            }
            written += count;
        }
    }

    private static bool IsExpectedCompressionFailure(Exception error) =>
        FirmwareCompressionFailure.IsMalformedInput(error);


    private static bool HasExplicitUnsafeMarker(X509Certificate2 certificate)
    {
        string identity = string.Join(' ', certificate.Subject, certificate.Issuer, CertificateDisplayName(certificate, string.Empty));
        string normalized = identity.ToUpperInvariant();
        if (normalized.Contains("DO NOT TRUST", StringComparison.Ordinal))
        {
            return true;
        }

        string[] tokens = normalized
            .Split([' ', ',', '=', '-', '_', '/', '\\', '(', ')', '[', ']', ':', ';'], StringSplitOptions.RemoveEmptyEntries);
        return tokens.Any(token => token is "TEST" or "DEBUG" or "DEVELOPMENT" or "DEMO" or "SAMPLE");
    }

    private static bool LooksLikeBootloaderDevelopmentCertificate(X509Certificate2 certificate)
    {
        if (!certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) ||
            !HasCertificateAuthorityConstraint(certificate) ||
            !HasCodeSigningEnhancedKeyUsage(certificate))
        {
            return false;
        }

        string simpleName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false).Trim();
        if (simpleName.Length == 0)
        {
            return false;
        }

        string[] tokens = simpleName
            .ToUpperInvariant()
            .Split([' ', '-', '_', '/', '\\', '.', ':'], StringSplitOptions.RemoveEmptyEntries);
        return tokens.Any(token => token is "GRUB" or "SHIM" or "BOOTLOADER");
    }

    private static bool HasCertificateAuthorityConstraint(X509Certificate2 certificate)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509BasicConstraintsExtension constraints)
            {
                return constraints.CertificateAuthority;
            }
        }
        return false;
    }

    private static bool HasCodeSigningEnhancedKeyUsage(X509Certificate2 certificate)
    {
        const string codeSigningOid = "1.3.6.1.5.5.7.3.3";
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is not X509EnhancedKeyUsageExtension usage)
            {
                continue;
            }
            foreach (Oid oid in usage.EnhancedKeyUsages)
            {
                if (string.Equals(oid.Value, codeSigningOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private static (string Algorithm, int Bits, bool Strong) PublicKeyInfo(X509Certificate2 certificate)
    {
        using (RSA? rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                return ("RSA", rsa.KeySize, rsa.KeySize >= SecureBootInspectionPolicy.MinimumRsaBits);
            }
        }

        using (ECDsa? ecdsa = certificate.GetECDsaPublicKey())
        {
            if (ecdsa is not null)
            {
                return ("ECDSA", ecdsa.KeySize, ecdsa.KeySize >= SecureBootInspectionPolicy.MinimumEcdsaBits);
            }
        }

        using (DSA? dsa = certificate.GetDSAPublicKey())
        {
            if (dsa is not null)
            {
                return ("DSA", dsa.KeySize, dsa.KeySize >= SecureBootInspectionPolicy.MinimumDsaBits);
            }
        }

        return (certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "?", 0, false);
    }

    private static CertificateSignatureStatus VerifySelfSignature(X509Certificate2 certificate, string expectedOid)
    {
        if (!certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
        {
            return CertificateSignatureStatus.IssuerUnavailable;
        }

        try
        {
            var reader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            ReadOnlyMemory<byte> tbsCertificate = sequence.ReadEncodedValue();
            AsnReader algorithm = sequence.ReadSequence();
            string oid = algorithm.ReadObjectIdentifier();
            while (algorithm.HasData)
            {
                _ = algorithm.ReadEncodedValue();
            }
            if (!string.Equals(oid, expectedOid, StringComparison.Ordinal))
            {
                return CertificateSignatureStatus.Invalid;
            }
            byte[] signature = sequence.ReadBitString(out int unusedBitCount);
            if (unusedBitCount != 0 || sequence.HasData || reader.HasData)
            {
                return CertificateSignatureStatus.Invalid;
            }

            if (!CertificateSignatureAlgorithms.TryGetVerificationHash(oid, out HashAlgorithmName hash))
            {
                return CertificateSignatureStatus.UnsupportedAlgorithm;
            }

            bool verified;
            if (oid.StartsWith(CertificateSignatureAlgorithms.RsaOidPrefix, StringComparison.Ordinal))
            {
                using RSA? rsa = certificate.GetRSAPublicKey();
                if (rsa is null)
                {
                    return CertificateSignatureStatus.Invalid;
                }
                verified = rsa.VerifyData(tbsCertificate.Span, signature, hash, RSASignaturePadding.Pkcs1);
            }
            else if (oid.StartsWith(CertificateSignatureAlgorithms.EcdsaOidPrefix, StringComparison.Ordinal))
            {
                using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
                if (ecdsa is null)
                {
                    return CertificateSignatureStatus.Invalid;
                }
                verified = ecdsa.VerifyData(
                    tbsCertificate.Span,
                    signature,
                    hash,
                    DSASignatureFormat.Rfc3279DerSequence);
            }
            else
            {
                return CertificateSignatureStatus.UnsupportedAlgorithm;
            }

            return verified ? CertificateSignatureStatus.Verified : CertificateSignatureStatus.Invalid;
        }
        catch (Exception error) when (error is AsnContentException or CryptographicException or ArgumentException)
        {
            return CertificateSignatureStatus.Invalid;
        }
    }

    private static IReadOnlyList<BundledCertificate> LoadCatalog()
    {
        BundledCertificateCatalogEntry[] entries = JsonSerializer.Deserialize<BundledCertificateCatalogEntry[]>(
                Resource(SecureBootCertificateResources.CatalogFileName))
            ?? throw new InvalidDataException(OperationError.CertificateCatalog);
        if (entries.Length == 0)
        {
            throw new InvalidDataException(OperationError.CertificateCatalog);
        }

        var hashes = new HashSet<string>(StringComparer.Ordinal);
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalized = new BundledCertificate[entries.Length];
        for (int index = 0; index < entries.Length; index++)
        {
            BundledCertificateCatalogEntry entry = entries[index];
            if (string.IsNullOrWhiteSpace(entry.File) ||
                !string.Equals(entry.File, Path.GetFileName(entry.File), StringComparison.Ordinal) ||
                !string.Equals(Path.GetExtension(entry.File), SecureBootCertificateResources.CertificateFileExtension,
                    StringComparison.OrdinalIgnoreCase) ||
                !SecureBootCertificateRoles.IsSupported(entry.Role))
            {
                throw new InvalidDataException(OperationError.CertificateCatalog);
            }

            string hash = Sha256Identity.Normalize(entry.Sha256, OperationError.CertificateCatalog);
            if (!hashes.Add(hash) || !files.Add(entry.File))
            {
                throw new InvalidDataException(OperationError.CertificateCatalog);
            }

            byte[] bytes = Resource(entry.File);
            if (!Sha256Identity.Matches(bytes, hash))
            {
                throw new InvalidDataException(OperationError.CertificateCatalog);
            }

            try
            {
                using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(bytes);
                (string _, int _, bool strongKey) = PublicKeyInfo(certificate);
                if (!strongKey ||
                    CertificateSignatureAlgorithms.Classify(certificate.SignatureAlgorithm.Value) !=
                        CertificateSignatureAlgorithmStatus.Strong)
                {
                    throw new InvalidDataException(OperationError.CertificateCatalog);
                }

                normalized[index] = new BundledCertificate(
                    entry.File,
                    entry.Role,
                    hash,
                    entry.Modern,
                    CertificateDisplayName(certificate, hash));
            }
            catch (CryptographicException error)
            {
                throw new InvalidDataException(OperationError.CertificateCatalog, error);
            }
        }

        return Array.AsReadOnly(normalized);
    }

    private static IReadOnlyDictionary<string, KnownCertificateIdentity> LoadKnownIdentities()
    {
        KnownCertificateIdentity[] identities =
            JsonSerializer.Deserialize<KnownCertificateIdentity[]>(Resource(SecureBootCertificateResources.KnownIdentityFileName))
            ?? throw new InvalidDataException(OperationError.CertificateCatalog);
        var result = new Dictionary<string, KnownCertificateIdentity>(StringComparer.Ordinal);
        foreach (KnownCertificateIdentity identity in identities)
        {
            if ((identity.TestKey && identity.OfficialMicrosoft) ||
                (identity.TestKey && !identity.Dangerous))
            {
                throw new InvalidDataException(OperationError.CertificateCatalog);
            }

            string hash = Sha256Identity.Normalize(identity.Sha256, OperationError.CertificateCatalog);
            if (!result.TryAdd(hash, identity with { Sha256 = hash }))
            {
                throw new InvalidDataException(OperationError.CertificateCatalog);
            }
        }

        return result;
    }

    private static string CertificateDisplayName(X509Certificate2 certificate, string hash)
    {
        string name = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        if (!string.IsNullOrWhiteSpace(name))
        {
            return name;
        }
        if (!string.IsNullOrWhiteSpace(certificate.Subject))
        {
            return certificate.Subject;
        }
        return hash[..Math.Min(SecureBootInspectionPolicy.FallbackCertificateNameHashCharacters, hash.Length)];
    }

    private static string FormatLocation(string parent, int offset) =>
        parent + " + 0x" + offset.ToString("X", System.Globalization.CultureInfo.InvariantCulture);

    private static string FormatCompressedLocation(string parent, int offset) =>
        parent + " / LZMA 0x" + offset.ToString("X", System.Globalization.CultureInfo.InvariantCulture);

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);

    private static int ReadU24(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;
}
