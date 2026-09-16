using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpCompress.Compressors.LZMA;

namespace XeonV3Control.Core;

/// <summary>Creates modified AMI X99 images while preserving the source image.</summary>
public static class SecureBootImageUpdater
{
    private static readonly byte[] LzmaSection = AmiSecureBootSpecification.LzmaGuidedSectionDefinition.ToByteArray();
    private static readonly byte[] X509Type = EfiSignatureDatabaseSpecification.X509SignatureType.ToByteArray();
    private static readonly byte[] MicrosoftOwner = EfiSignatureDatabaseSpecification.MicrosoftCertificateOwner.ToByteArray();
    private static readonly byte[] s_applicationOwner = EfiSignatureDatabaseSpecification.XeonV3ControlCertificateOwner.ToByteArray();

    public static async Task UpdateFileAsync(string source, string destination, CancellationToken token = default)
    {
        byte[] original = await ReadSourceImageAsync(source, token);
        byte[] updated = Update(original, token);
        await WriteNewImageAsync(destination, updated, token);
    }

    /// <summary>
    /// Returns the certificates contained in the unambiguous AMI PK/KEK/db stores managed by this updater.
    /// The broad SecureBootInspector scan is intentionally not used for repair decisions because firmware
    /// images can contain inactive, recovery, or unrelated certificate copies.
    /// </summary>
    internal static SecureBootReport? TryInspectManagedState(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token = default)
    {
        try
        {
            FfsFileLocation[] platformKeys = FindFiles(
                source,
                image,
                AmiSecureBootSpecification.PlatformKeyFile,
                token);
            if (platformKeys.Length == 0 ||
                platformKeys.GroupBy(file => file.VolumeStart).Any(group => group.Count() != 1))
            {
                return null;
            }

            SecureBootStorePair[] pairs = FindCertificateStorePairs(source, image, token);
            var reports = new List<SecureBootReport>(platformKeys.Length + (pairs.Length * 2));
            foreach (FfsFileLocation platformKey in platformKeys)
            {
                reports.Add(InspectSecureBootFile(source, platformKey, token));
            }
            foreach (SecureBootStorePair pair in pairs)
            {
                reports.Add(InspectSecureBootFile(source, pair.Kek, token));
                reports.Add(InspectSecureBootFile(source, pair.Db, token));
            }

            FirmwareCertificate[] certificates = reports
                .SelectMany(report => report.Certificates)
                .GroupBy(certificate => certificate.Sha256, StringComparer.Ordinal)
                .Select(group => group.First())
                .OrderByDescending(certificate => certificate.OfficialMicrosoft)
                .ThenBy(certificate => certificate.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var presentHashes = certificates
                .Select(certificate => certificate.Sha256)
                .ToHashSet(StringComparer.Ordinal);
            BundledCertificate[] missing = SecureBootInspector.Catalog
                .Where(certificate => certificate.Modern && !presentHashes.Contains(certificate.Sha256))
                .ToArray();

            return new SecureBootReport(
                certificates,
                missing,
                reports.Any(report => report.Incomplete),
                reports.Sum(report => report.InvalidCertificateCount));
        }
        catch (InvalidDataException error) when (
            string.Equals(error.Message, OperationError.UnsupportedSecureBootLayout, StringComparison.Ordinal))
        {
            return null;
        }
    }

    public static byte[] Update(ReadOnlySpan<byte> source, CancellationToken token = default)
    {
        byte[] working = source.ToArray();
        BiosImage initial = ValidateSourceImage(working, token);

        bool changed = false;
        if (HasManagedPlatformKeyMatching(working, initial, PlatformKeyRemovalMode.Dangerous, token))
        {
            working = RemoveDangerousPlatformKeys(working, token);
            changed = true;
        }

        working = EnsureUsablePlatformKey(working, token, out bool platformKeyChanged);
        changed |= platformKeyChanged;

        BiosImage afterPlatformKeyRepair = ValidateSourceImage(working, token);
        if (ManagedCertificateStoresRequireUpdate(working, afterPlatformKeyRepair, token))
        {
            working = UpdateCertificateStores(working, token);
            changed = true;
        }

        if (!changed)
        {
            throw new InvalidDataException(OperationError.CertificatesCurrent);
        }

        BiosImage verified = ValidateSourceImage(working, token);
        VerifyManagedSecureBootState(working, verified, token);
        return working;
    }

    private static byte[] UpdateCertificateStores(ReadOnlySpan<byte> source, CancellationToken token)
    {
        byte[] working = source.ToArray();
        BiosImage sourceImage = ValidateSourceImage(working, token);
        SecureBootStorePair[] pairs = FindCertificateStorePairs(working, sourceImage, token);
        int[] volumeStarts = pairs
            .Select(pair => pair.VolumeStart)
            .OrderBy(offset => offset)
            .ToArray();

        bool changed = false;
        foreach (int volumeStart in volumeStarts)
        {
            working = UpdateCertificateStoreVolume(working, volumeStart, token, out bool volumeChanged);
            changed |= volumeChanged;
        }

        if (!changed)
        {
            // The managed AMI KEK/db stores were selected structurally, but none required a rewrite.
            // Do not guess at an unrelated certificate container.
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        return working;
    }

    private static byte[] UpdateCertificateStoreVolume(
        ReadOnlySpan<byte> source,
        int volumeStart,
        CancellationToken token,
        out bool changed)
    {
        BiosImage sourceImage = ValidateSourceImage(source, token);
        SecureBootStorePair[] matches = FindCertificateStorePairs(source, sourceImage, token)
            .Where(pair => pair.VolumeStart == volumeStart)
            .ToArray();
        if (matches.Length != 1)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        SecureBootStorePair pair = matches[0];
        FfsFileLocation kek = pair.Kek;
        FfsFileLocation db = pair.Db;
        if (kek.HeaderSize != AmiSecureBootSpecification.FfsFileHeaderBytes ||
            db.HeaderSize != AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        int volumeEnd = kek.VolumeEnd;
        int first = Math.Min(kek.Offset, db.Offset);
        List<FfsFile> files = ReadFiles(source, volumeStart, first, volumeEnd, token, out int oldEnd);
        if (!files.Any(file => file.Offset == kek.Offset && file.Guid == AmiSecureBootSpecification.KekFile) ||
            !files.Any(file => file.Offset == db.Offset && file.Guid == AmiSecureBootSpecification.DbFile))
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        SecureBootReport existing = sourceImage.SecureBoot;
        SecureBootReport kekBefore = InspectSecureBootFile(source, kek, token);
        SecureBootReport dbBefore = InspectSecureBootFile(source, db, token);
        SecureBootMutationPolicy.EnsureCanModify(kekBefore);
        SecureBootMutationPolicy.EnsureCanModify(dbBefore);

        IReadOnlyList<BundledCertificate> wanted = SecureBootInspector.Catalog;
        BundledCertificate[] wantedKek = wanted
            .Where(certificate => certificate.Role == SecureBootCertificateRoles.Kek)
            .ToArray();
        BundledCertificate[] wantedDb = wanted
            .Where(certificate => certificate.Role == SecureBootCertificateRoles.Db)
            .ToArray();
        HashSet<string> removeKek = UnsafeCertificateHashes(kekBefore);
        HashSet<string> removeDb = UnsafeCertificateHashes(dbBefore);
        bool updateKek = HasMissingCertificates(kekBefore, wantedKek) || removeKek.Count > 0;
        bool updateDb = HasMissingCertificates(dbBefore, wantedDb) || removeDb.Count > 0;
        if (!updateKek && !updateDb)
        {
            changed = false;
            return source.ToArray();
        }

        for (int index = 0; index < files.Count; index++)
        {
            FfsFile file = files[index];
            byte[]? replacement = file.Offset switch
            {
                var offset when updateKek && offset == kek.Offset => RewriteCertificateSet(
                    source.Slice(file.Offset, file.Size).ToArray(), wantedKek, removeKek, token),
                var offset when updateDb && offset == db.Offset => RewriteCertificateSet(
                    source.Slice(file.Offset, file.Size).ToArray(), wantedDb, removeDb, token),
                _ => null
            };
            if (replacement is not null)
            {
                files[index] = file with { Replacement = replacement };
            }
        }

        byte[] result = RebuildFiles(source, volumeStart, first, volumeEnd, oldEnd, files);
        VerifyUpdatedImage(
            result,
            volumeStart,
            existing,
            kekBefore,
            dbBefore,
            wantedKek,
            wantedDb,
            removeKek,
            removeDb,
            token);
        changed = true;
        return result;
    }

    internal static byte[] RemoveTestKeys(ReadOnlySpan<byte> source, CancellationToken token = default) =>
        RemovePlatformKeyCertificates(source, PlatformKeyRemovalMode.TestOnly, token);

    private static byte[] RemoveDangerousPlatformKeys(
        ReadOnlySpan<byte> source,
        CancellationToken token = default) =>
        RemovePlatformKeyCertificates(source, PlatformKeyRemovalMode.Dangerous, token);

    private static byte[] RemovePlatformKeyCertificates(
        ReadOnlySpan<byte> source,
        PlatformKeyRemovalMode mode,
        CancellationToken token)
    {
        BiosImage sourceImage = ValidateSourceImage(source, token);
        SecureBootReport existing = sourceImage.SecureBoot;
        if (!HasManagedPlatformKeyMatching(source, sourceImage, mode, token))
        {
            throw new InvalidDataException(mode == PlatformKeyRemovalMode.TestOnly
                ? OperationError.TestKeyNotFound
                : OperationError.CertificateVerification);
        }

        FfsFileLocation[] pkFiles = FindFiles(
            source,
            sourceImage,
            AmiSecureBootSpecification.PlatformKeyFile,
            token);
        if (pkFiles.Length == 0 ||
            pkFiles.GroupBy(file => file.VolumeStart).Any(group => group.Count() != 1))
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        var targetVolumes = new List<int>();
        var allRemovedHashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (FfsFileLocation pk in pkFiles)
        {
            token.ThrowIfCancellationRequested();
            SecureBootReport pkReport = InspectSecureBootFile(source, pk, token);
            SecureBootMutationPolicy.EnsureCanModify(pkReport);
            HashSet<string> matches = MatchingCertificateHashes(pkReport, mode);
            if (matches.Count == 0)
            {
                continue;
            }

            if (pk.HeaderSize != AmiSecureBootSpecification.FfsFileHeaderBytes)
            {
                throw new InvalidDataException(PlatformKeyRemovalUnsupportedError(mode));
            }
            targetVolumes.Add(pk.VolumeStart);
            allRemovedHashes.UnionWith(matches);
        }

        if (targetVolumes.Count == 0)
        {
            throw new InvalidDataException(PlatformKeyRemovalUnsupportedError(mode));
        }

        byte[] working = source.ToArray();
        foreach (int volumeStart in targetVolumes.OrderBy(offset => offset))
        {
            working = RemovePlatformKeyCertificatesFromVolume(working, volumeStart, mode, token);
        }

        BiosImage finalImage = ValidateSourceImage(working, token);
        SecureBootReport finalReport = finalImage.SecureBoot;
        if (CanUseGlobalCertificateCrossCheck(existing, finalReport) &&
            HasMissingExistingCertificates(finalReport, existing, excludedHashes: allRemovedHashes))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }
        if (HasManagedPlatformKeyMatching(working, finalImage, mode, token))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }

        return working;
    }

    private static byte[] RemovePlatformKeyCertificatesFromVolume(
        ReadOnlySpan<byte> source,
        int volumeStart,
        PlatformKeyRemovalMode mode,
        CancellationToken token)
    {
        BiosImage sourceImage = ValidateSourceImage(source, token);
        SecureBootReport existing = sourceImage.SecureBoot;
        FfsFileLocation pk = FindFileInVolume(
            source,
            sourceImage,
            AmiSecureBootSpecification.PlatformKeyFile,
            volumeStart,
            token);
        if (pk.HeaderSize != AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            throw new InvalidDataException(PlatformKeyRemovalUnsupportedError(mode));
        }

        SecureBootReport pkBefore = InspectSecureBootFile(source, pk, token);
        SecureBootMutationPolicy.EnsureCanModify(pkBefore);
        HashSet<string> removeHashes = MatchingCertificateHashes(pkBefore, mode);
        if (removeHashes.Count == 0)
        {
            throw new InvalidDataException(PlatformKeyRemovalUnsupportedError(mode));
        }

        List<FfsFile> files = ReadFiles(source, volumeStart, pk.Offset, pk.VolumeEnd, token, out int oldEnd);
        int targetIndex = files.FindIndex(file =>
            file.Offset == pk.Offset && file.Guid == AmiSecureBootSpecification.PlatformKeyFile);
        if (targetIndex < 0)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        FfsFile target = files[targetIndex];
        (byte[] rewrittenFile, int removed) = RewriteRemovingCertificates(
            source.Slice(target.Offset, target.Size).ToArray(),
            removeHashes,
            token);
        if (removed == 0)
        {
            throw new InvalidDataException(PlatformKeyRemovalUnsupportedError(mode));
        }
        files[targetIndex] = target with { Replacement = rewrittenFile };

        byte[] result = RebuildFiles(source, volumeStart, pk.Offset, pk.VolumeEnd, oldEnd, files);
        BiosImage parsed = ValidateSourceImage(result, token);
        SecureBootReport verified = parsed.SecureBoot;
        FfsFileLocation verifiedPk = FindFileInVolume(
            result,
            parsed,
            AmiSecureBootSpecification.PlatformKeyFile,
            volumeStart,
            token);
        SecureBootReport pkAfter = InspectSecureBootFile(result, verifiedPk, token);
        SecureBootMutationPolicy.EnsureCanModify(pkAfter);
        if (pkAfter.Certificates.Any(certificate => MatchesRemovalMode(certificate, mode)) ||
            (CanUseGlobalCertificateCrossCheck(existing, verified) &&
                HasMissingExistingCertificates(verified, existing, excludedHashes: removeHashes)) ||
            HasMissingExistingCertificates(pkAfter, pkBefore, excludedHashes: removeHashes))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }

        return result;
    }

    private static HashSet<string> MatchingCertificateHashes(
        SecureBootReport report,
        PlatformKeyRemovalMode mode) =>
        report.Certificates
            .Where(certificate => MatchesRemovalMode(certificate, mode))
            .Select(certificate => certificate.Sha256)
            .ToHashSet(StringComparer.Ordinal);

    private static bool MatchesRemovalMode(FirmwareCertificate certificate, PlatformKeyRemovalMode mode) =>
        mode == PlatformKeyRemovalMode.TestOnly ? certificate.TestKey : certificate.Dangerous;

    private static string PlatformKeyRemovalUnsupportedError(PlatformKeyRemovalMode mode) =>
        mode == PlatformKeyRemovalMode.TestOnly
            ? OperationError.TestKeyRemovalUnsupported
            : OperationError.UnsafePlatformKeyRemovalUnsupported;

    private static async Task<byte[]> ReadSourceImageAsync(string source, CancellationToken token)
    {
        string fullSource = Path.GetFullPath(source);
        await using var input = new FileStream(
            fullSource,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            UefiFirmwareSpecification.FileIoBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length is < BiosImageLoader.MinBiosImageBytes or > BiosImageLoader.MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }

        byte[] image = new byte[checked((int)input.Length)];
        await input.ReadExactlyAsync(image, token);
        return image;
    }

    private static async Task WriteNewImageAsync(string destination, byte[] image, CancellationToken token)
    {
        string fullDestination = Path.GetFullPath(destination);
        string partial = fullDestination + "." + Guid.NewGuid().ToString("N") + ".partial";
        byte[] expectedHash = SHA256.HashData(image);
        Exception? operationError = null;
        try
        {
            await using (var output = new FileStream(
                partial,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                SecureBootRepairPolicy.FileWriteBufferBytes,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(image, token);
                await output.FlushAsync(token);
                output.Flush(flushToDisk: true);
            }

            await using (var verification = new FileStream(
                partial,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                SecureBootRepairPolicy.FileWriteBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                byte[] actualHash = await SHA256.HashDataAsync(verification, token);
                if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
                {
                    throw new IOException(OperationError.OutputVerification);
                }
            }

            token.ThrowIfCancellationRequested();
            File.Move(partial, fullDestination, overwrite: false);
        }
        catch (Exception error)
        {
            operationError = error;
            throw;
        }
        finally
        {
            if (!FileSystemCleanup.TryDeleteFile(partial, out Exception? cleanupError) &&
                operationError is not null && cleanupError is not null)
            {
                FileSystemCleanup.AttachCleanupFailure(operationError, cleanupError);
            }
        }
    }

    private static BiosImage ValidateSourceImage(ReadOnlySpan<byte> image, CancellationToken token)
    {
        if (image.Length is < BiosImageLoader.MinBiosImageBytes or > BiosImageLoader.MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }

        BiosImage parsed = BiosImageLoader.Analyze(image, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(parsed);
        return parsed;
    }

    private static void VerifyUpdatedImage(
        ReadOnlySpan<byte> result,
        int volumeStart,
        SecureBootReport existing,
        SecureBootReport kekBefore,
        SecureBootReport dbBefore,
        IReadOnlyList<BundledCertificate> wantedKek,
        IReadOnlyList<BundledCertificate> wantedDb,
        HashSet<string> removedKek,
        HashSet<string> removedDb,
        CancellationToken token)
    {
        BiosImage parsed = ValidateSourceImage(result, token);
        SecureBootReport verified = parsed.SecureBoot;
        FfsFileLocation kek = FindFileInVolume(
            result,
            parsed,
            AmiSecureBootSpecification.KekFile,
            volumeStart,
            token);
        FfsFileLocation db = FindFileInVolume(
            result,
            parsed,
            AmiSecureBootSpecification.DbFile,
            volumeStart,
            token);
        SecureBootReport kekAfter = InspectSecureBootFile(result, kek, token);
        SecureBootReport dbAfter = InspectSecureBootFile(result, db, token);
        SecureBootMutationPolicy.EnsureCanModify(kekAfter);
        SecureBootMutationPolicy.EnsureCanModify(dbAfter);

        HashSet<string> removed = removedKek
            .Concat(removedDb)
            .ToHashSet(StringComparer.Ordinal);
        if (HasMissingCertificates(kekAfter, wantedKek) ||
            HasMissingCertificates(dbAfter, wantedDb) ||
            HasMissingExistingCertificates(kekAfter, kekBefore, excludedHashes: removedKek) ||
            HasMissingExistingCertificates(dbAfter, dbBefore, excludedHashes: removedDb) ||
            (CanUseGlobalCertificateCrossCheck(existing, verified) &&
                HasMissingExistingCertificates(verified, existing, excludedHashes: removed)) ||
            kekAfter.Certificates.Any(certificate => removedKek.Contains(certificate.Sha256)) ||
            dbAfter.Certificates.Any(certificate => removedDb.Contains(certificate.Sha256)))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }
    }

    private static bool HasManagedPlatformKeyMatching(
        ReadOnlySpan<byte> source,
        BiosImage image,
        PlatformKeyRemovalMode mode,
        CancellationToken token)
    {
        FfsFileLocation[] platformKeys = FindFiles(
            source,
            image,
            AmiSecureBootSpecification.PlatformKeyFile,
            token);
        foreach (FfsFileLocation platformKey in platformKeys)
        {
            SecureBootReport report = InspectSecureBootFile(source, platformKey, token);
            SecureBootMutationPolicy.EnsureCanModify(report);
            if (report.Certificates.Any(certificate => MatchesRemovalMode(certificate, mode)))
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] EnsureUsablePlatformKey(
        ReadOnlySpan<byte> source,
        CancellationToken token,
        out bool changed)
    {
        BiosImage image = ValidateSourceImage(source, token);
        FfsFileLocation[] platformKeys = FindFiles(
            source,
            image,
            AmiSecureBootSpecification.PlatformKeyFile,
            token);
        if (platformKeys.Length == 0 ||
            platformKeys.GroupBy(file => file.VolumeStart).Any(group => group.Count() != 1))
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        var emptyVolumes = new List<int>();
        foreach (FfsFileLocation platformKey in platformKeys)
        {
            SecureBootReport report = InspectSecureBootFile(source, platformKey, token);
            SecureBootMutationPolicy.EnsureCanModify(report);
            if (report.HasDangerousCertificate)
            {
                throw new InvalidDataException(OperationError.CertificateVerification);
            }

            if (report.Certificates.Count == 0)
            {
                emptyVolumes.Add(platformKey.VolumeStart);
                continue;
            }

            if (report.Certificates.Any(certificate => !IsUsablePlatformKey(certificate)))
            {
                throw new InvalidDataException(OperationError.CertificateVerification);
            }
        }

        emptyVolumes.Sort();
        if (emptyVolumes.Count == 0)
        {
            changed = false;
            return source.ToArray();
        }

        byte[] ownerCertificate = CreatePlatformKeyCertificate();
        byte[] working = source.ToArray();
        foreach (int volumeStart in emptyVolumes)
        {
            working = AddPlatformKeyToVolume(working, volumeStart, ownerCertificate, token);
        }

        changed = true;
        return working;
    }

    private static byte[] AddPlatformKeyToVolume(
        ReadOnlySpan<byte> source,
        int volumeStart,
        byte[] ownerCertificate,
        CancellationToken token)
    {
        BiosImage image = ValidateSourceImage(source, token);
        FfsFileLocation platformKey = FindFileInVolume(
            source,
            image,
            AmiSecureBootSpecification.PlatformKeyFile,
            volumeStart,
            token);
        if (platformKey.HeaderSize != AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        SecureBootReport before = InspectSecureBootFile(source, platformKey, token);
        SecureBootMutationPolicy.EnsureCanModify(before);
        if (before.Certificates.Count != 0)
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }

        List<FfsFile> files = ReadFiles(
            source,
            volumeStart,
            platformKey.Offset,
            platformKey.VolumeEnd,
            token,
            out int oldEnd);
        int targetIndex = files.FindIndex(file =>
            file.Offset == platformKey.Offset && file.Guid == AmiSecureBootSpecification.PlatformKeyFile);
        if (targetIndex < 0)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        FfsFile target = files[targetIndex];
        byte[] replacement = RewriteCompressedFile(
            source.Slice(target.Offset, target.Size).ToArray(),
            raw =>
            {
                SecureBootReport rawReport = SecureBootInspector.Inspect(raw, token);
                SecureBootMutationPolicy.EnsureCanModify(rawReport);
                if (rawReport.Certificates.Count != 0)
                {
                    throw new InvalidDataException(OperationError.CertificateVerification);
                }

                using var expanded = new MemoryStream(
                    checked(raw.Length + ownerCertificate.Length +
                        EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes +
                        EfiSignatureDatabaseSpecification.SignatureOwnerBytes));
                expanded.Write(raw);
                expanded.Write(BuildSignatureList(ownerCertificate, s_applicationOwner));
                return expanded.ToArray();
            },
            token);
        files[targetIndex] = target with { Replacement = replacement };

        byte[] result = RebuildFiles(
            source,
            volumeStart,
            platformKey.Offset,
            platformKey.VolumeEnd,
            oldEnd,
            files);
        BiosImage verifiedImage = ValidateSourceImage(result, token);
        FfsFileLocation verifiedPlatformKey = FindFileInVolume(
            result,
            verifiedImage,
            AmiSecureBootSpecification.PlatformKeyFile,
            volumeStart,
            token);
        SecureBootReport verified = InspectSecureBootFile(result, verifiedPlatformKey, token);
        string expectedHash = Convert.ToHexString(SHA256.HashData(ownerCertificate));
        if (verified.HasDangerousCertificate ||
            verified.Certificates.Count != 1 ||
            !verified.Certificates.Any(certificate =>
                certificate.Sha256 == expectedHash && IsUsablePlatformKey(certificate)))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }

        return result;
    }

    private static byte[] CreatePlatformKeyCertificate()
    {
        using RSA key = RSA.Create(SecureBootRepairPolicy.PlatformKeyRsaBits);
        var request = new CertificateRequest(
            SecureBootRepairPolicy.PlatformKeySubject,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            SecureBootRepairPolicy.PlatformKeyNotBeforeUtc,
            SecureBootRepairPolicy.PlatformKeyNotAfterUtc);
        // Only the public DER certificate is embedded in firmware. The ephemeral private key is disposed here and is never persisted.
        return certificate.Export(X509ContentType.Cert);
    }

    private static bool IsUsablePlatformKey(FirmwareCertificate certificate) =>
        !certificate.Dangerous &&
        certificate.StrongPublicKey &&
        certificate.SignatureAlgorithmStatus == CertificateSignatureAlgorithmStatus.Strong &&
        certificate.SignatureStatus != CertificateSignatureStatus.Invalid;

    private static bool ManagedCertificateStoresRequireUpdate(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token)
    {
        IReadOnlyList<BundledCertificate> catalog = SecureBootInspector.Catalog;
        BundledCertificate[] wantedKek = catalog
            .Where(certificate => certificate.Role == SecureBootCertificateRoles.Kek)
            .ToArray();
        BundledCertificate[] wantedDb = catalog
            .Where(certificate => certificate.Role == SecureBootCertificateRoles.Db)
            .ToArray();

        foreach (SecureBootStorePair pair in FindCertificateStorePairs(source, image, token))
        {
            SecureBootReport kek = InspectSecureBootFile(source, pair.Kek, token);
            SecureBootReport db = InspectSecureBootFile(source, pair.Db, token);
            SecureBootMutationPolicy.EnsureCanModify(kek);
            SecureBootMutationPolicy.EnsureCanModify(db);
            if (kek.HasLegacy || db.HasLegacy || kek.HasDangerousCertificate || db.HasDangerousCertificate ||
                HasMissingCertificates(kek, wantedKek) || HasMissingCertificates(db, wantedDb))
            {
                return true;
            }
        }

        return false;
    }

    private static void VerifyManagedSecureBootState(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token)
    {
        if (HasManagedPlatformKeyMatching(source, image, PlatformKeyRemovalMode.Dangerous, token))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }

        FfsFileLocation[] platformKeys = FindFiles(
            source,
            image,
            AmiSecureBootSpecification.PlatformKeyFile,
            token);
        if (platformKeys.Length == 0 ||
            platformKeys.GroupBy(file => file.VolumeStart).Any(group => group.Count() != 1))
        {
            throw new InvalidDataException(OperationError.CertificateVerification);
        }
        foreach (FfsFileLocation platformKey in platformKeys)
        {
            SecureBootReport report = InspectSecureBootFile(source, platformKey, token);
            SecureBootMutationPolicy.EnsureCanModify(report);
            if (report.Certificates.Count == 0 ||
                report.Certificates.Any(certificate => !IsUsablePlatformKey(certificate)))
            {
                throw new InvalidDataException(OperationError.CertificateVerification);
            }
        }

        IReadOnlyList<BundledCertificate> catalog = SecureBootInspector.Catalog;
        BundledCertificate[] wantedKek = catalog
            .Where(certificate => certificate.Role == SecureBootCertificateRoles.Kek)
            .ToArray();
        BundledCertificate[] wantedDb = catalog
            .Where(certificate => certificate.Role == SecureBootCertificateRoles.Db)
            .ToArray();

        foreach (SecureBootStorePair pair in FindCertificateStorePairs(source, image, token))
        {
            SecureBootReport kek = InspectSecureBootFile(source, pair.Kek, token);
            SecureBootReport db = InspectSecureBootFile(source, pair.Db, token);
            SecureBootMutationPolicy.EnsureCanModify(kek);
            SecureBootMutationPolicy.EnsureCanModify(db);
            if (kek.HasLegacy || db.HasLegacy || kek.HasDangerousCertificate || db.HasDangerousCertificate ||
                HasMissingCertificates(kek, wantedKek) || HasMissingCertificates(db, wantedDb))
            {
                throw new InvalidDataException(OperationError.CertificateVerification);
            }
        }
    }

    private static bool CanUseGlobalCertificateCrossCheck(SecureBootReport before, SecureBootReport after) =>
        !before.Incomplete && !after.Incomplete &&
        !before.HasCertificateIntegrityFailure && !after.HasCertificateIntegrityFailure;

    private static SecureBootReport InspectSecureBootFile(
        ReadOnlySpan<byte> source,
        FfsFileLocation file,
        CancellationToken token) =>
        SecureBootInspector.Inspect(source.Slice(file.Offset, file.Size), token);

    private static bool HasMissingCertificates(
        SecureBootReport report,
        IReadOnlyList<BundledCertificate> expected) =>
        expected.Any(certificate => !report.Certificates.Any(current => current.Sha256 == certificate.Sha256));

    private static bool HasMissingExistingCertificates(
        SecureBootReport report,
        SecureBootReport baseline,
        bool excludeTestKeys = false,
        IReadOnlySet<string>? excludedHashes = null) =>
        baseline.Certificates
            .Where(certificate => (!excludeTestKeys || !certificate.TestKey) &&
                (excludedHashes is null || !excludedHashes.Contains(certificate.Sha256)))
            .Any(certificate => !report.Certificates.Any(current => current.Sha256 == certificate.Sha256));

    private static HashSet<string> UnsafeCertificateHashes(SecureBootReport report) =>
        report.Certificates
            .Where(certificate => certificate.Dangerous ||
                (certificate.OfficialMicrosoft && !certificate.Modern))
            .Select(certificate => certificate.Sha256)
            .ToHashSet(StringComparer.Ordinal);

    private static byte[] RewriteCertificateSet(
        byte[] file,
        IEnumerable<BundledCertificate> requested,
        HashSet<string> removeHashes,
        CancellationToken token)
    {
        return RewriteCompressedFile(file, raw =>
        {
            SecureBootReport before = SecureBootInspector.Inspect(raw, token);
            SecureBootMutationPolicy.EnsureCanModify(before);
            byte[] sanitized = removeHashes.Count == 0
                ? raw
                : RemoveSignatureEntries(raw, removeHashes, token, out _);
            SecureBootReport sanitizedReport = SecureBootInspector.Inspect(sanitized, token);
            SecureBootMutationPolicy.EnsureCanModify(sanitizedReport);

            using var expanded = new MemoryStream(checked(sanitized.Length + SecureBootRepairPolicy.CertificateGrowthCapacityHintBytes));
            expanded.Write(sanitized);
            foreach (BundledCertificate item in requested)
            {
                if (sanitizedReport.Certificates.Any(certificate => certificate.Sha256 == item.Sha256))
                {
                    continue;
                }
                byte[] certificate = SecureBootInspector.CertificateBytes(item);
                expanded.Write(BuildSignatureList(certificate));
            }

            return expanded.ToArray();
        }, token);
    }

    private static (byte[] Bytes, int Removed) RewriteRemovingCertificates(
        byte[] file,
        HashSet<string> hashes,
        CancellationToken token)
    {
        int removed = 0;
        byte[] rewritten = RewriteCompressedFile(file, raw => RemoveSignatureEntries(raw, hashes, token, out removed), token);
        return (rewritten, removed);
    }

    private static byte[] RewriteCompressedFile(byte[] file, Func<byte[], byte[]> transform, CancellationToken token)
    {
        int sectionStart = AmiSecureBootSpecification.FfsFileHeaderBytes;
        if (file.Length < sectionStart + AmiSecureBootSpecification.GuidedSectionHeaderBytes ||
            file[sectionStart + AmiSecureBootSpecification.SectionTypeOffset] != AmiSecureBootSpecification.GuidedSectionType ||
            !file.AsSpan(
                    sectionStart + AmiSecureBootSpecification.GuidedSectionDefinitionOffset,
                    AmiSecureBootSpecification.GuidedSectionDefinitionBytes)
                .SequenceEqual(LzmaSection))
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        int sectionSize = ReadU24(file, sectionStart);
        int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            file.AsSpan(sectionStart + AmiSecureBootSpecification.GuidedSectionDataOffsetOffset));
        if (sectionSize != file.Length - sectionStart ||
            dataOffset < AmiSecureBootSpecification.GuidedSectionHeaderBytes ||
            dataOffset > sectionSize - AmiSecureBootSpecification.LzmaHeaderBytes)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        ReadOnlySpan<byte> packed = file.AsSpan(sectionStart + dataOffset, sectionSize - dataOffset);
        long outputLength = BinaryPrimitives.ReadInt64LittleEndian(
            packed[AmiSecureBootSpecification.LzmaUncompressedSizeOffset..]);
        uint dictionarySize = BinaryPrimitives.ReadUInt32LittleEndian(
            packed[AmiSecureBootSpecification.LzmaDictionarySizeOffset..]);
        if (packed[0] > AmiSecureBootSpecification.MaximumValidLzmaPropertiesByte ||
            dictionarySize > SecureBootInspectionPolicy.MaximumExpandedSectionBytes ||
            outputLength < AmiSecureBootSpecification.SectionHeaderBytes ||
            outputLength > SecureBootRepairPolicy.MaximumEditableRawSectionBytes)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        byte[] raw = new byte[checked((int)outputLength)];
        try
        {
            using var input = new MemoryStream(
                packed[AmiSecureBootSpecification.LzmaHeaderBytes..].ToArray(),
                writable: false);
            using var decoder = LzmaStream.Create(
                packed[..AmiSecureBootSpecification.LzmaPropertiesBytes].ToArray(),
                input,
                input.Length,
                outputLength);
            ReadExactly(decoder, raw, token);
        }
        catch (Exception error) when (FirmwareCompressionFailure.IsMalformedInput(error))
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout, error);
        }

        if (raw[AmiSecureBootSpecification.SectionTypeOffset] != AmiSecureBootSpecification.RawSectionType ||
            ReadU24(raw, 0) != raw.Length)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        byte[] newRaw = transform(raw);
        if (newRaw.Length < AmiSecureBootSpecification.SectionHeaderBytes ||
            newRaw[AmiSecureBootSpecification.SectionTypeOffset] != AmiSecureBootSpecification.RawSectionType ||
            newRaw.Length > SecureBootRepairPolicy.MaximumEditableRawSectionBytes ||
            newRaw.Length > AmiSecureBootSpecification.MaximumNormalU24Size)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        WriteU24(newRaw, 0, newRaw.Length);

        token.ThrowIfCancellationRequested();
        using var compressed = new MemoryStream();
        byte[] properties;
        using (var encoder = LzmaStream.Create(
                   new LzmaEncoderProperties(false, SecureBootRepairPolicy.LzmaDictionaryBytes),
                   false,
                   compressed))
        {
            properties = encoder.Properties.ToArray();
            encoder.Write(newRaw);
        }
        token.ThrowIfCancellationRequested();

        byte[] compressedBytes = compressed.ToArray();
        int newSectionSize = checked(dataOffset + AmiSecureBootSpecification.LzmaHeaderBytes + compressedBytes.Length);
        int newFileSize = checked(AmiSecureBootSpecification.FfsFileHeaderBytes + newSectionSize);
        if (newSectionSize > AmiSecureBootSpecification.MaximumNormalU24Size ||
            newFileSize > AmiSecureBootSpecification.MaximumNormalFfsFileBytes)
        {
            throw new InvalidDataException(OperationError.SecureBootSpace);
        }

        byte[] result = new byte[newFileSize];
        file.AsSpan(0, AmiSecureBootSpecification.FfsFileHeaderBytes).CopyTo(result);
        file.AsSpan(sectionStart, dataOffset).CopyTo(result.AsSpan(sectionStart));
        WriteU24(result, sectionStart, newSectionSize);
        properties.CopyTo(result, sectionStart + dataOffset);
        BinaryPrimitives.WriteInt64LittleEndian(
            result.AsSpan(sectionStart + dataOffset + AmiSecureBootSpecification.LzmaUncompressedSizeOffset),
            newRaw.Length);
        compressedBytes.CopyTo(result, sectionStart + dataOffset + AmiSecureBootSpecification.LzmaHeaderBytes);
        WriteU24(result, AmiSecureBootSpecification.FfsSizeOffset, newFileSize);
        FixFfsChecksum(result);
        return result;
    }

    private static byte[] RemoveSignatureEntries(
        ReadOnlySpan<byte> raw,
        HashSet<string> hashes,
        CancellationToken token,
        out int removed)
    {
        removed = 0;
        using var output = new MemoryStream(raw.Length);
        int copyFrom = 0;
        int scan = 0;
        int certificateEntries = 0;

        while (scan <= raw.Length - EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes)
        {
            int relative = raw[scan..].IndexOf(X509Type);
            if (relative < 0)
            {
                break;
            }
            int start = scan + relative;
            if (raw.Length - start < EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes)
            {
                break;
            }

            uint listSize = BinaryPrimitives.ReadUInt32LittleEndian(
                raw[(start + EfiSignatureDatabaseSpecification.SignatureListSizeOffset)..]);
            uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(
                raw[(start + EfiSignatureDatabaseSpecification.SignatureHeaderSizeOffset)..]);
            uint signatureSize = BinaryPrimitives.ReadUInt32LittleEndian(
                raw[(start + EfiSignatureDatabaseSpecification.SignatureSizeOffset)..]);
            if (!EfiSignatureListValidation.IsValidX509List(raw.Length - start, listSize, headerSize, signatureSize))
            {
                scan = start + EfiSignatureDatabaseSpecification.SignatureOwnerBytes;
                continue;
            }

            int entriesStart = start + EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes + checked((int)headerSize);
            int listEnd = start + checked((int)listSize);
            int entrySize = checked((int)signatureSize);
            int removedHere = 0;
            for (int offset = entriesStart; offset < listEnd; offset += entrySize)
            {
                token.ThrowIfCancellationRequested();
                if (++certificateEntries > SecureBootInspectionPolicy.MaximumCertificateEntries)
                {
                    throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
                }

                ReadOnlySpan<byte> certificate = raw.Slice(
                    offset + EfiSignatureDatabaseSpecification.SignatureOwnerBytes,
                    entrySize - EfiSignatureDatabaseSpecification.SignatureOwnerBytes);
                if (hashes.Contains(Convert.ToHexString(SHA256.HashData(certificate))))
                {
                    removedHere++;
                }
            }

            if (removedHere == 0)
            {
                scan = listEnd;
                continue;
            }

            output.Write(raw[copyFrom..start]);
            int totalEntries = (listEnd - entriesStart) / entrySize;
            int keptEntries = totalEntries - removedHere;
            if (keptEntries > 0)
            {
                int fixedPrefix = EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes + checked((int)headerSize);
                byte[] header = raw.Slice(start, fixedPrefix).ToArray();
                int newListSize = checked(fixedPrefix + keptEntries * entrySize);
                BinaryPrimitives.WriteUInt32LittleEndian(
                    header.AsSpan(EfiSignatureDatabaseSpecification.SignatureListSizeOffset),
                    checked((uint)newListSize));
                output.Write(header);
                for (int offset = entriesStart; offset < listEnd; offset += entrySize)
                {
                    token.ThrowIfCancellationRequested();
                    ReadOnlySpan<byte> certificate = raw.Slice(
                        offset + EfiSignatureDatabaseSpecification.SignatureOwnerBytes,
                        entrySize - EfiSignatureDatabaseSpecification.SignatureOwnerBytes);
                    if (!hashes.Contains(Convert.ToHexString(SHA256.HashData(certificate))))
                    {
                        output.Write(raw.Slice(offset, entrySize));
                    }
                }
            }

            removed += removedHere;
            copyFrom = listEnd;
            scan = listEnd;
        }

        if (removed == 0)
        {
            return raw.ToArray();
        }
        output.Write(raw[copyFrom..]);
        return output.ToArray();
    }

    private static byte[] RebuildFiles(
        ReadOnlySpan<byte> source,
        int volumeStart,
        int first,
        int volumeEnd,
        int oldEnd,
        IReadOnlyList<FfsFile> files)
    {
        byte eraseByte = GetVolumeEraseByte(source, volumeStart);
        FfsPlacement[] placements = BuildRepackPlan(files, volumeStart, first, eraseByte);
        int newEnd = placements.Length == 0
            ? first
            : AlignFfsFile(volumeStart, checked(placements[^1].Offset + placements[^1].Size));

        int freeEnd = oldEnd;
        while (freeEnd < volumeEnd && source[freeEnd] == eraseByte)
        {
            freeEnd++;
        }
        if (newEnd > freeEnd)
        {
            throw new InvalidDataException(OperationError.SecureBootSpace);
        }

        byte[] result = source.ToArray();
        result.AsSpan(first, Math.Max(oldEnd, newEnd) - first).Fill(eraseByte);
        foreach (FfsPlacement placement in placements)
        {
            ReadOnlySpan<byte> bytes = placement.File.Replacement is null
                ? source.Slice(placement.File.Offset, placement.File.Size)
                : placement.File.Replacement;
            bytes.CopyTo(result.AsSpan(placement.Offset));
        }

        return result;
    }

    private static FfsPlacement[] BuildRepackPlan(
        IReadOnlyList<FfsFile> files,
        int volumeStart,
        int first,
        byte eraseByte)
    {
        var placements = new FfsPlacement[files.Count];
        int cursor = first;
        for (int index = 0; index < files.Count; index++)
        {
            FfsFile file = files[index];
            int size = ValidateReplacementAndGetSize(file, eraseByte);
            ValidateFfsPlacement(file, volumeStart, cursor);
            placements[index] = new(file, cursor, size);
            cursor = AlignFfsFile(volumeStart, checked(cursor + size));
        }
        return placements;
    }

    private static int ValidateReplacementAndGetSize(FfsFile file, byte eraseByte)
    {
        if (file.Replacement is null)
        {
            return file.Size;
        }
        if (!UefiFfsFileParser.TryRead(
                file.Replacement,
                0,
                file.Replacement.Length,
                eraseByte,
                out FfsFileHeaderInfo replacement) ||
            replacement.Guid != file.Guid ||
            replacement.Size != file.Replacement.Length ||
            replacement.HeaderSize != file.HeaderSize ||
            replacement.Attributes != file.Attributes ||
            replacement.State != FfsFileState.DataValid)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }
        return replacement.Size;
    }

    private static void ValidateFfsPlacement(FfsFile file, int volumeStart, int destinationOffset)
    {
        if (AmiSecureBootSpecification.IsFixed(file.Attributes) && destinationOffset != file.Offset)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        int requiredAlignment = AmiSecureBootSpecification.RequiredDataAlignment(file.Attributes);
        int relativeDataOffset = checked(destinationOffset - volumeStart + file.HeaderSize);
        if (relativeDataOffset < 0 || relativeDataOffset % requiredAlignment != 0)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }
    }

    private static byte[] BuildSignatureList(byte[] certificate) =>
        BuildSignatureList(certificate, MicrosoftOwner);

    private static byte[] BuildSignatureList(byte[] certificate, ReadOnlySpan<byte> owner)
    {
        if (owner.Length != EfiSignatureDatabaseSpecification.SignatureOwnerBytes)
        {
            throw new ArgumentException("Signature owner GUID must be 16 bytes.", nameof(owner));
        }

        int signatureSize = checked(EfiSignatureDatabaseSpecification.SignatureOwnerBytes + certificate.Length);
        int listSize = checked(EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes + signatureSize);
        byte[] result = new byte[listSize];
        X509Type.CopyTo(result, EfiSignatureDatabaseSpecification.SignatureTypeOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(
            result.AsSpan(EfiSignatureDatabaseSpecification.SignatureListSizeOffset),
            checked((uint)result.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(
            result.AsSpan(EfiSignatureDatabaseSpecification.SignatureSizeOffset),
            checked((uint)signatureSize));
        owner.CopyTo(result.AsSpan(EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes));
        certificate.CopyTo(
            result,
            EfiSignatureDatabaseSpecification.SignatureListFixedHeaderBytes +
            EfiSignatureDatabaseSpecification.SignatureOwnerBytes);
        return result;
    }

    private static SecureBootStorePair[] FindCertificateStorePairs(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token)
    {
        FfsFileLocation[] kekFiles = FindFiles(source, image, AmiSecureBootSpecification.KekFile, token);
        FfsFileLocation[] dbFiles = FindFiles(source, image, AmiSecureBootSpecification.DbFile, token);
        if (kekFiles.Length == 0 || dbFiles.Length == 0)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        int[] volumeStarts = kekFiles
            .Select(file => file.VolumeStart)
            .Concat(dbFiles.Select(file => file.VolumeStart))
            .Distinct()
            .OrderBy(offset => offset)
            .ToArray();
        var pairs = new List<SecureBootStorePair>(volumeStarts.Length);
        foreach (int volumeStart in volumeStarts)
        {
            FfsFileLocation[] keks = kekFiles.Where(file => file.VolumeStart == volumeStart).ToArray();
            FfsFileLocation[] dbs = dbFiles.Where(file => file.VolumeStart == volumeStart).ToArray();
            if (keks.Length != 1 || dbs.Length != 1 ||
                keks[0].VolumeEnd != dbs[0].VolumeEnd)
            {
                throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
            }
            pairs.Add(new SecureBootStorePair(keks[0], dbs[0]));
        }

        return pairs.ToArray();
    }

    private static FfsFileLocation FindFileInVolume(
        ReadOnlySpan<byte> source,
        BiosImage image,
        Guid guid,
        int volumeStart,
        CancellationToken token)
    {
        FfsFileLocation[] matches = FindFiles(source, image, guid, token)
            .Where(file => file.VolumeStart == volumeStart)
            .ToArray();
        return matches.Length == 1
            ? matches[0]
            : throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
    }

    private static FfsFileLocation[] FindFiles(
        ReadOnlySpan<byte> source,
        BiosImage image,
        Guid guid,
        CancellationToken token)
    {
        byte[] guidBytes = guid.ToByteArray();
        var matches = new List<FfsFileLocation>();
        foreach (FirmwareVolume volume in image.Volumes)
        {
            token.ThrowIfCancellationRequested();
            int volumeStart = checked((int)volume.Offset);
            int volumeLength = checked((int)volume.Length);
            int volumeEnd = checked(volumeStart + volumeLength);
            if (volumeStart < 0 || volumeEnd > source.Length ||
                source.Slice(volumeStart, volumeLength).IndexOf(guidBytes) < 0)
            {
                continue;
            }

            FfsVolumeLayout layout = GetFfsVolumeLayout(source, volume);
            int search = layout.FirstFileOffset;
            while (search <= layout.End - AmiSecureBootSpecification.FfsNameBytes)
            {
                token.ThrowIfCancellationRequested();
                int relative = source.Slice(search, layout.End - search).IndexOf(guidBytes);
                if (relative < 0)
                {
                    break;
                }

                int candidate = checked(search + relative);
                search = checked(candidate + AmiSecureBootSpecification.FfsNameBytes);
                if ((candidate - layout.Start) % AmiSecureBootSpecification.FfsAlignmentBytes != 0 ||
                    candidate > layout.End - AmiSecureBootSpecification.FfsFileHeaderBytes ||
                    !UefiFfsFileParser.TryRead(
                        source,
                        candidate,
                        layout.End,
                        layout.EraseByte,
                        out FfsFileHeaderInfo header) ||
                    header.Guid != guid)
                {
                    continue;
                }

                if (header.Type != AmiSecureBootSpecification.FfsFreeformFileType)
                {
                    throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
                }
                if (header.State == FfsFileState.Deleted)
                {
                    continue;
                }
                if (header.State != FfsFileState.DataValid)
                {
                    throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
                }

                matches.Add(new FfsFileLocation(
                    candidate,
                    header.Size,
                    header.HeaderSize,
                    layout.Start,
                    layout.End));
            }
        }

        return matches
            .Distinct()
            .OrderBy(file => file.Offset)
            .ToArray();
    }

    private static FfsVolumeLayout GetFfsVolumeLayout(ReadOnlySpan<byte> source, FirmwareVolume volume)
    {
        int start = checked((int)volume.Offset);
        int length = checked((int)volume.Length);
        int end = checked(start + length);
        if (start < 0 || length < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes || end > source.Length)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }

        int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
            source[(start + UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset)..]);
        int relativeFileStart = headerLength;
        int extendedHeaderOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            source[(start + UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderOffsetOffset)..]);
        if (extendedHeaderOffset != 0)
        {
            if (extendedHeaderOffset < headerLength ||
                extendedHeaderOffset > length - UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderMinimumBytes)
            {
                throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
            }

            uint extendedHeaderSize = BinaryPrimitives.ReadUInt32LittleEndian(
                source[(start + extendedHeaderOffset + UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderSizeOffset)..]);
            if (extendedHeaderSize < UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderMinimumBytes ||
                extendedHeaderSize > (uint)(length - extendedHeaderOffset))
            {
                throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
            }

            relativeFileStart = checked(extendedHeaderOffset + (int)extendedHeaderSize);
        }

        int firstFileOffset = AlignFfsFile(start, checked(start + relativeFileStart));
        if (firstFileOffset > end)
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }
        return new FfsVolumeLayout(start, end, firstFileOffset, GetVolumeEraseByte(source, start));
    }

    private static byte GetVolumeEraseByte(ReadOnlySpan<byte> source, int volumeStart)
    {
        uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(
            source[(volumeStart + UefiFirmwareSpecification.FirmwareVolumeAttributesOffset)..]);
        return (attributes & UefiFirmwareSpecification.FirmwareVolumeErasePolarityMask) != 0
            ? byte.MaxValue
            : byte.MinValue;
    }

    private static List<FfsFile> ReadFiles(
        ReadOnlySpan<byte> source,
        int volumeStart,
        int start,
        int limit,
        CancellationToken token,
        out int end)
    {
        var files = new List<FfsFile>();
        int cursor = start;
        byte eraseByte = GetVolumeEraseByte(source, volumeStart);
        while (cursor <= limit - AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            token.ThrowIfCancellationRequested();
            if (source.Slice(cursor, AmiSecureBootSpecification.FfsFileHeaderBytes).IndexOfAnyExcept(eraseByte) < 0)
            {
                break;
            }
            if (files.Count >= SecureBootRepairPolicy.MaximumFilesPerFirmwareVolume ||
                !UefiFfsFileParser.TryRead(source, cursor, limit, eraseByte, out FfsFileHeaderInfo header))
            {
                throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
            }

            // Repacking an FV that contains deleted or transitional files could change update semantics.
            if (header.State != FfsFileState.DataValid)
            {
                throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
            }

            var file = new FfsFile(header.Guid, cursor, header.Size, header.HeaderSize, header.Attributes);
            ValidateFfsPlacement(file, volumeStart, cursor);
            files.Add(file);
            cursor = AlignFfsFile(volumeStart, checked(cursor + header.Size));
        }

        end = cursor;
        return files;
    }

    private static void FixFfsChecksum(Span<byte> file)
    {
        if (!UefiFfsChecksum.TryRecalculate(file, AmiSecureBootSpecification.FfsFileHeaderBytes))
        {
            throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
        }
    }

    private static void ReadExactly(Stream input, Span<byte> output, CancellationToken token)
    {
        int done = 0;
        while (done < output.Length)
        {
            token.ThrowIfCancellationRequested();
            int count = input.Read(output[done..]);
            if (count == 0)
            {
                throw new InvalidDataException(OperationError.UnsupportedSecureBootLayout);
            }
            done += count;
        }
    }

    private static int ReadU24(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;

    private static void WriteU24(Span<byte> data, int offset, int value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
        data[offset + 2] = (byte)(value >> 16);
    }

    private static int AlignFfsFile(int volumeStart, int value)
    {
        int alignment = AmiSecureBootSpecification.FfsAlignmentBytes;
        int relative = checked(value - volumeStart);
        int aligned = checked((relative + alignment - 1) & ~(alignment - 1));
        return checked(volumeStart + aligned);
    }

    private enum PlatformKeyRemovalMode
    {
        TestOnly,
        Dangerous
    }

    private readonly record struct FfsFileLocation(int Offset, int Size, int HeaderSize, int VolumeStart, int VolumeEnd);
    private readonly record struct SecureBootStorePair(FfsFileLocation Kek, FfsFileLocation Db)
    {
        internal int VolumeStart => Kek.VolumeStart;
    }
    private readonly record struct FfsVolumeLayout(int Start, int End, int FirstFileOffset, byte EraseByte);
    private readonly record struct FfsPlacement(FfsFile File, int Offset, int Size);
    private sealed record FfsFile(
        Guid Guid,
        int Offset,
        int Size,
        int HeaderSize,
        byte Attributes,
        byte[]? Replacement = null);
}
