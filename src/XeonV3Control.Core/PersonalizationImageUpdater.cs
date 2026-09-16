using System.Security.Cryptography;

namespace XeonV3Control.Core;

/// <summary>Fail-closed boot-logo and startup-beeper mutations for recognized AMI X99 layouts.</summary>
public static class PersonalizationImageUpdater
{
    private const int MaximumReplacementBmpBytes = 8 * 1024 * 1024;

    public static async Task<BiosImage> ReplaceBootLogoFileAsync(
        string sourcePath,
        string destinationPath,
        BiosImage sourceImage,
        BootLogoKind kind,
        string replacementBmpPath,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(replacementBmpPath);
        byte[] replacement = await ReadReplacementBmpAsync(replacementBmpPath, token);
        return await ReplaceBootLogoAsync(
            sourcePath, destinationPath, sourceImage, kind, replacement, token);
    }

    public static Task<BiosImage> ReplaceBootLogoAsync(
        string sourcePath,
        string destinationPath,
        BiosImage sourceImage,
        BootLogoKind kind,
        ReadOnlyMemory<byte> replacementBmp,
        CancellationToken token = default) =>
        ReplaceBootLogoBytesAsync(
            sourcePath, destinationPath, sourceImage, kind, replacementBmp, token);

    private static async Task<BiosImage> ReplaceBootLogoBytesAsync(
        string sourcePath,
        string destinationPath,
        BiosImage sourceImage,
        BootLogoKind kind,
        ReadOnlyMemory<byte> replacementBmp,
        CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(sourceImage);

        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourcePath, token);
        FirmwareMutationFileIo.VerifySha256(source, sourceImage.Sha256, OperationError.PersonalizationSourceChanged);

        byte[] replacement = replacementBmp.ToArray();
        if (replacement.Length < PersonalizationInspector.BmpInfo.MinimumHeaderBytes ||
            replacement.Length > MaximumReplacementBmpBytes)
        {
            throw new InvalidDataException(OperationError.PersonalizationInvalidBmp);
        }
        if (!PersonalizationInspector.BmpInfo.TryParse(replacement, out PersonalizationInspector.BmpInfo replacementInfo))
        {
            throw new InvalidDataException(OperationError.PersonalizationInvalidBmp);
        }

        if (!PersonalizationInspector.TryReadLogoBmp(
                source,
                sourceImage,
                kind,
                token,
                out AmiLzmaFfsEditor.LocatedFile located,
                out AmiLzmaFfsEditor.SectionInfo rawSection,
                out _,
                out PersonalizationInspector.BmpInfo currentInfo))
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }
        if (replacementInfo.Width != currentInfo.Width ||
            replacementInfo.Height != currentInfo.Height ||
            replacementInfo.TopDown != currentInfo.TopDown ||
            replacementInfo.BitsPerPixel != currentInfo.BitsPerPixel ||
            replacementInfo.Compression != currentInfo.Compression ||
            replacementInfo.DibHeaderSize != currentInfo.DibHeaderSize ||
            replacementInfo.PixelOffset != currentInfo.PixelOffset ||
            replacementInfo.FileSize != currentInfo.FileSize)
        {
            throw new InvalidDataException(OperationError.PersonalizationBmpFormatMismatch);
        }

        byte[] sourceFfs = source.AsSpan(located.File.Offset, located.File.Size).ToArray();
        byte[] candidate = AmiLzmaFfsEditor.RewriteExpandedSectionStream(
            sourceFfs,
            expanded =>
            {
                if (!AmiLzmaFfsEditor.TryReadSections(expanded, out IReadOnlyList<AmiLzmaFfsEditor.SectionInfo> sections))
                {
                    throw new InvalidDataException(OperationError.PersonalizationUnsupported);
                }
                AmiLzmaFfsEditor.SectionInfo[] rawBmps = sections
                    .Where(item => item.Type == AmiSecureBootSpecification.RawSectionType &&
                        item.HeaderSize == AmiSecureBootSpecification.SectionHeaderBytes &&
                        item.Size > item.HeaderSize + PersonalizationInspector.BmpInfo.MinimumHeaderBytes &&
                        expanded[item.Offset + item.HeaderSize] == (byte)'B' &&
                        expanded[item.Offset + item.HeaderSize + 1] == (byte)'M')
                    .ToArray();
                if (rawBmps.Length != 1 || rawBmps[0].Offset != rawSection.Offset || rawBmps[0].Size != rawSection.Size)
                {
                    throw new InvalidDataException(OperationError.PersonalizationSourceChanged);
                }
                byte[] replacementSection = AmiLzmaFfsEditor.BuildNormalSection(
                    AmiSecureBootSpecification.RawSectionType,
                    replacement);
                return AmiLzmaFfsEditor.ReplaceSection(expanded, rawBmps[0], replacementSection);
            },
            token);

        byte[] updated = ApplyReplacement(source, sourceImage, located, candidate, token);
        BiosImage inspected = BiosImageLoader.Analyze(updated, Path.GetFullPath(destinationPath), token);
        BiosImageLoader.EnsureValidBiosImage(inspected);
        BootLogoInfo result = kind == BootLogoKind.SmallAmi
            ? inspected.Personalization.SmallLogo
            : inspected.Personalization.LargeLogo;
        BootLogoInfo untouchedBefore = kind == BootLogoKind.SmallAmi
            ? sourceImage.Personalization.LargeLogo
            : sourceImage.Personalization.SmallLogo;
        BootLogoInfo untouchedAfter = kind == BootLogoKind.SmallAmi
            ? inspected.Personalization.LargeLogo
            : inspected.Personalization.SmallLogo;
        bool untouchedLogoChanged =
            untouchedBefore.Status == PersonalizationFeatureStatus.Available &&
            (untouchedAfter.Status != PersonalizationFeatureStatus.Available ||
             !string.Equals(untouchedBefore.BmpSha256, untouchedAfter.BmpSha256, StringComparison.OrdinalIgnoreCase));
        if (result.Status != PersonalizationFeatureStatus.Available ||
            result.Width != replacementInfo.Width ||
            result.Height != replacementInfo.Height ||
            result.BitsPerPixel != replacementInfo.BitsPerPixel ||
            !string.Equals(result.BmpSha256, Convert.ToHexString(SHA256.HashData(replacement)), StringComparison.OrdinalIgnoreCase) ||
            untouchedLogoChanged ||
            inspected.Personalization.Beeper.Status != sourceImage.Personalization.Beeper.Status)
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }

        await FirmwareMutationFileIo.WriteNewVerifiedImageAsync(destinationPath, updated, token);
        BiosImage diskImage = await BiosImageLoader.LoadValidatedAsync(destinationPath, token);
        if (!string.Equals(diskImage.Sha256, inspected.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }
        return diskImage;
    }

    public static async Task<BiosImage> SetStartupBeeperDisabledAsync(
        string sourcePath,
        string destinationPath,
        BiosImage sourceImage,
        bool disabled,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(sourceImage);

        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourcePath, token);
        FirmwareMutationFileIo.VerifySha256(source, sourceImage.Sha256, OperationError.PersonalizationSourceChanged);
        if (!PersonalizationInspector.TryLocateBeeperFunction(
                source,
                sourceImage,
                token,
                out AmiLzmaFfsEditor.LocatedFile located,
                out AmiLzmaFfsEditor.SectionInfo peSection,
                out byte[] sourceExpanded,
                out int functionOffset,
                out StartupBeeperStatus currentStatus) ||
            currentStatus is not (StartupBeeperStatus.Enabled or StartupBeeperStatus.Disabled))
        {
            throw new InvalidDataException(OperationError.PersonalizationBeeperUnsupported);
        }
        bool currentlyDisabled = currentStatus == StartupBeeperStatus.Disabled;
        if (currentlyDisabled == disabled)
        {
            throw new InvalidDataException(OperationError.PersonalizationBeeperAlreadySet);
        }

        int patchOffset = checked(peSection.Offset + peSection.HeaderSize + functionOffset);
        byte[] sourceFfs = source.AsSpan(located.File.Offset, located.File.Size).ToArray();
        byte[] candidate;
        if (disabled)
        {
            if (!PersonalizationInspector.TryBuildBeeperDisablePatches(
                    sourceExpanded, peSection, functionOffset, out IReadOnlyList<byte[]> patches))
            {
                throw new InvalidDataException(OperationError.PersonalizationBeeperUnsupported);
            }

            candidate = AmiLzmaFfsEditor.RewriteExpandedSectionStreamCandidates(
                sourceFfs,
                expanded =>
                {
                    if (!expanded.AsSpan().SequenceEqual(sourceExpanded))
                    {
                        throw new InvalidDataException(OperationError.PersonalizationSourceChanged);
                    }

                    var variants = new List<byte[]>(patches.Count);
                    foreach (byte[] patch in patches)
                    {
                        if (patchOffset < 0 || patchOffset > expanded.Length - patch.Length)
                        {
                            continue;
                        }
                        byte[] rewritten = expanded.ToArray();
                        patch.CopyTo(rewritten, patchOffset);
                        variants.Add(rewritten);
                    }
                    if (variants.Count == 0)
                    {
                        throw new InvalidDataException(OperationError.PersonalizationBeeperUnsupported);
                    }
                    return variants;
                },
                token);
        }
        else
        {
            if (!PersonalizationInspector.TryBuildBeeperEnablePatches(
                    sourceExpanded, peSection, functionOffset, out IReadOnlyList<byte[]> enablePatches))
            {
                throw new InvalidDataException(OperationError.PersonalizationBeeperUnsupported);
            }

            candidate = AmiLzmaFfsEditor.RewriteExpandedSectionStreamCandidates(
                sourceFfs,
                expanded =>
                {
                    if (!expanded.AsSpan().SequenceEqual(sourceExpanded))
                    {
                        throw new InvalidDataException(OperationError.PersonalizationSourceChanged);
                    }

                    var variants = new List<byte[]>(enablePatches.Count);
                    foreach (byte[] enablePatch in enablePatches)
                    {
                        if (patchOffset < 0 || patchOffset > expanded.Length - enablePatch.Length)
                        {
                            continue;
                        }
                        byte[] rewritten = expanded.ToArray();
                        enablePatch.CopyTo(rewritten, patchOffset);
                        variants.Add(rewritten);
                    }
                    if (variants.Count == 0)
                    {
                        throw new InvalidDataException(OperationError.PersonalizationBeeperUnsupported);
                    }
                    return variants;
                },
                token);
        }

        byte[] updated = ApplyReplacement(source, sourceImage, located, candidate, token);
        BiosImage inspected = BiosImageLoader.Analyze(updated, Path.GetFullPath(destinationPath), token);
        BiosImageLoader.EnsureValidBiosImage(inspected);
        StartupBeeperStatus expectedStatus = disabled ? StartupBeeperStatus.Disabled : StartupBeeperStatus.Enabled;
        bool largeLogoChanged = sourceImage.Personalization.LargeLogo.Status == PersonalizationFeatureStatus.Available &&
            (inspected.Personalization.LargeLogo.Status != PersonalizationFeatureStatus.Available ||
             !string.Equals(sourceImage.Personalization.LargeLogo.BmpSha256, inspected.Personalization.LargeLogo.BmpSha256, StringComparison.OrdinalIgnoreCase));
        bool smallLogoChanged = sourceImage.Personalization.SmallLogo.Status == PersonalizationFeatureStatus.Available &&
            (inspected.Personalization.SmallLogo.Status != PersonalizationFeatureStatus.Available ||
             !string.Equals(sourceImage.Personalization.SmallLogo.BmpSha256, inspected.Personalization.SmallLogo.BmpSha256, StringComparison.OrdinalIgnoreCase));
        if (inspected.Personalization.Beeper.Status != expectedStatus || largeLogoChanged || smallLogoChanged)
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }

        await FirmwareMutationFileIo.WriteNewVerifiedImageAsync(destinationPath, updated, token);
        BiosImage diskImage = await BiosImageLoader.LoadValidatedAsync(destinationPath, token);
        if (!string.Equals(diskImage.Sha256, inspected.Sha256, StringComparison.OrdinalIgnoreCase) ||
            diskImage.Personalization.Beeper.Status != expectedStatus)
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }
        return diskImage;
    }

    private static byte[] ApplyReplacement(
        ReadOnlySpan<byte> source,
        BiosImage sourceImage,
        AmiLzmaFfsEditor.LocatedFile located,
        ReadOnlySpan<byte> candidate,
        CancellationToken token)
    {
        UefiDriverMutationPlanner.EnsureImageMatches(source, sourceImage);
        token.ThrowIfCancellationRequested();

        if (!UefiFfsVolumeScanner.TryGetLayout(source, located.Volume, out UefiFfsVolumeLayout layout) ||
            !UefiFfsVolumeScanner.TryReadFiles(
                source,
                located.Volume,
                token,
                out UefiFfsVolumeLayout sourceLayout,
                out IReadOnlyList<UefiFfsFileLocation> sourceFiles) ||
            sourceLayout != layout ||
            !UefiFfsFileParser.TryRead(candidate, 0, candidate.Length, layout.EraseByte, out FfsFileHeaderInfo candidateHeader) ||
            candidateHeader.Size != candidate.Length ||
            candidateHeader.State != FfsFileState.DataValid ||
            candidateHeader.Guid != located.File.Guid ||
            candidateHeader.Type != located.File.Type ||
            candidateHeader.Attributes != located.File.Attributes ||
            candidateHeader.HeaderSize != located.File.HeaderSize)
        {
            throw new InvalidDataException(OperationError.PersonalizationUnsupported);
        }

        string sourceTargetSha = Convert.ToHexString(
            SHA256.HashData(source.Slice(located.File.Offset, located.File.Size)));
        if (!string.Equals(sourceTargetSha, located.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(OperationError.PersonalizationSourceChanged);
        }

        int candidateNext = UefiFfsVolumeScanner.Align(
            layout.Start,
            checked(located.File.Offset + candidate.Length),
            AmiSecureBootSpecification.FfsAlignmentBytes);
        if (candidateNext != located.File.NextOffset ||
            located.File.NextOffset > layout.End ||
            candidate.Length > located.File.NextOffset - located.File.Offset)
        {
            throw new InvalidDataException(OperationError.PersonalizationSpace);
        }

        // This mutation is intentionally local to the original FFS allocation. No neighbouring file
        // moves, no DXE dispatch order changes, and no opaque/freeform file needs to be reclassified.
        byte[] output = source.ToArray();
        candidate.CopyTo(output.AsSpan(located.File.Offset));
        output.AsSpan(
                located.File.Offset + candidate.Length,
                located.File.NextOffset - located.File.Offset - candidate.Length)
            .Fill(layout.EraseByte);

        if (!source[..located.File.Offset].SequenceEqual(output.AsSpan(0, located.File.Offset)) ||
            !source[located.File.NextOffset..].SequenceEqual(output.AsSpan(located.File.NextOffset)))
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }

        if (!UefiFfsVolumeScanner.TryReadFiles(
                output,
                located.Volume,
                token,
                out UefiFfsVolumeLayout outputLayout,
                out IReadOnlyList<UefiFfsFileLocation> outputFiles) ||
            outputLayout != layout ||
            sourceFiles.Count != outputFiles.Count)
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }

        bool targetValidated = false;
        for (int index = 0; index < sourceFiles.Count; index++)
        {
            UefiFfsFileLocation before = sourceFiles[index];
            UefiFfsFileLocation after = outputFiles[index];
            bool target = before.Offset == located.File.Offset && before.Guid == located.File.Guid;
            if (target)
            {
                if (targetValidated ||
                    after.Offset != before.Offset ||
                    after.NextOffset != before.NextOffset ||
                    after.Guid != before.Guid ||
                    after.Type != before.Type ||
                    after.Attributes != before.Attributes ||
                    after.HeaderSize != before.HeaderSize ||
                    after.State != FfsFileState.DataValid ||
                    after.Size != candidate.Length ||
                    !output.AsSpan(after.Offset, after.Size).SequenceEqual(candidate))
                {
                    throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
                }
                targetValidated = true;
                continue;
            }

            if (after != before ||
                !source.Slice(before.Offset, before.Size).SequenceEqual(output.AsSpan(after.Offset, after.Size)))
            {
                throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
            }
        }

        if (!targetValidated)
        {
            throw new InvalidDataException(OperationError.PersonalizationOutputInvalid);
        }
        return output;
    }

    private static async Task<byte[]> ReadReplacementBmpAsync(string path, CancellationToken token)
    {
        string fullPath = Path.GetFullPath(path);
        var info = new FileInfo(fullPath);
        info.Refresh();
        if (!info.Exists || info.Length < PersonalizationInspector.BmpInfo.MinimumHeaderBytes ||
            info.Length > MaximumReplacementBmpBytes)
        {
            throw new InvalidDataException(OperationError.PersonalizationInvalidBmp);
        }
        byte[] bytes = new byte[checked((int)info.Length)];
        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            UefiFirmwareSpecification.FileIoBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await stream.ReadExactlyAsync(bytes, token);
        return bytes;
    }
}



