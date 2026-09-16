using System.Buffers.Binary;
using System.Security.Cryptography;

namespace XeonV3Control.Core;

public enum ImageKind
{
    Unknown,
    UefiImage,
    IntelSpiImage,
    Capsule
}
public sealed record FirmwareVolume(long Offset, long Length, Guid FileSystem, bool HeaderChecksumValid);
public sealed record FlashRegion(FlashRegionKind Kind, long Offset, long Length, bool WithinImage);
public sealed record BiosImage(string FilePath, long Size, string Sha256, ImageKind Kind,
    IReadOnlyList<FirmwareVolume> Volumes, IReadOnlyList<FlashRegion> Regions,
    IReadOnlyList<string> Markers, IReadOnlyList<string> Issues)
{
    /// <summary>
    /// Broad read-only scan of all recognizable EFI X.509 signature lists in the image.
    /// This may include inactive, recovery, or unrelated copies.
    /// </summary>
    public SecureBootReport SecureBoot { get; init; } = SecureBootReport.Empty;

    /// <summary>
    /// Certificates from the structurally selected AMI PK/KEK/db stores that the repair operation manages.
    /// Null when the managed layout cannot be identified unambiguously.
    /// </summary>
    public SecureBootReport? ManagedSecureBoot { get; init; }

    /// <summary>Active DXE/MM firmware drivers found in standard PI firmware volumes.</summary>
    public UefiDriverReport UefiDrivers { get; init; } = UefiDriverReport.Empty;

    /// <summary>Read-only Turbo Boost Unlock and Intel CPU patch inspection.</summary>
    public TurboBoostUnlockReport TurboBoostUnlock { get; init; } = TurboBoostUnlockReport.Empty;

    /// <summary>Read-only X99/LGA2011-3 exact-transition UEFI driver update plans.</summary>
    public IReadOnlyList<X99UefiDriverUpdatePlan> X99UefiDriverUpdates { get; init; } = [];

    /// <summary>BIOS/base-board identity supported by bytes in this firmware image.</summary>
    public FirmwareImageIdentity FirmwareIdentity { get; init; } = FirmwareImageIdentity.Empty;

    /// <summary>TPM firmware evidence derived only from the opened image bytes.</summary>
    public TpmFirmwareReport TpmFirmware { get; init; } = TpmFirmwareReport.Empty;

    /// <summary>Boot-logo and startup-beeper personalization state derived from the opened image.</summary>
    public PersonalizationReport Personalization { get; init; } = PersonalizationReport.Empty;
}

/// <summary>Structural inspection, never a declaration that an image is safe to flash.</summary>
public static class BiosImageLoader
{
    public const int MinBiosImageBytes = 1024 * 1024;
    public const int MaxImageBytes = 128 * 1024 * 1024;
    public static IReadOnlyList<string> SupportedFileExtensions { get; } =
        [".bin", ".rom", ".fd", ".cap", ".bio", ".bios", ".img", ".dump"];

    public static bool HasSupportedFileExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        string extension = Path.GetExtension(path) ?? string.Empty;
        return SupportedFileExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    private static readonly string[] ValidationIssuePriority =
    [
        FirmwareValidationError.InvalidCapsule,
        FirmwareValidationError.InvalidDescriptor,
        FirmwareValidationError.RegionOutsideImage,
        FirmwareValidationError.OverlappingRegions,
        FirmwareValidationError.InvalidVolume,
        FirmwareValidationError.VolumeChecksum,
        FirmwareValidationError.TooManyVolumes,
        FirmwareValidationError.NoVolumes
    ];

    public static async Task<BiosImage> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            UefiFirmwareSpecification.FileIoBufferBytes, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length is < MinBiosImageBytes or > MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }

        byte[] data = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(data, cancellationToken);
        return await Task.Run(() => Analyze(data, Path.GetFullPath(path), cancellationToken), cancellationToken);
    }

    public static async Task<BiosImage> LoadValidatedAsync(string path, CancellationToken cancellationToken = default)
    {
        BiosImage image = await LoadAsync(path, cancellationToken);
        EnsureValidBiosImage(image);
        return image;
    }

    public static void EnsureValidBiosImage(BiosImage image)
    {
        if (image.Size < MinBiosImageBytes || image.Size > MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }
        if (image.Kind == ImageKind.Unknown)
        {
            throw new InvalidDataException(FirmwareValidationError.NotBiosImage);
        }

        foreach (string issue in ValidationIssuePriority)
        {
            if (image.Issues.Contains(issue))
            {
                throw new InvalidDataException(issue);
            }
        }
        if (image.Issues.Count != 0)
        {
            throw new InvalidDataException(FirmwareValidationError.NotBiosImage);
        }

        if (image.Volumes.Count == 0 ||
            !image.Volumes.Any(volume => volume.HeaderChecksumValid && IsStandardFirmwareFileSystem(volume.FileSystem)))
        {
            throw new InvalidDataException(FirmwareValidationError.NotBiosImage);
        }

        if (image.Regions.Count == 0)
        {
            return;
        }
        FlashRegion? bios = image.Regions.FirstOrDefault(region => region.Kind == FlashRegionKind.BIOS);
        if (bios is null || !bios.WithinImage ||
            !image.Volumes.Any(volume => RangeContains(bios.Offset, bios.Length, volume.Offset, volume.Length)))
        {
            throw new InvalidDataException(FirmwareValidationError.InvalidBiosRegion);
        }
    }

    public static BiosImage Analyze(ReadOnlySpan<byte> data, string path = "", CancellationToken cancellationToken = default)
    {
        if (data.Length is < 1 or > MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }

        var volumes = new List<FirmwareVolume>();
        var regions = new List<FlashRegion>();
        var issues = new HashSet<string>();
        ImageKind kind = ImageKind.Unknown;
        int payload = 0;

        if (data.Length >= UefiFirmwareSpecification.CapsuleMinimumHeaderBytes)
        {
            Guid capsuleGuid = new(data[..16]);
            if (UefiFirmwareSpecification.CapsuleGuids.Contains(capsuleGuid))
            {
                kind = ImageKind.Capsule;
                uint header = U32(data, UefiFirmwareSpecification.CapsuleHeaderSizeOffset);
                uint total = U32(data, UefiFirmwareSpecification.CapsuleImageSizeOffset);
                if (header < UefiFirmwareSpecification.CapsuleMinimumHeaderBytes || header > data.Length ||
                    total != data.Length || header >= total)
                {
                    issues.Add(FirmwareValidationError.InvalidCapsule);
                }
                else
                {
                    payload = (int)header;
                }
            }
        }

        ReadOnlySpan<byte> body = data[payload..];
        if (body.Length >= IntelFlashDescriptorSpecification.DescriptorWindowBytes &&
            U32(body, IntelFlashDescriptorSpecification.SignatureOffset) == IntelFlashDescriptorSpecification.Signature)
        {
            if (kind != ImageKind.Capsule)
            {
                kind = ImageKind.IntelSpiImage;
            }
            uint flashMap0 = U32(body, IntelFlashDescriptorSpecification.FlashMap0Offset);
            int frba = checked((int)((flashMap0 >> IntelFlashDescriptorSpecification.RegionBaseFieldShift) &
                IntelFlashDescriptorSpecification.RegionBaseFieldMask) *
                IntelFlashDescriptorSpecification.RegionTableAddressUnitBytes);
            int regionCount = checked((int)((flashMap0 >> IntelFlashDescriptorSpecification.RegionCountFieldShift) &
                IntelFlashDescriptorSpecification.RegionCountFieldMask) +
                IntelFlashDescriptorSpecification.RegionCountBias);

            if (frba < IntelFlashDescriptorSpecification.MinimumRegionTableOffset ||
                frba + regionCount * IntelFlashDescriptorSpecification.RegionEntryBytes >
                    IntelFlashDescriptorSpecification.DescriptorWindowBytes ||
                regionCount > IntelFlashDescriptorSpecification.MaximumRegionCount)
            {
                issues.Add(FirmwareValidationError.InvalidDescriptor);
            }
            else
            {
                for (int n = 0; n < regionCount; n++)
                {
                    uint value = U32(body, frba + n * IntelFlashDescriptorSpecification.RegionEntryBytes);
                    long start = (value & IntelFlashDescriptorSpecification.RegionAddressFieldMask) <<
                        IntelFlashDescriptorSpecification.RegionAddressShift;
                    long end = ((long)((value >> 16) & IntelFlashDescriptorSpecification.RegionAddressFieldMask) <<
                        IntelFlashDescriptorSpecification.RegionAddressShift) |
                        IntelFlashDescriptorSpecification.RegionTailMask;
                    if (start > end)
                    {
                        continue;
                    }

                    bool fits = end < body.Length;
                    regions.Add(new(IntelFlashDescriptorSpecification.RegionKinds[n], payload + start,
                        end - start + 1, fits));
                    if (!fits)
                    {
                        issues.Add(FirmwareValidationError.RegionOutsideImage);
                    }
                }

                for (int n = 0; n < regions.Count; n++)
                {
                    for (int j = n + 1; j < regions.Count; j++)
                    {
                        if (regions[n].Offset < regions[j].Offset + regions[j].Length &&
                            regions[j].Offset < regions[n].Offset + regions[n].Length)
                        {
                            issues.Add(FirmwareValidationError.OverlappingRegions);
                        }
                    }
                }
            }
        }

        int scan = payload + UefiFirmwareSpecification.FirmwareVolumeSignatureOffset;
        while (scan <= data.Length - UefiFirmwareSpecification.FirmwareVolumeSignature.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int found = data[scan..].IndexOf(UefiFirmwareSpecification.FirmwareVolumeSignature);
            if (found < 0)
            {
                break;
            }

            int start = scan + found - UefiFirmwareSpecification.FirmwareVolumeSignatureOffset;
            scan += found + UefiFirmwareSpecification.FirmwareVolumeSignature.Length;
            if (start < payload || data.Length - start < UefiFirmwareSpecification.FirmwareVolumeMinimumHeaderBytes)
            {
                issues.Add(FirmwareValidationError.InvalidVolume);
                continue;
            }

            ReadOnlySpan<byte> header = data[start..];
            Guid fileSystem = new(header.Slice(UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset, 16));
            bool standardFileSystem = IsStandardFirmwareFileSystem(fileSystem);
            bool zeroVector = header[..UefiFirmwareSpecification.FirmwareVolumeFileSystemOffset]
                .IndexOfAnyExcept((byte)0) < 0;
            bool plausibleHeader = zeroVector || standardFileSystem;
            ulong length = BinaryPrimitives.ReadUInt64LittleEndian(
                header[UefiFirmwareSpecification.FirmwareVolumeLengthOffset..]);
            int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
                header[UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset..]);

            if (length < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes || length > (ulong)header.Length ||
                headerLength < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes ||
                (ulong)headerLength > length || (headerLength & 1) != 0 ||
                header[UefiFirmwareSpecification.FirmwareVolumeReservedOffset] != 0 ||
                header[UefiFirmwareSpecification.FirmwareVolumeRevisionOffset] != UefiFirmwareSpecification.FirmwareVolumeRevision2)
            {
                if (plausibleHeader)
                {
                    issues.Add(FirmwareValidationError.InvalidVolume);
                }
                continue;
            }

            uint checksumSum = 0;
            for (int i = 0; i < headerLength; i += sizeof(ushort))
            {
                checksumSum += BinaryPrimitives.ReadUInt16LittleEndian(header[i..]);
            }
            bool checksum = (checksumSum & ushort.MaxValue) == 0;
            if (!checksum)
            {
                issues.Add(FirmwareValidationError.VolumeChecksum);
            }

            if (!zeroVector || !standardFileSystem || !HasValidBlockMap(header[..headerLength], length))
            {
                issues.Add(FirmwareValidationError.InvalidVolume);
                continue;
            }

            volumes.Add(new(start, (long)length, fileSystem, checksum));
            if (volumes.Count >= UefiFirmwareSpecification.MaximumFirmwareVolumes)
            {
                issues.Add(FirmwareValidationError.TooManyVolumes);
                break;
            }
        }

        if (kind == ImageKind.Unknown && volumes.Count > 0)
        {
            kind = ImageKind.UefiImage;
        }
        if (volumes.Count == 0)
        {
            issues.Add(FirmwareValidationError.NoVolumes);
        }

        var markers = new List<string>();
        foreach (FirmwareMarkerPattern marker in FirmwareMarkerCatalog.Entries)
        {
            if (data.IndexOf(marker.Ascii) >= 0 || data.IndexOf(marker.Utf16Le) >= 0)
            {
                markers.Add(marker.Name);
            }
        }

        string imageSha256 = Convert.ToHexString(SHA256.HashData(data));
        TurboBoostExecutableObserver turboObserver = TurboBoostUnlockInspector.CreateExecutableObserver();
        UefiDriverReport uefiDrivers = UefiDriverInspector.Inspect(data, volumes, turboObserver, cancellationToken);
        TurboBoostUnlockReport turboBoostUnlock = TurboBoostUnlockInspector.Inspect(
            data,
            imageSha256,
            volumes,
            uefiDrivers,
            turboObserver,
            cancellationToken);

        var image = new BiosImage(
            path,
            data.Length,
            imageSha256,
            kind,
            volumes,
            regions,
            markers,
            ValidationIssuePriority.Where(issues.Contains).ToArray())
        {
            SecureBoot = SecureBootInspector.Inspect(data, cancellationToken),
            UefiDrivers = uefiDrivers,
            TurboBoostUnlock = turboBoostUnlock,
            FirmwareIdentity = FirmwareImageIdentityInspector.Inspect(data),
            TpmFirmware = TpmFirmwareInspector.Inspect(data, uefiDrivers)
        };

        image = image with
        {
            Personalization = PersonalizationInspector.Inspect(data, image, cancellationToken)
        };
        image = image with
        {
            ManagedSecureBoot = SecureBootImageUpdater.TryInspectManagedState(data, image, cancellationToken)
        };
        image = image with
        {
            X99UefiDriverUpdates = X99UefiDriverUpdatePlanner.Plan(data, image, cancellationToken)
        };
        return image;
    }

    private static bool IsStandardFirmwareFileSystem(Guid fileSystem) =>
        UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(fileSystem);

    private static bool HasValidBlockMap(ReadOnlySpan<byte> header, ulong volumeLength)
    {
        if (header.Length < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes)
        {
            return false;
        }
        ulong covered = 0;
        for (int offset = UefiFirmwareSpecification.FirmwareVolumeBlockMapOffset;
             offset <= header.Length - UefiFirmwareSpecification.FirmwareVolumeBlockMapEntryBytes;
             offset += UefiFirmwareSpecification.FirmwareVolumeBlockMapEntryBytes)
        {
            uint blocks = U32(header, offset);
            uint blockLength = U32(header, offset + sizeof(uint));
            if (blocks == 0 && blockLength == 0)
            {
                return covered == volumeLength;
            }
            if (blocks == 0 || blockLength == 0)
            {
                return false;
            }

            ulong extent = (ulong)blocks * blockLength;
            if (covered > volumeLength || extent > volumeLength - covered)
            {
                return false;
            }
            covered += extent;
        }

        return false;
    }

    private static bool RangeContains(long outerOffset, long outerLength, long innerOffset, long innerLength)
    {
        if (outerOffset < 0 || outerLength < 0 || innerOffset < 0 || innerLength < 0)
        {
            return false;
        }
        try
        {
            long outerEnd = checked(outerOffset + outerLength);
            long innerEnd = checked(innerOffset + innerLength);
            return innerOffset >= outerOffset && innerEnd <= outerEnd;
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    private static uint U32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
}
