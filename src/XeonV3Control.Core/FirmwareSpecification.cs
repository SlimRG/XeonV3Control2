using System.Text;
using System.Text.Json;

namespace XeonV3Control.Core;

public enum FlashRegionKind
{
    Descriptor,
    BIOS,
    ME,
    GbE,
    PDR,
    DeviceExpansion,
    SecondaryBIOS,
    Reserved7
}


public static class FirmwareValidationError
{
    public const string ImageSize = nameof(ImageSize);
    public const string NotBiosImage = nameof(NotBiosImage);
    public const string InvalidCapsule = nameof(InvalidCapsule);
    public const string InvalidDescriptor = nameof(InvalidDescriptor);
    public const string RegionOutsideImage = nameof(RegionOutsideImage);
    public const string OverlappingRegions = nameof(OverlappingRegions);
    public const string InvalidVolume = nameof(InvalidVolume);
    public const string VolumeChecksum = nameof(VolumeChecksum);
    public const string TooManyVolumes = nameof(TooManyVolumes);
    public const string NoVolumes = nameof(NoVolumes);
    public const string InvalidBiosRegion = nameof(InvalidBiosRegion);
}

internal static class UefiFirmwareSpecification
{
    internal const int FileIoBufferBytes = 64 * 1024;
    internal const int CapsuleMinimumHeaderBytes = 28;
    internal const int CapsuleGuidBytes = 16;
    internal const int CapsuleHeaderSizeOffset = 16;
    internal const int CapsuleImageSizeOffset = 24;
    internal const int FirmwareVolumeSignatureOffset = 40;
    internal const int FirmwareVolumeMinimumHeaderBytes = 56;
    internal const int FirmwareVolumeMinimumLengthBytes = 64;
    internal const int FirmwareVolumeFileSystemOffset = 16;
    internal const int FirmwareVolumeLengthOffset = 32;
    internal const int FirmwareVolumeHeaderLengthOffset = 48;
    internal const int FirmwareVolumeChecksumOffset = 50;
    internal const int FirmwareVolumeAttributesOffset = 44;
    internal const int FirmwareVolumeExtendedHeaderOffsetOffset = 52;
    internal const int FirmwareVolumeExtendedHeaderSizeOffset = 16;
    internal const int FirmwareVolumeExtendedHeaderMinimumBytes = 20;
    internal const uint FirmwareVolumeErasePolarityMask = 0x00000800;
    internal const int FirmwareVolumeReservedOffset = 54;
    internal const int FirmwareVolumeRevisionOffset = 55;
    internal const byte FirmwareVolumeRevision2 = 2;
    internal const int FirmwareVolumeBlockMapOffset = 56;
    internal const int FirmwareVolumeBlockMapEntryBytes = 8;
    internal const int MaximumFirmwareVolumes = 4096;

    internal static ReadOnlySpan<byte> FirmwareVolumeSignature => "_FVH"u8;

    internal static readonly Guid[] CapsuleGuids =
    [
        new("6dcbd5ed-e82d-4c44-bda1-7194199ad92a"),
        new("4a3ca68b-7723-48fb-803d-578cc1fec44d"),
        new("56102b5b-1647-4c19-ae2f-98e9f92e5dcf")
    ];

    internal static readonly Guid[] StandardFirmwareFileSystems =
    [
        new("7a9354d9-0468-444a-81ce-0bf617d890df"),
        new("8c8ce578-8a3d-4f1c-9935-896185c32dd3"),
        new("5473c07a-3dcb-4dca-bd6f-1e9689e7349a")
    ];
}

internal static class IntelFirmwareInterfaceTableSpecification
{
    internal const int PointerOffsetFromTop = 0x40;
    internal const int EntryBytes = 16;
    internal const int SizeOffset = 8;
    internal const int ReservedOffset = 11;
    internal const int VersionOffset = 12;
    internal const int TypeOffset = 14;
    internal const int ChecksumOffset = 15;
    internal const byte ChecksumValidMask = 0x80;
    internal const byte TypeMask = 0x7F;
    internal const byte HeaderType = 0x00;
    internal const byte MicrocodeType = 0x01;
    internal const byte UnusedType = 0x7F;
    internal const ushort Version100 = 0x0100;
    internal const int MaximumEntries = 4096;
    internal const ulong FourGib = 0x1_0000_0000UL;

    internal static ReadOnlySpan<byte> HeaderSignature => "_FIT_   "u8;
}

internal static class IntelMicrocodeContainerSpecification
{
    internal const int HeaderBytes = 48;
    internal const int MaximumPatchBytes = 2 * 1024 * 1024;
    internal const int LegacyPatchBytes = 2048;
    internal const int ScanAlignmentBytes = sizeof(uint);
    internal const int MpdtFooterBytes = 16;
    internal const uint HeaderVersion = 1;

    internal static ReadOnlySpan<byte> MpdtSignature => "MPDT"u8;
}

internal static class IntelFlashDescriptorSpecification
{
    internal const int DescriptorWindowBytes = 4096;
    internal const int SignatureOffset = 16;
    internal const uint Signature = 0x0FF0A55A;
    internal const int FlashMap0Offset = 20;
    internal const int ComponentBaseFieldShift = 0;
    internal const uint ComponentBaseFieldMask = 0xFF;
    internal const int ComponentCountFieldShift = 8;
    internal const uint ComponentCountFieldMask = 0x03;
    internal const int ComponentCountBias = 1;
    internal const int ComponentSectionAddressUnitBytes = 16;
    internal const int FlashComponentConfigurationOffset = 0;
    internal const uint ComponentDensityFieldMask = 0x07;
    internal const int SecondComponentDensityFieldShift = 4;
    internal const int MaximumWellsburgComponentCount = 2;
    internal const int MaximumWellsburgComponentDensityIndex = 5;
    internal const uint MinimumComponentBytes = 512 * 1024;
    internal const int RegionBaseFieldShift = 16;
    internal const uint RegionBaseFieldMask = 0xFF;
    internal const int RegionCountFieldShift = 24;
    internal const uint RegionCountFieldMask = 0x07;
    internal const int RegionCountBias = 1;
    internal const int RegionTableAddressUnitBytes = 16;
    internal const int MinimumRegionTableOffset = 32;
    internal const int RegionEntryBytes = 4;
    internal const int MaximumRegionCount = 8;
    internal const uint RegionAddressFieldMask = 0x7FFF;
    internal const int RegionAddressShift = 12;
    internal const long RegionTailMask = (1L << RegionAddressShift) - 1L;

    internal static readonly FlashRegionKind[] RegionKinds =
    [
        FlashRegionKind.Descriptor,
        FlashRegionKind.BIOS,
        FlashRegionKind.ME,
        FlashRegionKind.GbE,
        FlashRegionKind.PDR,
        FlashRegionKind.DeviceExpansion,
        FlashRegionKind.SecondaryBIOS,
        FlashRegionKind.Reserved7
    ];
}

internal sealed record FirmwareMarkerPattern(string Name, byte[] Ascii, byte[] Utf16Le);

internal static class FirmwareMarkerCatalog
{
    private const string MarkerFileName = "markers.json";
    private static readonly string ResourceName = EmbeddedResourceNames.File(
        EmbeddedResourceNames.FirmwareFolder, MarkerFileName);
    internal static IReadOnlyList<FirmwareMarkerPattern> Entries { get; } = Load();

    private static IReadOnlyList<FirmwareMarkerPattern> Load()
    {
        using Stream resource = typeof(FirmwareMarkerCatalog).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidDataException(OperationError.FirmwareMarkerCatalog);
        string[] markers = JsonSerializer.Deserialize<string[]>(resource)
            ?? throw new InvalidDataException(OperationError.FirmwareMarkerCatalog);
        if (markers.Length == 0 || markers.Any(string.IsNullOrWhiteSpace) ||
            markers.Distinct(StringComparer.Ordinal).Count() != markers.Length)
        {
            throw new InvalidDataException(OperationError.FirmwareMarkerCatalog);
        }

        return markers
            .Select(marker => new FirmwareMarkerPattern(
                marker,
                Encoding.ASCII.GetBytes(marker),
                Encoding.Unicode.GetBytes(marker)))
            .ToArray();
    }
}
