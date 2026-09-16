using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SharpCompress.Compressors.LZMA;

namespace XeonV3Control.Core;

public enum UefiDriverKind
{
    Dxe,
    CombinedPeimDxe,
    Mm,
    CombinedMmDxe,
    MmStandalone
}

public enum UefiDriverSecurityStatus
{
    NoKnownIssues,
    ReviewRecommended,
    KnownVulnerable,
    Unknown
}

public enum UefiExecutableFormat
{
    Pe32,
    Te
}

public enum UefiMachine
{
    Unknown,
    Ia32,
    X64,
    Itanium,
    Arm,
    Arm64
}

public enum UefiExecutableSubsystem
{
    Unknown,
    EfiApplication,
    EfiBootServiceDriver,
    EfiRuntimeDriver,
    EfiRom
}

public static class UefiDriverIssueCode
{
    public const string KnownVulnerable = nameof(KnownVulnerable);
    public const string WritableExecutableSection = nameof(WritableExecutableSection);
    public const string MalformedExecutable = nameof(MalformedExecutable);
    public const string MissingExecutable = nameof(MissingExecutable);
    public const string UnsupportedGuidedSection = nameof(UnsupportedGuidedSection);
    public const string InvalidSectionStream = nameof(InvalidSectionStream);
    public const string DuplicateFileGuid = nameof(DuplicateFileGuid);
    public const string FileTypeSectionRulesViolation = nameof(FileTypeSectionRulesViolation);
}

public sealed record UefiExecutableInfo(
    UefiExecutableFormat Format,
    string Sha256,
    UefiMachine Machine,
    UefiExecutableSubsystem Subsystem,
    int ImageSize,
    int SectionCount,
    bool StructurallyValid,
    bool? NxCompatible,
    bool? DynamicBase,
    bool WritableExecutableSection);

public sealed record UefiDriverInfo(
    Guid FileGuid,
    UefiDriverKind Kind,
    string? Name,
    string? Version,
    ushort? BuildNumber,
    long VolumeOffset,
    Guid VolumeFileSystem,
    long FileOffset,
    int FileSize,
    int FfsHeaderSize,
    byte FfsType,
    byte FfsAttributes,
    int RequiredDataAlignment,
    bool FixedLocation,
    int SectionCount,
    int CompressionSectionCount,
    int GuidedSectionCount,
    int DependencySectionCount,
    IReadOnlyList<string> DependencySha256,
    string Sha256,
    UefiDriverSecurityStatus SecurityStatus,
    IReadOnlyList<string> Issues,
    IReadOnlyList<string> VulnerabilityIds,
    IReadOnlyList<UefiExecutableInfo> Executables);

public sealed record UefiDriverReport(
    IReadOnlyList<UefiDriverInfo> Drivers,
    bool Incomplete,
    int IncompleteVolumes)
{
    public static UefiDriverReport Empty { get; } = new([], false, 0);
}

internal static class UefiPiCode
{
    internal const byte FfsDriver = 0x07;
    internal const byte FfsCombinedPeimDriver = 0x08;
    internal const byte FfsMm = 0x0A;
    internal const byte FfsCombinedMmDxe = 0x0C;
    internal const byte FfsMmStandalone = 0x0E;
    internal const byte FfsPad = 0xF0;

    internal const int SectionAlignmentBytes = 4;
    internal const int CommonSectionHeaderBytes = 4;
    internal const int ExtendedSectionHeaderBytes = 8;
    internal const int ExtendedSectionSizeOffset = 4;
    internal const byte SectionCompression = 0x01;
    internal const byte SectionGuidDefined = 0x02;
    internal const byte SectionDisposable = 0x03;
    internal const byte SectionPe32 = 0x10;
    internal const byte SectionTe = 0x12;
    internal const byte SectionDxeDepex = 0x13;
    internal const byte SectionVersion = 0x14;
    internal const byte SectionUserInterface = 0x15;
    internal const byte SectionFreeformSubtypeGuid = 0x18;
    internal const byte SectionPeiDepex = 0x1B;
    internal const byte SectionMmDepex = 0x1C;

    internal const int CompressionUncompressedLengthBytes = sizeof(uint);
    internal const int CompressionTypeBytes = sizeof(byte);
    internal const byte CompressionNone = 0;
    internal const byte CompressionStandard = 1;

    internal const int GuidedDefinitionBytes = 16;
    internal const int FreeformSubtypeGuidBytes = 16;
    internal const int GuidedDataOffsetBytes = sizeof(ushort);
    internal const int GuidedAttributesBytes = sizeof(ushort);
    internal const ushort GuidedProcessingRequired = 0x0001;
    internal const ushort GuidedAuthenticationStatusValid = 0x0002;
    internal const ushort GuidedKnownAttributesMask = GuidedProcessingRequired | GuidedAuthenticationStatusValid;
    internal static readonly Guid TianoCustomDecompressGuid = new("a31280ad-481e-41b6-95e8-127f4c984779");

    internal const ushort PeMachineIa32 = 0x014C;
    internal const ushort PeMachineItanium = 0x0200;
    internal const ushort PeMachineX64 = 0x8664;
    internal const ushort PeMachineArm = 0x01C0;
    internal const ushort PeMachineArmNt = 0x01C4;
    internal const ushort PeMachineArm64 = 0xAA64;

    internal const ushort PeSubsystemEfiApplication = 10;
    internal const ushort PeSubsystemEfiBootServiceDriver = 11;
    internal const ushort PeSubsystemEfiRuntimeDriver = 12;
    internal const ushort PeSubsystemEfiRom = 13;

    internal const ushort PeOptionalMagic32 = 0x010B;
    internal const ushort PeOptionalMagic64 = 0x020B;
    internal const ushort PeDllDynamicBase = 0x0040;
    internal const ushort PeDllNxCompatible = 0x0100;
    internal const uint PeSectionMemExecute = 0x20000000;
    internal const uint PeSectionMemWrite = 0x80000000;

    internal const ushort DosMagic = 0x5A4D;
    internal const uint PeSignature = 0x00004550;
    internal const ushort TeSignature = 0x5A56;

    internal const int DosPeOffsetOffset = 0x3C;
    internal const int PeCoffHeaderOffset = 4;
    internal const int PeCoffHeaderBytes = 20;
    internal const int PeMachineOffset = 4;
    internal const int PeNumberOfSectionsOffset = 6;
    internal const int PeOptionalHeaderSizeOffset = 20;
    internal const int PeOptionalHeaderOffset = 24;
    internal const int PeOptionalSubsystemOffset = 68;
    internal const int PeOptionalDllCharacteristicsOffset = 70;
    internal const int PeSectionHeaderBytes = 40;
    internal const int PeSectionRawSizeOffset = 16;
    internal const int PeSectionRawPointerOffset = 20;
    internal const int PeSectionCharacteristicsOffset = 36;

    internal const int TeHeaderBytes = 40;
    internal const int TeMachineOffset = 2;
    internal const int TeNumberOfSectionsOffset = 4;
    internal const int TeSubsystemOffset = 5;
    internal const int TeStrippedSizeOffset = 6;

    internal const int MaximumExecutableSections = 96;
}

internal static class UefiDriverInspectionPolicy
{
    // A parsed FFS can never legitimately exceed the maximum firmware image accepted by the app.
    // Keep this shared defensive allocation limit tied to the image-size policy rather than
    // duplicating another magic byte count in the driver-update catalog loader.
    internal const int MaximumFfsFileBytes = BiosImageLoader.MaxImageBytes;
    internal const int MaximumDrivers = 4096;
    internal const int MaximumSections = 65_536;
    internal const int MaximumSectionDepth = 8;
    internal const int MaximumExpandedSectionBytes = 16 * 1024 * 1024;
    internal const int TotalExpansionBudgetBytes = 128 * 1024 * 1024;
    internal const int DecoderReadBufferBytes = 64 * 1024;
    internal const int MaximumNameCharacters = 512;
}

internal readonly record struct UefiFfsVolumeLayout(
    int Start,
    int End,
    int FirstFileOffset,
    byte EraseByte);

internal readonly record struct UefiFfsFileLocation(
    Guid Guid,
    byte Type,
    byte Attributes,
    int Offset,
    int Size,
    int HeaderSize,
    int NextOffset,
    FfsFileState State);

internal static class UefiFfsVolumeScanner
{
    internal static bool TryGetLayout(ReadOnlySpan<byte> source, FirmwareVolume volume, out UefiFfsVolumeLayout layout)
    {
        layout = default;
        if (volume.Offset < 0 || volume.Length < UefiFirmwareSpecification.FirmwareVolumeMinimumLengthBytes ||
            volume.Offset > int.MaxValue || volume.Length > int.MaxValue)
        {
            return false;
        }

        int start = (int)volume.Offset;
        int length = (int)volume.Length;
        if (start > source.Length || length > source.Length - start)
        {
            return false;
        }
        int end = start + length;

        int headerLength = BinaryPrimitives.ReadUInt16LittleEndian(
            source[(start + UefiFirmwareSpecification.FirmwareVolumeHeaderLengthOffset)..]);
        if (headerLength < UefiFirmwareSpecification.FirmwareVolumeMinimumHeaderBytes || headerLength > length)
        {
            return false;
        }

        int relativeFileStart = headerLength;
        int extendedHeaderOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            source[(start + UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderOffsetOffset)..]);
        if (extendedHeaderOffset != 0)
        {
            if (extendedHeaderOffset < UefiFirmwareSpecification.FirmwareVolumeMinimumHeaderBytes ||
                extendedHeaderOffset > length - UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderMinimumBytes)
            {
                return false;
            }

            uint rawExtendedHeaderSize = BinaryPrimitives.ReadUInt32LittleEndian(
                source[(start + extendedHeaderOffset + UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderSizeOffset)..]);
            if (rawExtendedHeaderSize > int.MaxValue)
            {
                return false;
            }

            int extendedHeaderSize = (int)rawExtendedHeaderSize;
            if (extendedHeaderSize < UefiFirmwareSpecification.FirmwareVolumeExtendedHeaderMinimumBytes ||
                extendedHeaderSize > length ||
                extendedHeaderOffset > length - extendedHeaderSize)
            {
                return false;
            }
            relativeFileStart = Math.Max(relativeFileStart, extendedHeaderOffset + extendedHeaderSize);
        }

        if (relativeFileStart > length || !TryAlign(
                start,
                start + relativeFileStart,
                AmiSecureBootSpecification.FfsAlignmentBytes,
                out int firstFileOffset) ||
            firstFileOffset > end)
        {
            return false;
        }

        uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(
            source[(start + UefiFirmwareSpecification.FirmwareVolumeAttributesOffset)..]);
        byte eraseByte = (attributes & UefiFirmwareSpecification.FirmwareVolumeErasePolarityMask) != 0
            ? byte.MaxValue
            : byte.MinValue;
        layout = new(start, end, firstFileOffset, eraseByte);
        return true;
    }

    internal static bool TryReadFiles(
        ReadOnlySpan<byte> source,
        FirmwareVolume volume,
        CancellationToken token,
        out UefiFfsVolumeLayout layout,
        out IReadOnlyList<UefiFfsFileLocation> files)
    {
        files = [];
        if (!TryGetLayout(source, volume, out layout))
        {
            return false;
        }

        var result = new List<UefiFfsFileLocation>();
        int cursor = layout.FirstFileOffset;
        while (cursor <= layout.End - AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            token.ThrowIfCancellationRequested();
            ReadOnlySpan<byte> possibleHeader = source.Slice(cursor, AmiSecureBootSpecification.FfsFileHeaderBytes);
            if (IsFilled(possibleHeader, layout.EraseByte))
            {
                files = result;
                return true;
            }

            if (result.Count >= SecureBootRepairPolicy.MaximumFilesPerFirmwareVolume ||
                !UefiFfsFileParser.TryRead(source, cursor, layout.End, layout.EraseByte, out FfsFileHeaderInfo header))
            {
                files = result;
                return false;
            }

            if (header.Size <= 0 ||
                cursor > layout.End - header.Size ||
                !TryAlign(
                    layout.Start,
                    cursor + header.Size,
                    AmiSecureBootSpecification.FfsAlignmentBytes,
                    out int next) ||
                next <= cursor ||
                next > layout.End)
            {
                files = result;
                return false;
            }

            result.Add(new(
                header.Guid,
                header.Type,
                header.Attributes,
                cursor,
                header.Size,
                header.HeaderSize,
                next,
                header.State));
            cursor = next;
        }

        files = result;
        return cursor == layout.End || IsFilled(source[cursor..layout.End], layout.EraseByte);
    }

    internal static int Align(int baseOffset, int value, int alignment)
    {
        if (alignment <= 0 || (alignment & (alignment - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(alignment));
        }
        if (!TryAlign(baseOffset, value, alignment, out int aligned))
        {
            throw new OverflowException();
        }
        return aligned;
    }

    private static bool TryAlign(int baseOffset, int value, int alignment, out int aligned)
    {
        aligned = 0;
        if (alignment <= 0 || (alignment & (alignment - 1)) != 0 || value < baseOffset)
        {
            return false;
        }

        long relative = (long)value - baseOffset;
        long rounded = (relative + alignment - 1L) & ~(alignment - 1L);
        long result = baseOffset + rounded;
        if (result is < int.MinValue or > int.MaxValue)
        {
            return false;
        }

        aligned = (int)result;
        return true;
    }

    private static bool IsFilled(ReadOnlySpan<byte> source, byte value)
    {
        foreach (byte item in source)
        {
            if (item != value)
            {
                return false;
            }
        }
        return true;
    }
}

internal sealed record KnownUefiDriverVulnerability(
    Guid FileGuid,
    string Sha256,
    string Id,
    string Source);

internal static class UefiDriverVulnerabilityCatalog
{
    private const string FileName = "uefi-driver-vulnerabilities.json";
    private static readonly string ResourceName = EmbeddedResourceNames.File(EmbeddedResourceNames.FirmwareFolder, FileName);
    private static readonly IReadOnlyDictionary<Guid, KnownUefiDriverVulnerability[]> EntriesByGuid = Load();

    internal static IReadOnlyList<KnownUefiDriverVulnerability> Match(
        Guid fileGuid,
        string fileSha256,
        IReadOnlyList<UefiExecutableInfo> executables)
    {
        if (!EntriesByGuid.TryGetValue(fileGuid, out KnownUefiDriverVulnerability[]? entries))
        {
            return [];
        }

        var matches = new List<KnownUefiDriverVulnerability>();
        foreach (KnownUefiDriverVulnerability entry in entries)
        {
            if (string.Equals(entry.Sha256, fileSha256, StringComparison.Ordinal))
            {
                matches.Add(entry);
                continue;
            }
            foreach (UefiExecutableInfo executable in executables)
            {
                if (string.Equals(entry.Sha256, executable.Sha256, StringComparison.Ordinal))
                {
                    matches.Add(entry);
                    break;
                }
            }
        }
        return matches;
    }

    private static IReadOnlyDictionary<Guid, KnownUefiDriverVulnerability[]> Load()
    {
        using Stream resource = typeof(UefiDriverVulnerabilityCatalog).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidDataException(OperationError.UefiDriverCatalog);
        KnownUefiDriverVulnerability[] entries = JsonSerializer.Deserialize<KnownUefiDriverVulnerability[]>(resource)
            ?? throw new InvalidDataException(OperationError.UefiDriverCatalog);

        var normalized = new List<KnownUefiDriverVulnerability>(entries.Length);
        var identities = new HashSet<(Guid Guid, string Hash, string Id)>();
        foreach (KnownUefiDriverVulnerability entry in entries)
        {
            if (entry.FileGuid == Guid.Empty || string.IsNullOrWhiteSpace(entry.Id) ||
                !Uri.TryCreate(entry.Source, UriKind.Absolute, out Uri? source) || source.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidDataException(OperationError.UefiDriverCatalog);
            }

            string hash = Sha256Identity.Normalize(entry.Sha256, OperationError.UefiDriverCatalog);
            string id = entry.Id.Trim();
            var item = entry with { Sha256 = hash, Id = id, Source = source.AbsoluteUri };
            if (!identities.Add((item.FileGuid, item.Sha256, item.Id)))
            {
                throw new InvalidDataException(OperationError.UefiDriverCatalog);
            }
            normalized.Add(item);
        }

        return normalized
            .GroupBy(entry => entry.FileGuid)
            .ToDictionary(group => group.Key, group => group.ToArray());
    }
}

/// <summary>
/// Structural and indicator-based inspection of active PI FFS DXE/MM drivers.
/// </summary>
public static class UefiDriverInspector
{
    public static UefiDriverReport Inspect(
        ReadOnlySpan<byte> source,
        IReadOnlyList<FirmwareVolume> volumes,
        CancellationToken token = default) =>
        Inspect(source, volumes, observer: null, token);

    internal static UefiDriverReport Inspect(
        ReadOnlySpan<byte> source,
        IReadOnlyList<FirmwareVolume> volumes,
        IUefiExecutableObserver? observer,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(volumes);
        var context = new InspectionContext();
        var drivers = new List<UefiDriverInfo>();
        int incompleteVolumes = 0;

        foreach (FirmwareVolume volume in volumes)
        {
            token.ThrowIfCancellationRequested();
            if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem))
            {
                continue;
            }

            bool complete = UefiFfsVolumeScanner.TryReadFiles(source, volume, token, out _, out IReadOnlyList<UefiFfsFileLocation> files);
            if (!complete)
            {
                context.Incomplete = true;
                incompleteVolumes++;
            }

            foreach (UefiFfsFileLocation file in files)
            {
                token.ThrowIfCancellationRequested();
                if (file.State != FfsFileState.DataValid || !TryDriverKind(file.Type, out UefiDriverKind kind))
                {
                    continue;
                }
                if (drivers.Count >= UefiDriverInspectionPolicy.MaximumDrivers)
                {
                    context.Incomplete = true;
                    return FinalizeReport(drivers, context, Math.Max(1, incompleteVolumes));
                }

                drivers.Add(InspectDriver(source, file, volume.Offset, volume.FileSystem, kind, context, observer, token));
            }
        }

        return FinalizeReport(drivers, context, incompleteVolumes);
    }

    internal static bool TryInspectFfs(
        ReadOnlySpan<byte> ffs,
        byte eraseByte,
        long volumeOffset,
        Guid volumeFileSystem,
        long logicalFileOffset,
        CancellationToken token,
        out UefiDriverInfo driver)
    {
        driver = default!;
        if (ffs.Length < AmiSecureBootSpecification.FfsFileHeaderBytes ||
            !UefiFfsFileParser.TryRead(ffs, 0, ffs.Length, eraseByte, out FfsFileHeaderInfo header) ||
            header.Size != ffs.Length || header.State != FfsFileState.DataValid ||
            !TryDriverKind(header.Type, out UefiDriverKind kind))
        {
            return false;
        }

        var context = new InspectionContext();
        var location = new UefiFfsFileLocation(
            header.Guid,
            header.Type,
            header.Attributes,
            0,
            header.Size,
            header.HeaderSize,
            header.Size,
            header.State);
        UefiDriverInfo inspected = InspectDriver(
            ffs,
            location,
            volumeOffset,
            volumeFileSystem,
            kind,
            context,
            observer: null,
            token);
        driver = inspected with { FileOffset = logicalFileOffset };
        return true;
    }

    private static UefiDriverReport FinalizeReport(
        List<UefiDriverInfo> drivers,
        InspectionContext context,
        int incompleteVolumes)
    {
        HashSet<(long VolumeOffset, Guid Guid)> duplicates = drivers
            .GroupBy(driver => (driver.VolumeOffset, driver.FileGuid))
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToHashSet();

        if (duplicates.Count != 0)
        {
            for (int index = 0; index < drivers.Count; index++)
            {
                UefiDriverInfo driver = drivers[index];
                if (!duplicates.Contains((driver.VolumeOffset, driver.FileGuid)))
                {
                    continue;
                }
                string[] issues = driver.Issues
                    .Append(UefiDriverIssueCode.DuplicateFileGuid)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                drivers[index] = driver with
                {
                    Issues = issues,
                    SecurityStatus = driver.SecurityStatus == UefiDriverSecurityStatus.Unknown
                        ? UefiDriverSecurityStatus.Unknown
                        : Status(driver.VulnerabilityIds.Count != 0, incomplete: false, issues)
                };
            }
        }

        return new(
            drivers
                .OrderBy(driver => driver.SecurityStatus)
                .ThenBy(driver => driver.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(driver => driver.FileGuid)
                .ToArray(),
            context.Incomplete || drivers.Any(driver => driver.SecurityStatus == UefiDriverSecurityStatus.Unknown),
            incompleteVolumes);
    }

    private static UefiDriverInfo InspectDriver(
        ReadOnlySpan<byte> source,
        UefiFfsFileLocation file,
        long volumeOffset,
        Guid volumeFileSystem,
        UefiDriverKind kind,
        InspectionContext context,
        IUefiExecutableObserver? observer,
        CancellationToken token)
    {
        ReadOnlySpan<byte> fileBytes = source.Slice(file.Offset, file.Size);
        string fileHash = Convert.ToHexString(SHA256.HashData(fileBytes));
        var scan = new DriverSectionScan
        {
            Observer = observer,
            Observation = new UefiExecutableObservation(
                file.Guid,
                volumeOffset,
                file.Offset,
                file.Type,
                default)
        };
        ScanSections(fileBytes[file.HeaderSize..], scan, context, 0, token);
        ValidateSectionRules(kind, scan);

        if (scan.Executables.Count == 0 && !scan.Incomplete)
        {
            scan.Issues.Add(UefiDriverIssueCode.MissingExecutable);
        }

        IReadOnlyList<KnownUefiDriverVulnerability> vulnerabilities = UefiDriverVulnerabilityCatalog.Match(
            file.Guid,
            fileHash,
            scan.Executables);
        if (vulnerabilities.Count != 0)
        {
            scan.Issues.Add(UefiDriverIssueCode.KnownVulnerable);
        }

        string[] issues = scan.Issues.Distinct(StringComparer.Ordinal).ToArray();
        string[] vulnerabilityIds = vulnerabilities
            .Select(vulnerability => vulnerability.Id)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToArray();
        return new(
            file.Guid,
            kind,
            scan.Name,
            scan.Version,
            scan.BuildNumber,
            volumeOffset,
            volumeFileSystem,
            file.Offset,
            file.Size,
            file.HeaderSize,
            file.Type,
            file.Attributes,
            AmiSecureBootSpecification.RequiredDataAlignment(file.Attributes),
            AmiSecureBootSpecification.IsFixed(file.Attributes),
            scan.Sections,
            scan.CompressionSections,
            scan.GuidedSections,
            scan.DxeDepexSections + scan.PeiDepexSections + scan.MmDepexSections,
            scan.DependencyHashes.ToArray(),
            fileHash,
            Status(vulnerabilityIds.Length != 0, scan.Incomplete, issues),
            issues,
            vulnerabilityIds,
            scan.Executables.ToArray());
    }

    private static UefiDriverSecurityStatus Status(bool knownVulnerable, bool incomplete, IReadOnlyList<string> issues)
    {
        if (knownVulnerable)
        {
            return UefiDriverSecurityStatus.KnownVulnerable;
        }
        if (incomplete || issues.Contains(UefiDriverIssueCode.MalformedExecutable, StringComparer.Ordinal) ||
            issues.Contains(UefiDriverIssueCode.UnsupportedGuidedSection, StringComparer.Ordinal) ||
            issues.Contains(UefiDriverIssueCode.InvalidSectionStream, StringComparer.Ordinal))
        {
            return UefiDriverSecurityStatus.Unknown;
        }
        if (issues.Count != 0)
        {
            return UefiDriverSecurityStatus.ReviewRecommended;
        }
        return UefiDriverSecurityStatus.NoKnownIssues;
    }

    private static void ValidateSectionRules(UefiDriverKind kind, DriverSectionScan scan)
    {
        // Observed excess/forbidden sections are conclusive even when another encapsulation is unreadable.
        bool invalid = scan.TeSections != 0 || scan.VersionSections > 1 || scan.UserInterfaceSections > 1;

        if (kind == UefiDriverKind.Dxe)
        {
            invalid |= scan.DxeDepexSections > 1;
        }
        else if (kind == UefiDriverKind.CombinedPeimDxe)
        {
            invalid |= scan.DxeDepexSections > 1 || scan.PeiDepexSections > 1;
        }
        else if (kind == UefiDriverKind.CombinedMmDxe)
        {
            invalid |= scan.DxeDepexSections > 1 || scan.MmDepexSections > 1;
        }
        else if (kind is UefiDriverKind.Mm or UefiDriverKind.MmStandalone)
        {
            invalid |= scan.MmDepexSections > 1;
        }

        // Missing PE32 wrappers are not treated as a security finding here. Some shipping OEM
        // firmware stores a valid PE image in a FREEFORM_SUBTYPE_GUID section. The scanner
        // still requires a readable executable before a driver can be considered inspected.

        if (invalid)
        {
            scan.Issues.Add(UefiDriverIssueCode.FileTypeSectionRulesViolation);
        }
    }

    private static void ScanSections(
        ReadOnlySpan<byte> sections,
        DriverSectionScan scan,
        InspectionContext context,
        int depth,
        CancellationToken token)
    {
        if (depth > UefiDriverInspectionPolicy.MaximumSectionDepth)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
            return;
        }

        int offset = 0;
        while (offset <= sections.Length - UefiPiCode.CommonSectionHeaderBytes)
        {
            token.ThrowIfCancellationRequested();
            if (++context.Sections > UefiDriverInspectionPolicy.MaximumSections)
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }

            if (!TryReadSectionHeader(sections, offset, out int sectionSize, out int commonHeaderSize, out byte type))
            {
                if (!IsPadding(sections[offset..]))
                {
                    MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                }
                return;
            }

            scan.Sections++;
            ReadOnlySpan<byte> section = sections.Slice(offset, sectionSize);
            ReadOnlySpan<byte> payload = section[commonHeaderSize..];
            switch (type)
            {
                case UefiPiCode.SectionPe32:
                    AddExecutable(payload, UefiExecutableFormat.Pe32, scan);
                    break;
                case UefiPiCode.SectionTe:
                    scan.TeSections++;
                    AddExecutable(payload, UefiExecutableFormat.Te, scan);
                    break;
                case UefiPiCode.SectionDxeDepex:
                    scan.DxeDepexSections++;
                    scan.DependencyHashes.Add(Convert.ToHexString(SHA256.HashData(payload)));
                    break;
                case UefiPiCode.SectionPeiDepex:
                    scan.PeiDepexSections++;
                    scan.DependencyHashes.Add(Convert.ToHexString(SHA256.HashData(payload)));
                    break;
                case UefiPiCode.SectionMmDepex:
                    scan.MmDepexSections++;
                    scan.DependencyHashes.Add(Convert.ToHexString(SHA256.HashData(payload)));
                    break;
                case UefiPiCode.SectionUserInterface:
                    scan.UserInterfaceSections++;
                    scan.Name ??= DecodeUnicodeText(payload);
                    break;
                case UefiPiCode.SectionVersion:
                    scan.VersionSections++;
                    if (payload.Length >= sizeof(ushort))
                    {
                        scan.BuildNumber ??= BinaryPrimitives.ReadUInt16LittleEndian(payload);
                        scan.Version ??= DecodeUnicodeText(payload[sizeof(ushort)..]);
                    }
                    break;
                case UefiPiCode.SectionFreeformSubtypeGuid:
                    ScanFreeformSubtypeGuid(payload, scan, context);
                    break;
                case UefiPiCode.SectionGuidDefined:
                    scan.GuidedSections++;
                    ScanGuidedSection(section, commonHeaderSize, scan, context, depth, token);
                    break;
                case UefiPiCode.SectionCompression:
                    scan.CompressionSections++;
                    ScanCompressionSection(section, commonHeaderSize, scan, context, depth, token);
                    break;
                case UefiPiCode.SectionDisposable:
                    ScanSections(payload, scan, context, depth + 1, token);
                    break;
            }

            int next = AlignSection(checked(offset + sectionSize));
            if (next <= offset || next > sections.Length)
            {
                if (offset + sectionSize != sections.Length)
                {
                    MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                }
                return;
            }
            offset = next;
        }

        if (offset < sections.Length && !IsPadding(sections[offset..]))
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
        }
    }

    private static void ScanGuidedSection(
        ReadOnlySpan<byte> section,
        int commonHeaderSize,
        DriverSectionScan scan,
        InspectionContext context,
        int depth,
        CancellationToken token)
    {
        int fixedBytes = checked(commonHeaderSize + UefiPiCode.GuidedDefinitionBytes +
            UefiPiCode.GuidedDataOffsetBytes + UefiPiCode.GuidedAttributesBytes);
        if (section.Length < fixedBytes)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
            return;
        }

        Guid definition = new(section.Slice(commonHeaderSize, UefiPiCode.GuidedDefinitionBytes));
        int dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(section[(commonHeaderSize + UefiPiCode.GuidedDefinitionBytes)..]);
        ushort attributes = BinaryPrimitives.ReadUInt16LittleEndian(
            section[(commonHeaderSize + UefiPiCode.GuidedDefinitionBytes + UefiPiCode.GuidedDataOffsetBytes)..]);
        if ((attributes & ~UefiPiCode.GuidedKnownAttributesMask) != 0)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
            return;
        }
        if (dataOffset < fixedBytes || dataOffset > section.Length)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
            return;
        }

        ReadOnlySpan<byte> guidedData = section[dataOffset..];
        if (definition == UefiPiCode.TianoCustomDecompressGuid)
        {
            if (!EfiCompressionDecoder.TryGetExpandedSize(
                    guidedData,
                    UefiDriverInspectionPolicy.MaximumExpandedSectionBytes,
                    out int expandedLength) ||
                expandedLength <= 0 || expandedLength > context.ExpansionBudget)
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }

            context.ExpansionBudget -= expandedLength;
            if (!EfiCompressionDecoder.TryDecompressTiano(
                    guidedData,
                    expandedLength,
                    UefiDriverInspectionPolicy.MaximumExpandedSectionBytes,
                    token,
                    out byte[] expanded))
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }

            ScanSections(expanded, scan, context, depth + 1, token);
            return;
        }

        if (definition == AmiSecureBootSpecification.LzmaGuidedSectionDefinition)
        {
            if (!TryDecodeLzma(guidedData, context, token, out byte[] expanded))
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }
            ScanSections(expanded, scan, context, depth + 1, token);
            return;
        }

        if ((attributes & UefiPiCode.GuidedProcessingRequired) != 0)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.UnsupportedGuidedSection);
            return;
        }

        ScanSections(guidedData, scan, context, depth + 1, token);
    }

    private static void ScanCompressionSection(
        ReadOnlySpan<byte> section,
        int commonHeaderSize,
        DriverSectionScan scan,
        InspectionContext context,
        int depth,
        CancellationToken token)
    {
        int fixedBytes = checked(commonHeaderSize + UefiPiCode.CompressionUncompressedLengthBytes + UefiPiCode.CompressionTypeBytes);
        if (section.Length < fixedBytes)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
            return;
        }

        uint expandedSize = BinaryPrimitives.ReadUInt32LittleEndian(section[commonHeaderSize..]);
        byte compressionType = section[commonHeaderSize + UefiPiCode.CompressionUncompressedLengthBytes];
        ReadOnlySpan<byte> nested = section[fixedBytes..];
        if (compressionType == UefiPiCode.CompressionNone)
        {
            if (expandedSize != nested.Length)
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }
            ScanSections(nested, scan, context, depth + 1, token);
            return;
        }

        if (compressionType == UefiPiCode.CompressionStandard)
        {
            if (expandedSize == 0 || expandedSize > UefiDriverInspectionPolicy.MaximumExpandedSectionBytes ||
                expandedSize > context.ExpansionBudget)
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }

            int expandedLength = checked((int)expandedSize);
            context.ExpansionBudget -= expandedLength;
            if (!EfiCompressionDecoder.TryDecompressEfi(
                    nested,
                    expandedLength,
                    UefiDriverInspectionPolicy.MaximumExpandedSectionBytes,
                    token,
                    out byte[] expanded))
            {
                MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
                return;
            }

            ScanSections(expanded, scan, context, depth + 1, token);
            return;
        }

        MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
    }

    private static void ScanFreeformSubtypeGuid(
        ReadOnlySpan<byte> payload,
        DriverSectionScan scan,
        InspectionContext context)
    {
        if (payload.Length < UefiPiCode.FreeformSubtypeGuidBytes)
        {
            MarkIncomplete(scan, context, UefiDriverIssueCode.InvalidSectionStream);
            return;
        }

        ReadOnlySpan<byte> data = payload[UefiPiCode.FreeformSubtypeGuidBytes..];
        if (data.Length >= sizeof(ushort) && BinaryPrimitives.ReadUInt16LittleEndian(data) == UefiPiCode.DosMagic)
        {
            AddExecutable(data, UefiExecutableFormat.Pe32, scan, malformedIsIssue: false);
            return;
        }
        if (data.Length >= sizeof(ushort) && BinaryPrimitives.ReadUInt16LittleEndian(data) == UefiPiCode.TeSignature)
        {
            AddExecutable(data, UefiExecutableFormat.Te, scan, malformedIsIssue: false);
        }
    }

    private static bool TryDecodeLzma(
        ReadOnlySpan<byte> payload,
        InspectionContext context,
        CancellationToken token,
        out byte[] expanded)
    {
        expanded = [];
        if (payload.Length < AmiSecureBootSpecification.LzmaHeaderBytes ||
            payload[0] > AmiSecureBootSpecification.MaximumValidLzmaPropertiesByte)
        {
            return false;
        }

        long expandedLength = BinaryPrimitives.ReadInt64LittleEndian(
            payload[AmiSecureBootSpecification.LzmaUncompressedSizeOffset..]);
        uint dictionarySize = BinaryPrimitives.ReadUInt32LittleEndian(
            payload[AmiSecureBootSpecification.LzmaDictionarySizeOffset..]);
        if (expandedLength < 1 || expandedLength > UefiDriverInspectionPolicy.MaximumExpandedSectionBytes ||
            expandedLength > context.ExpansionBudget || dictionarySize > UefiDriverInspectionPolicy.MaximumExpandedSectionBytes)
        {
            return false;
        }

        context.ExpansionBudget -= checked((int)expandedLength);
        try
        {
            using var input = new MemoryStream(payload[AmiSecureBootSpecification.LzmaHeaderBytes..].ToArray(), writable: false);
            using var decoder = LzmaStream.Create(
                payload[..AmiSecureBootSpecification.LzmaPropertiesBytes].ToArray(),
                input,
                input.Length,
                expandedLength);
            expanded = new byte[checked((int)expandedLength)];
            int written = 0;
            while (written < expanded.Length)
            {
                token.ThrowIfCancellationRequested();
                int count = decoder.Read(expanded, written,
                    Math.Min(UefiDriverInspectionPolicy.DecoderReadBufferBytes, expanded.Length - written));
                if (count == 0)
                {
                    expanded = [];
                    return false;
                }
                written += count;
            }
            return true;
        }
        catch (Exception error) when (FirmwareCompressionFailure.IsMalformedInput(error))
        {
            expanded = [];
            return false;
        }
    }

    private static bool AddExecutable(
        ReadOnlySpan<byte> image,
        UefiExecutableFormat format,
        DriverSectionScan scan,
        bool malformedIsIssue = true)
    {
        UefiMachine machine;
        UefiExecutableSubsystem subsystem;
        bool nxCompatible = false;
        bool dynamicBase = false;
        int sectionCount;
        bool writableExecutable;
        bool valid;
        if (format == UefiExecutableFormat.Pe32)
        {
            valid = TryInspectPe(image, out machine, out subsystem, out sectionCount, out nxCompatible, out dynamicBase,
                out writableExecutable);
        }
        else
        {
            valid = TryInspectTe(image, out machine, out subsystem, out sectionCount, out writableExecutable);
        }

        string hash = Convert.ToHexString(SHA256.HashData(image));
        if (!valid)
        {
            if (malformedIsIssue)
            {
                scan.Issues.Add(UefiDriverIssueCode.MalformedExecutable);
                scan.Incomplete = true;
                scan.Executables.Add(new(format, hash, UefiMachine.Unknown, UefiExecutableSubsystem.Unknown,
                    image.Length, 0, false, null, null, false));
            }
            return false;
        }

        if (writableExecutable)
        {
            scan.Issues.Add(UefiDriverIssueCode.WritableExecutableSection);
        }

        if (scan.Observer is not null)
        {
            UefiExecutableObservation observation = scan.Observation with { Format = format };
            scan.Observer.Observe(in observation, image);
        }

        if (!scan.Executables.Any(item => item.Format == format &&
            string.Equals(item.Sha256, hash, StringComparison.Ordinal)))
        {
            scan.Executables.Add(new(
                format,
                hash,
                machine,
                subsystem,
                image.Length,
                sectionCount,
                true,
                format == UefiExecutableFormat.Pe32 ? nxCompatible : null,
                format == UefiExecutableFormat.Pe32 ? dynamicBase : null,
                writableExecutable));
        }
        return true;
    }

    private static bool TryInspectPe(
        ReadOnlySpan<byte> image,
        out UefiMachine machine,
        out UefiExecutableSubsystem subsystem,
        out int sectionCount,
        out bool nxCompatible,
        out bool dynamicBase,
        out bool writableExecutable)
    {
        machine = UefiMachine.Unknown;
        subsystem = UefiExecutableSubsystem.Unknown;
        sectionCount = 0;
        nxCompatible = false;
        dynamicBase = false;
        writableExecutable = false;
        if (image.Length < UefiPiCode.DosPeOffsetOffset + sizeof(int) ||
            BinaryPrimitives.ReadUInt16LittleEndian(image) != UefiPiCode.DosMagic)
        {
            return false;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(image[UefiPiCode.DosPeOffsetOffset..]);
        int minimumPeBytes = UefiPiCode.PeOptionalHeaderOffset + UefiPiCode.PeOptionalDllCharacteristicsOffset + sizeof(ushort);
        if (peOffset < 0 || peOffset > image.Length - minimumPeBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(image[peOffset..]) != UefiPiCode.PeSignature)
        {
            return false;
        }

        ushort machineValue = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeMachineOffset)..]);
        sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeNumberOfSectionsOffset)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeOptionalHeaderSizeOffset)..]);
        int optionalOffset = checked(peOffset + UefiPiCode.PeOptionalHeaderOffset);
        if (sectionCount is < 1 or > UefiPiCode.MaximumExecutableSections ||
            optionalSize < UefiPiCode.PeOptionalDllCharacteristicsOffset + sizeof(ushort) ||
            optionalOffset > image.Length - optionalSize)
        {
            return false;
        }

        ushort optionalMagic = BinaryPrimitives.ReadUInt16LittleEndian(image[optionalOffset..]);
        if (optionalMagic is not (UefiPiCode.PeOptionalMagic32 or UefiPiCode.PeOptionalMagic64))
        {
            return false;
        }

        ushort subsystemValue = BinaryPrimitives.ReadUInt16LittleEndian(
            image[(optionalOffset + UefiPiCode.PeOptionalSubsystemOffset)..]);
        ushort dllCharacteristics = BinaryPrimitives.ReadUInt16LittleEndian(
            image[(optionalOffset + UefiPiCode.PeOptionalDllCharacteristicsOffset)..]);
        int sectionHeadersOffset = checked(optionalOffset + optionalSize);
        int sectionHeadersBytes = checked(sectionCount * UefiPiCode.PeSectionHeaderBytes);
        if (sectionHeadersOffset > image.Length - sectionHeadersBytes)
        {
            return false;
        }

        for (int index = 0; index < sectionCount; index++)
        {
            int sectionOffset = checked(sectionHeadersOffset + index * UefiPiCode.PeSectionHeaderBytes);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(image[(sectionOffset + UefiPiCode.PeSectionRawSizeOffset)..]);
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(image[(sectionOffset + UefiPiCode.PeSectionRawPointerOffset)..]);
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(
                image[(sectionOffset + UefiPiCode.PeSectionCharacteristicsOffset)..]);
            if (rawSize != 0 && (rawPointer > (uint)image.Length || rawSize > (uint)image.Length - rawPointer))
            {
                return false;
            }
            if ((characteristics & UefiPiCode.PeSectionMemExecute) != 0 &&
                (characteristics & UefiPiCode.PeSectionMemWrite) != 0)
            {
                writableExecutable = true;
            }
        }

        machine = Machine(machineValue);
        subsystem = Subsystem(subsystemValue);
        nxCompatible = (dllCharacteristics & UefiPiCode.PeDllNxCompatible) != 0;
        dynamicBase = (dllCharacteristics & UefiPiCode.PeDllDynamicBase) != 0;
        return true;
    }

    private static bool TryInspectTe(
        ReadOnlySpan<byte> image,
        out UefiMachine machine,
        out UefiExecutableSubsystem subsystem,
        out int sectionCount,
        out bool writableExecutable)
    {
        machine = UefiMachine.Unknown;
        subsystem = UefiExecutableSubsystem.Unknown;
        sectionCount = 0;
        writableExecutable = false;
        if (image.Length < UefiPiCode.TeHeaderBytes ||
            BinaryPrimitives.ReadUInt16LittleEndian(image) != UefiPiCode.TeSignature)
        {
            return false;
        }

        ushort machineValue = BinaryPrimitives.ReadUInt16LittleEndian(image[UefiPiCode.TeMachineOffset..]);
        sectionCount = image[UefiPiCode.TeNumberOfSectionsOffset];
        ushort strippedSize = BinaryPrimitives.ReadUInt16LittleEndian(image[UefiPiCode.TeStrippedSizeOffset..]);
        if (sectionCount is < 1 or > UefiPiCode.MaximumExecutableSections || strippedSize < UefiPiCode.TeHeaderBytes)
        {
            return false;
        }

        int sectionHeadersBytes = checked(sectionCount * UefiPiCode.PeSectionHeaderBytes);
        if (UefiPiCode.TeHeaderBytes > image.Length - sectionHeadersBytes)
        {
            return false;
        }
        int strippedAdjustment = strippedSize - UefiPiCode.TeHeaderBytes;
        for (int index = 0; index < sectionCount; index++)
        {
            int sectionOffset = checked(UefiPiCode.TeHeaderBytes + index * UefiPiCode.PeSectionHeaderBytes);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(image[(sectionOffset + UefiPiCode.PeSectionRawSizeOffset)..]);
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(image[(sectionOffset + UefiPiCode.PeSectionRawPointerOffset)..]);
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(
                image[(sectionOffset + UefiPiCode.PeSectionCharacteristicsOffset)..]);
            long adjustedPointer = (long)rawPointer - strippedAdjustment;
            if (rawSize != 0 && (adjustedPointer < 0 || adjustedPointer > image.Length || (long)rawSize > image.Length - adjustedPointer))
            {
                return false;
            }
            if ((characteristics & UefiPiCode.PeSectionMemExecute) != 0 &&
                (characteristics & UefiPiCode.PeSectionMemWrite) != 0)
            {
                writableExecutable = true;
            }
        }

        machine = Machine(machineValue);
        subsystem = Subsystem(image[UefiPiCode.TeSubsystemOffset]);
        return true;
    }

    private static bool TryReadSectionHeader(
        ReadOnlySpan<byte> sections,
        int offset,
        out int sectionSize,
        out int headerSize,
        out byte type)
    {
        sectionSize = 0;
        headerSize = 0;
        type = 0;
        if (offset < 0 || offset > sections.Length - UefiPiCode.CommonSectionHeaderBytes)
        {
            return false;
        }

        int encoded = ReadU24(sections, offset);
        type = sections[offset + AmiSecureBootSpecification.SectionTypeOffset];
        if (encoded == AmiSecureBootSpecification.U24ExtendedSizeMarker)
        {
            if (offset > sections.Length - UefiPiCode.ExtendedSectionHeaderBytes)
            {
                return false;
            }
            uint extended = BinaryPrimitives.ReadUInt32LittleEndian(sections[(offset + UefiPiCode.ExtendedSectionSizeOffset)..]);
            if (extended > int.MaxValue)
            {
                return false;
            }
            sectionSize = checked((int)extended);
            headerSize = UefiPiCode.ExtendedSectionHeaderBytes;
        }
        else
        {
            sectionSize = encoded;
            headerSize = UefiPiCode.CommonSectionHeaderBytes;
        }

        return sectionSize >= headerSize && sectionSize <= sections.Length - offset;
    }

    private static string? DecodeUnicodeText(ReadOnlySpan<byte> payload)
    {
        int bytes = payload.Length & ~1;
        while (bytes >= sizeof(char) && payload[bytes - 1] == 0 && payload[bytes - 2] == 0)
        {
            bytes -= sizeof(char);
        }
        if (bytes == 0)
        {
            return null;
        }

        int maximumBytes = checked(UefiDriverInspectionPolicy.MaximumNameCharacters * sizeof(char));
        bytes = Math.Min(bytes, maximumBytes);
        string value = Encoding.Unicode.GetString(payload[..bytes]).Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static UefiMachine Machine(ushort value) => value switch
    {
        UefiPiCode.PeMachineIa32 => UefiMachine.Ia32,
        UefiPiCode.PeMachineX64 => UefiMachine.X64,
        UefiPiCode.PeMachineItanium => UefiMachine.Itanium,
        UefiPiCode.PeMachineArm or UefiPiCode.PeMachineArmNt => UefiMachine.Arm,
        UefiPiCode.PeMachineArm64 => UefiMachine.Arm64,
        _ => UefiMachine.Unknown
    };

    private static UefiExecutableSubsystem Subsystem(ushort value) => value switch
    {
        UefiPiCode.PeSubsystemEfiApplication => UefiExecutableSubsystem.EfiApplication,
        UefiPiCode.PeSubsystemEfiBootServiceDriver => UefiExecutableSubsystem.EfiBootServiceDriver,
        UefiPiCode.PeSubsystemEfiRuntimeDriver => UefiExecutableSubsystem.EfiRuntimeDriver,
        UefiPiCode.PeSubsystemEfiRom => UefiExecutableSubsystem.EfiRom,
        _ => UefiExecutableSubsystem.Unknown
    };

    private static bool TryDriverKind(byte type, out UefiDriverKind kind)
    {
        kind = type switch
        {
            UefiPiCode.FfsDriver => UefiDriverKind.Dxe,
            UefiPiCode.FfsCombinedPeimDriver => UefiDriverKind.CombinedPeimDxe,
            UefiPiCode.FfsMm => UefiDriverKind.Mm,
            UefiPiCode.FfsCombinedMmDxe => UefiDriverKind.CombinedMmDxe,
            UefiPiCode.FfsMmStandalone => UefiDriverKind.MmStandalone,
            _ => default
        };
        return type is UefiPiCode.FfsDriver or UefiPiCode.FfsCombinedPeimDriver or UefiPiCode.FfsMm or
            UefiPiCode.FfsCombinedMmDxe or UefiPiCode.FfsMmStandalone;
    }

    private static void MarkIncomplete(DriverSectionScan scan, InspectionContext context, string issue)
    {
        scan.Incomplete = true;
        context.Incomplete = true;
        scan.Issues.Add(issue);
    }

    private static int AlignSection(int value) => checked((value + UefiPiCode.SectionAlignmentBytes - 1) &
        ~(UefiPiCode.SectionAlignmentBytes - 1));

    private static int ReadU24(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;

    private static bool IsPadding(ReadOnlySpan<byte> source)
    {
        if (source.Length == 0)
        {
            return true;
        }
        byte first = source[0];
        if (first is not (byte.MinValue or byte.MaxValue))
        {
            return false;
        }
        foreach (byte value in source)
        {
            if (value != first)
            {
                return false;
            }
        }
        return true;
    }

    private sealed class InspectionContext
    {
        internal int Sections { get; set; }
        internal int ExpansionBudget { get; set; } = UefiDriverInspectionPolicy.TotalExpansionBudgetBytes;
        internal bool Incomplete { get; set; }
    }

    private sealed class DriverSectionScan
    {
        internal IUefiExecutableObserver? Observer { get; init; }
        internal UefiExecutableObservation Observation { get; init; }
        internal string? Name { get; set; }
        internal string? Version { get; set; }
        internal ushort? BuildNumber { get; set; }
        internal bool Incomplete { get; set; }
        internal int Sections { get; set; }
        internal int CompressionSections { get; set; }
        internal int GuidedSections { get; set; }
        internal int TeSections { get; set; }
        internal int DxeDepexSections { get; set; }
        internal int PeiDepexSections { get; set; }
        internal int MmDepexSections { get; set; }
        internal int VersionSections { get; set; }
        internal int UserInterfaceSections { get; set; }
        internal List<string> DependencyHashes { get; } = [];
        internal List<string> Issues { get; } = [];
        internal List<UefiExecutableInfo> Executables { get; } = [];
    }
}
