using System.Buffers.Binary;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace XeonV3Control.Core;

public enum TurboBoostUnlockStatus
{
    NotDetected,
    Possible,
    Detected,
    Inconclusive
}

public enum TurboBoostUnlockEvidenceKind
{
    ExactFfsIdentity,
    ExactExecutableIdentity,
    KnownFamilySemantics,
    NearKnownFamilySemantics,
    GenericUnlockSemantics
}

public enum CpuPatchRemovalPlanStatus
{
    Ready,
    UnsupportedLayout
}

public enum CpuPatchRemovalReason
{
    Ready,
    NotTurboBoostTarget,
    NotActiveRawFfs,
    InvalidFfs,
    InvalidFirmwareVolume,
    PatchIdentityMismatch,
    UnsupportedMicrocodeLayout,
    UnsupportedContainerTail,
    FitUnavailableOrMismatch
}

public sealed record TurboBoostUnlockFinding(
    TurboBoostUnlockEvidenceKind Evidence,
    string? Family,
    Guid? FileGuid,
    long? VolumeOffset,
    long? FileOffset,
    string Sha256,
    IReadOnlyList<string> RelevantMsrs,
    IReadOnlyList<string> MarkerHits);

public sealed record IntelMicrocodeInfo(
    long Offset,
    int Size,
    uint UpdateRevision,
    uint DateRaw,
    DateOnly? Date,
    uint ProcessorSignature,
    uint ProcessorFlags,
    string Sha256,
    long VolumeOffset,
    Guid FileGuid,
    long FileOffset,
    byte FfsType);

public sealed record CpuPatchRemovalPlan(
    CpuPatchRemovalPlanStatus Status,
    string SourceImageSha256,
    string PatchSha256,
    long PatchOffset,
    int PatchSize,
    uint ProcessorSignature,
    uint ProcessorFlags,
    uint UpdateRevision,
    long VolumeOffset,
    Guid FileGuid,
    long FileOffset,
    int RelativePatchOffset,
    int FileSize,
    int MicrocodeCount,
    long FitOffset,
    int FitMicrocodeEntryCount,
    CpuPatchRemovalReason Reason)
{
    public bool CanApply => Status == CpuPatchRemovalPlanStatus.Ready;
}

public sealed record TurboBoostUnlockReport(
    TurboBoostUnlockStatus Status,
    IReadOnlyList<TurboBoostUnlockFinding> Findings,
    IReadOnlyList<TurboBoostUnlockModule> Modules,
    IReadOnlyList<IntelMicrocodeInfo> Microcodes,
    IReadOnlyList<CpuPatchRemovalPlan> CpuPatchRemovalPlans,
    bool Incomplete)
{
    // Haswell-E/EP Cx/M1 is identified by F-M-S 06-3F-02 and platform mask 0x6F.
    // Turbo Boost Unlock workflows remove this BIOS microcode update so no matching revision
    // patch is loaded during POST before the unlock driver executes.
    public const uint XeonE5V3ProcessorSignature = 0x000306F2;
    public const uint XeonE5V3ProcessorFlags = 0x0000006F;

    public static TurboBoostUnlockReport Empty { get; } = new(
        TurboBoostUnlockStatus.Inconclusive,
        [],
        [],
        [],
        [],
        true);

    public IReadOnlyList<IntelMicrocodeInfo> XeonE5V3CpuPatches =>
        Microcodes.Where(IsXeonE5V3TurboUnlockCpuPatch).ToArray();

    public bool HasXeonE5V3CpuPatch => Microcodes.Any(IsXeonE5V3TurboUnlockCpuPatch);

    public int RemovableXeonE5V3CpuPatchCount =>
        CpuPatchRemovalPlans.Count(item => item.CanApply);

    public IReadOnlyList<TurboBoostUnlockModule> RetainedUnlockModules =>
        Modules.Where(item => item.Disposition == TurboBoostUnlockModuleDisposition.Retained).ToArray();

    public IReadOnlyList<TurboBoostUnlockModule> ForeignUnlockModules =>
        Modules.Where(item => item.Disposition == TurboBoostUnlockModuleDisposition.Foreign).ToArray();

    public IReadOnlyList<TurboBoostUnlockModule> UnclassifiedUnlockModules =>
        Modules.Where(item => item.Disposition == TurboBoostUnlockModuleDisposition.Unclassified).ToArray();

    public static bool IsXeonE5V3TurboUnlockCpuPatch(IntelMicrocodeInfo item) =>
        item.ProcessorSignature == XeonE5V3ProcessorSignature &&
        item.ProcessorFlags == XeonE5V3ProcessorFlags;
}

internal readonly record struct UefiExecutableObservation(
    Guid FileGuid,
    long VolumeOffset,
    int FileOffset,
    byte FfsType,
    UefiExecutableFormat Format);

internal interface IUefiExecutableObserver
{
    void Observe(in UefiExecutableObservation observation, ReadOnlySpan<byte> image);
}

/// <summary>
/// Detects known Xeon E5-v3 Turbo Boost Unlock payloads and valid Intel CPU microcode patches.
/// Detection is read-only; mutation is isolated in <see cref="CpuPatchImageUpdater"/> and is available only
/// for removal plans that pass the container and FIT validation gates.
/// </summary>
public static class TurboBoostUnlockInspector
{
    private const byte FfsRaw = 0x01;
    private const int MaximumMicrocodes = 512;

    internal static TurboBoostExecutableObserver CreateExecutableObserver() =>
        new(TurboBoostUnlockIdentityCatalog.Instance);

    internal static TurboBoostUnlockReport Inspect(
        ReadOnlySpan<byte> source,
        string sourceSha256,
        IReadOnlyList<FirmwareVolume> volumes,
        UefiDriverReport driverReport,
        TurboBoostExecutableObserver observer,
        CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceSha256);
        ArgumentNullException.ThrowIfNull(volumes);
        ArgumentNullException.ThrowIfNull(driverReport);
        ArgumentNullException.ThrowIfNull(observer);

        TurboBoostUnlockIdentityCatalog catalog = TurboBoostUnlockIdentityCatalog.Instance;
        var findings = new List<TurboBoostUnlockFinding>(observer.Findings);
        var microcodes = new List<IntelMicrocodeInfo>();
        var ffsContexts = new Dictionary<(long VolumeOffset, long FileOffset), TurboBoostFfsContext>();
        bool incomplete = false;

        foreach (FirmwareVolume volume in volumes)
        {
            token.ThrowIfCancellationRequested();
            if (!UefiFirmwareSpecification.StandardFirmwareFileSystems.Contains(volume.FileSystem))
            {
                continue;
            }

            bool complete = UefiFfsVolumeScanner.TryReadFiles(
                source,
                volume,
                token,
                out _,
                out IReadOnlyList<UefiFfsFileLocation> files);
            incomplete |= !complete;

            foreach (UefiFfsFileLocation file in files)
            {
                token.ThrowIfCancellationRequested();
                if (file.State != FfsFileState.DataValid || file.Size <= 0 || file.Offset < 0 ||
                    file.Offset > source.Length - file.Size)
                {
                    continue;
                }

                ReadOnlySpan<byte> ffs = source.Slice(file.Offset, file.Size);
                string ffsHash = Convert.ToHexString(SHA256.HashData(ffs));
                ffsContexts[(volume.Offset, file.Offset)] = new(
                    file.Guid,
                    volume.Offset,
                    file.Offset,
                    file.Size,
                    file.Type,
                    file.Attributes,
                    ffsHash);
                if (catalog.TryGetExactFfsFamily(ffsHash, out string? family))
                {
                    findings.Add(new(
                        TurboBoostUnlockEvidenceKind.ExactFfsIdentity,
                        family,
                        file.Guid,
                        volume.Offset,
                        file.Offset,
                        ffsHash,
                        [],
                        []));
                }

                findings.AddRange(catalog.ScanRawProfiles(
                    ffs,
                    file.Guid,
                    volume.Offset,
                    file.Offset,
                    token));

                if (file.Type == FfsRaw)
                {
                    ScanMicrocodes(source, volume, file, microcodes, token);
                }
            }
        }

        TurboBoostUnlockFinding[] normalizedFindings = findings
            .GroupBy(item => new
            {
                item.Evidence,
                item.Family,
                item.FileGuid,
                item.VolumeOffset,
                item.FileOffset,
                item.Sha256
            })
            .Select(group => group.First())
            .OrderBy(item => item.FileOffset ?? long.MaxValue)
            .ThenBy(item => item.Family ?? string.Empty, StringComparer.Ordinal)
            .ToArray();

        TurboBoostUnlockModule[] modules = TurboBoostUnlockModulePlanner.Build(
            sourceSha256,
            normalizedFindings,
            ffsContexts,
            driverReport,
            catalog,
            incomplete || driverReport.Incomplete);

        IntelMicrocodeInfo[] normalizedMicrocodes = microcodes
            .GroupBy(item => (item.Offset, item.Size, item.Sha256))
            .Select(group => group.First())
            .OrderBy(item => item.Offset)
            .Take(MaximumMicrocodes)
            .ToArray();

        var removalPlanList = new List<CpuPatchRemovalPlan>();
        foreach (IntelMicrocodeInfo item in normalizedMicrocodes)
        {
            if (!TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(item))
            {
                continue;
            }

            removalPlanList.Add(CpuPatchImageUpdater.PlanRemoval(source, sourceSha256, item, token));
        }

        CpuPatchRemovalPlan[] removalPlans = removalPlanList.ToArray();

        bool verified = normalizedFindings.Any(item => item.Evidence is
            TurboBoostUnlockEvidenceKind.ExactFfsIdentity or
            TurboBoostUnlockEvidenceKind.ExactExecutableIdentity or
            TurboBoostUnlockEvidenceKind.KnownFamilySemantics);
        bool possible = normalizedFindings.Any(item => item.Evidence is
            TurboBoostUnlockEvidenceKind.NearKnownFamilySemantics or
            TurboBoostUnlockEvidenceKind.GenericUnlockSemantics);

        TurboBoostUnlockStatus status = verified
            ? TurboBoostUnlockStatus.Detected
            : possible
                ? TurboBoostUnlockStatus.Possible
                : incomplete || driverReport.Incomplete
                    ? TurboBoostUnlockStatus.Inconclusive
                    : TurboBoostUnlockStatus.NotDetected;

        return new(status, normalizedFindings, modules, normalizedMicrocodes, removalPlans, incomplete || driverReport.Incomplete);
    }

    private static void ScanMicrocodes(
        ReadOnlySpan<byte> source,
        FirmwareVolume volume,
        UefiFfsFileLocation file,
        List<IntelMicrocodeInfo> output,
        CancellationToken token)
    {
        int start = checked(file.Offset + file.HeaderSize);
        int end = checked(file.Offset + file.Size);
        for (int offset = start; offset <= end - IntelMicrocodeContainerSpecification.HeaderBytes; offset += IntelMicrocodeContainerSpecification.ScanAlignmentBytes)
        {
            if ((offset & 0x3FFF) == 0)
            {
                token.ThrowIfCancellationRequested();
            }
            if (output.Count >= MaximumMicrocodes)
            {
                return;
            }
            if (!TryReadMicrocode(source, offset, end, out IntelMicrocodeInfo? microcode) || microcode is null)
            {
                continue;
            }

            output.Add(microcode with
            {
                VolumeOffset = volume.Offset,
                FileGuid = file.Guid,
                FileOffset = file.Offset,
                FfsType = file.Type
            });

            // Valid Intel updates are self-contained. Skip their payload to avoid re-scanning it as headers.
            int next = checked(offset + microcode.Size);
            if (next > offset)
            {
                offset = next - IntelMicrocodeContainerSpecification.ScanAlignmentBytes;
            }
        }
    }

    internal static bool TryReadMicrocode(
        ReadOnlySpan<byte> source,
        int offset,
        int containerEnd,
        out IntelMicrocodeInfo? result)
    {
        result = null;
        if (offset < 0 || offset > containerEnd - IntelMicrocodeContainerSpecification.HeaderBytes ||
            containerEnd > source.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> header = source.Slice(offset, IntelMicrocodeContainerSpecification.HeaderBytes);
        uint headerVersion = BinaryPrimitives.ReadUInt32LittleEndian(header);
        uint revision = BinaryPrimitives.ReadUInt32LittleEndian(header[4..]);
        uint date = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
        uint signature = BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
        uint loaderRevision = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
        uint processorFlags = BinaryPrimitives.ReadUInt32LittleEndian(header[24..]);
        uint dataSize = BinaryPrimitives.ReadUInt32LittleEndian(header[28..]);
        uint totalSize = BinaryPrimitives.ReadUInt32LittleEndian(header[32..]);

        if (headerVersion != IntelMicrocodeContainerSpecification.HeaderVersion || loaderRevision is not (0 or 1))
        {
            return false;
        }

        uint encodedSize = dataSize == 0 ? IntelMicrocodeContainerSpecification.LegacyPatchBytes : totalSize;
        if (encodedSize < IntelMicrocodeContainerSpecification.HeaderBytes || encodedSize > IntelMicrocodeContainerSpecification.MaximumPatchBytes ||
            (encodedSize & 3) != 0 || encodedSize > int.MaxValue ||
            offset > containerEnd - (int)encodedSize)
        {
            return false;
        }
        if (dataSize != 0 && (totalSize < IntelMicrocodeContainerSpecification.HeaderBytes + dataSize || (dataSize & 3) != 0))
        {
            return false;
        }

        ReadOnlySpan<byte> blob = source.Slice(offset, (int)encodedSize);
        uint sum = 0;
        for (int cursor = 0; cursor < blob.Length; cursor += sizeof(uint))
        {
            sum = unchecked(sum + BinaryPrimitives.ReadUInt32LittleEndian(blob[cursor..]));
        }
        if (sum != 0)
        {
            return false;
        }

        result = new(
            offset,
            (int)encodedSize,
            revision,
            date,
            ParseIntelMicrocodeDate(date),
            signature,
            processorFlags,
            Convert.ToHexString(SHA256.HashData(blob)),
            0,
            Guid.Empty,
            0,
            0);
        return true;
    }

    private static DateOnly? ParseIntelMicrocodeDate(uint raw)
    {
        string value = raw.ToString("X8", CultureInfo.InvariantCulture);
        if (!value.All(char.IsAsciiDigit) ||
            !int.TryParse(value.AsSpan(0, 2), NumberStyles.None, CultureInfo.InvariantCulture, out int month) ||
            !int.TryParse(value.AsSpan(2, 2), NumberStyles.None, CultureInfo.InvariantCulture, out int day) ||
            !int.TryParse(value.AsSpan(4, 4), NumberStyles.None, CultureInfo.InvariantCulture, out int year))
        {
            return null;
        }
        try
        {
            return new DateOnly(year, month, day);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static int RelativeOffsetInsideFfs(this IntelMicrocodeInfo patch) =>
        checked((int)(patch.Offset - patch.FileOffset));
}

internal sealed class TurboBoostExecutableObserver : IUefiExecutableObserver
{
    private readonly TurboBoostUnlockIdentityCatalog catalog;
    private readonly List<TurboBoostUnlockFinding> findings = [];

    internal TurboBoostExecutableObserver(TurboBoostUnlockIdentityCatalog catalog)
    {
        this.catalog = catalog;
    }

    internal IReadOnlyList<TurboBoostUnlockFinding> Findings => findings;

    public void Observe(in UefiExecutableObservation observation, ReadOnlySpan<byte> image)
    {
        string hash = Convert.ToHexString(SHA256.HashData(image));
        if (catalog.IsKnownCleanExecutable(hash) && !catalog.TryGetExactExecutableFamily(hash, out _))
        {
            return;
        }

        if (catalog.TryGetExactExecutableFamily(hash, out string? exactFamily))
        {
            findings.Add(new(
                TurboBoostUnlockEvidenceKind.ExactExecutableIdentity,
                exactFamily,
                observation.FileGuid,
                observation.VolumeOffset,
                observation.FileOffset,
                hash,
                [],
                []));
            return;
        }

        if (observation.Format != UefiExecutableFormat.Pe32 ||
            !TurboBoostPeAnalyzer.TryInspect(image, out TurboBoostPeImageInfo? pe) || pe is null)
        {
            return;
        }

        TurboBoostMsrEvidence semantics = TurboBoostSemanticAnalyzer.Analyze(pe.ExecutableCode);
        TurboUnlockProfileMatch? profileMatch = catalog.MatchBestPeProfile(pe, semantics, image);
        if (profileMatch is { Verified: true })
        {
            findings.Add(new(
                TurboBoostUnlockEvidenceKind.KnownFamilySemantics,
                profileMatch.Profile.Family,
                observation.FileGuid,
                observation.VolumeOffset,
                observation.FileOffset,
                hash,
                semantics.RelevantMsrNames,
                profileMatch.MarkerHits));
            return;
        }

        if (profileMatch is { Near: true })
        {
            findings.Add(new(
                TurboBoostUnlockEvidenceKind.NearKnownFamilySemantics,
                profileMatch.Profile.Family,
                observation.FileGuid,
                observation.VolumeOffset,
                observation.FileOffset,
                hash,
                semantics.RelevantMsrNames,
                profileMatch.MarkerHits));
            return;
        }

        if (semantics.IsStrongCandidate)
        {
            findings.Add(new(
                TurboBoostUnlockEvidenceKind.GenericUnlockSemantics,
                null,
                observation.FileGuid,
                observation.VolumeOffset,
                observation.FileOffset,
                hash,
                semantics.RelevantMsrNames,
                []));
        }
    }
}

internal sealed record TurboBoostMsrEvidence(
    IReadOnlyList<uint> RelevantMsrs,
    IReadOnlyList<string> RelevantMsrNames,
    int RdmsrCount,
    int WrmsrCount,
    int Score,
    bool IsStrongCandidate);

internal static class TurboBoostSemanticAnalyzer
{
    private const int MsrSearchWindowBytes = 32;

    private static readonly IReadOnlyDictionary<uint, string> RelevantMsrs = new Dictionary<uint, string>
    {
        [0x08B] = "IA32_BIOS_SIGN_ID (0x8B)",
        [0x150] = "OC_MAILBOX (0x150)",
        [0x194] = "MSR_FLEX_RATIO / OC_LOCK (0x194)",
        [0x1AD] = "IA32_TURBO_RATIO_LIMIT (0x1AD)",
        [0x1AE] = "IA32_TURBO_RATIO_LIMIT1 (0x1AE)",
        [0x1AF] = "IA32_TURBO_RATIO_LIMIT2 (0x1AF)",
        [0x620] = "MSR_UNCORE_RATIO_LIMIT (0x620)"
    };

    internal static TurboBoostMsrEvidence Analyze(ReadOnlySpan<byte> code)
    {
        var observed = new HashSet<uint>();
        int rdmsr = 0;
        int wrmsr = 0;
        int index = 0;
        while (index < code.Length)
        {
            uint? immediate = null;
            int instructionLength = 0;
            if (code[index] == 0xB9 && index <= code.Length - 5)
            {
                immediate = BinaryPrimitives.ReadUInt32LittleEndian(code[(index + 1)..]);
                instructionLength = 5;
            }
            else if (index <= code.Length - 4 && code[index] == 0x66 && code[index + 1] == 0xB9)
            {
                immediate = BinaryPrimitives.ReadUInt16LittleEndian(code[(index + 2)..]);
                instructionLength = 4;
            }

            if (immediate is null)
            {
                index++;
                continue;
            }

            int tailStart = checked(index + instructionLength);
            int tailLength = Math.Min(MsrSearchWindowBytes, code.Length - tailStart);
            ReadOnlySpan<byte> tail = code.Slice(tailStart, tailLength);
            bool hasRead = IndexOfOpcode(tail, 0x0F, 0x32) >= 0;
            bool hasWrite = IndexOfOpcode(tail, 0x0F, 0x30) >= 0;
            if (hasRead || hasWrite)
            {
                if (RelevantMsrs.ContainsKey(immediate.Value))
                {
                    observed.Add(immediate.Value);
                }
                rdmsr += hasRead ? 1 : 0;
                wrmsr += hasWrite ? 1 : 0;
            }
            index += Math.Max(1, instructionLength);
        }

        int score = 0;
        if (observed.Contains(0x1AD)) score += 3;
        if (observed.Contains(0x620)) score += 2;
        if (observed.Contains(0x150)) score += 2;
        if (observed.Contains(0x194)) score += 1;
        if (observed.Contains(0x08B)) score += 1;
        if (observed.Contains(0x1AE) || observed.Contains(0x1AF)) score += 1;
        if (wrmsr >= 2) score += 1;

        uint[] msrs = observed.OrderBy(value => value).ToArray();
        return new(
            msrs,
            msrs.Select(value => RelevantMsrs[value]).ToArray(),
            rdmsr,
            wrmsr,
            score,
            observed.Contains(0x1AD) && observed.Contains(0x620) &&
                (observed.Contains(0x150) || observed.Contains(0x194)) && score >= 7);
    }

    private static int IndexOfOpcode(ReadOnlySpan<byte> source, byte first, byte second)
    {
        for (int index = 0; index < source.Length - 1; index++)
        {
            if (source[index] == first && source[index + 1] == second)
            {
                return index;
            }
        }
        return -1;
    }
}

internal sealed record TurboBoostPeCodeSection(int Index, string Name, int RawSize, bool Executable, byte[] Data);

internal sealed record TurboBoostPeImageInfo(
    ushort Machine,
    ushort OptionalMagic,
    ushort Subsystem,
    IReadOnlyList<TurboBoostPeCodeSection> Sections,
    byte[] ExecutableCode);

internal static class TurboBoostPeAnalyzer
{
    private const uint SectionCode = 0x00000020;
    private const uint SectionExecute = 0x20000000;

    internal static bool TryInspect(ReadOnlySpan<byte> image, out TurboBoostPeImageInfo? result)
    {
        result = null;
        if (image.Length < UefiPiCode.DosPeOffsetOffset + sizeof(uint) ||
            BinaryPrimitives.ReadUInt16LittleEndian(image) != UefiPiCode.DosMagic)
        {
            return false;
        }

        uint peOffsetValue = BinaryPrimitives.ReadUInt32LittleEndian(image[UefiPiCode.DosPeOffsetOffset..]);
        if (peOffsetValue > int.MaxValue)
        {
            return false;
        }
        int peOffset = (int)peOffsetValue;
        if (peOffset > image.Length - UefiPiCode.PeOptionalHeaderOffset ||
            BinaryPrimitives.ReadUInt32LittleEndian(image[peOffset..]) != UefiPiCode.PeSignature)
        {
            return false;
        }

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeMachineOffset)..]);
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeNumberOfSectionsOffset)..]);
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(image[(peOffset + UefiPiCode.PeOptionalHeaderSizeOffset)..]);
        int optionalOffset = checked(peOffset + UefiPiCode.PeOptionalHeaderOffset);
        if (sectionCount is < 1 or > UefiPiCode.MaximumExecutableSections ||
            optionalSize < UefiPiCode.PeOptionalSubsystemOffset + sizeof(ushort) ||
            optionalOffset > image.Length - optionalSize)
        {
            return false;
        }

        ushort optionalMagic = BinaryPrimitives.ReadUInt16LittleEndian(image[optionalOffset..]);
        ushort subsystem = BinaryPrimitives.ReadUInt16LittleEndian(image[(optionalOffset + UefiPiCode.PeOptionalSubsystemOffset)..]);
        int sectionTable = checked(optionalOffset + optionalSize);
        int sectionTableBytes = checked(sectionCount * UefiPiCode.PeSectionHeaderBytes);
        if (sectionTable > image.Length - sectionTableBytes)
        {
            return false;
        }

        var sections = new List<TurboBoostPeCodeSection>(sectionCount);
        using var code = new MemoryStream();
        for (int index = 0; index < sectionCount; index++)
        {
            int header = checked(sectionTable + index * UefiPiCode.PeSectionHeaderBytes);
            string name = DecodeSectionName(image.Slice(header, 8));
            uint rawSizeValue = BinaryPrimitives.ReadUInt32LittleEndian(image[(header + UefiPiCode.PeSectionRawSizeOffset)..]);
            uint rawOffsetValue = BinaryPrimitives.ReadUInt32LittleEndian(image[(header + UefiPiCode.PeSectionRawPointerOffset)..]);
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(image[(header + UefiPiCode.PeSectionCharacteristicsOffset)..]);
            if (rawSizeValue > int.MaxValue || rawOffsetValue > int.MaxValue)
            {
                return false;
            }
            int rawSize = (int)rawSizeValue;
            int rawOffset = (int)rawOffsetValue;
            if (rawSize != 0 && rawOffset > image.Length - rawSize)
            {
                return false;
            }
            bool executable = (characteristics & (SectionCode | SectionExecute)) != 0;
            byte[] payload = executable && rawSize != 0 ? image.Slice(rawOffset, rawSize).ToArray() : [];
            sections.Add(new(index, name, rawSize, executable, payload));
            if (payload.Length != 0)
            {
                code.Write(payload);
            }
        }

        result = new(machine, optionalMagic, subsystem, sections, code.ToArray());
        return true;
    }

    private static string DecodeSectionName(ReadOnlySpan<byte> raw)
    {
        int length = raw.IndexOf((byte)0);
        if (length < 0)
        {
            length = raw.Length;
        }
        return Encoding.ASCII.GetString(raw[..length]);
    }
}

internal sealed record TurboUnlockProfileMatch(
    TurboUnlockIdentityProfile Profile,
    bool Verified,
    bool Near,
    double BlockScore,
    double MaskedScore,
    IReadOnlyList<string> MarkerHits);

internal sealed class TurboBoostUnlockIdentityCatalog
{
    private const string FileName = "turbo-unlock-identities.json";
    private const int SupportedSchemaVersion = 3;
    private const int MaximumRawCandidatesPerProfile = 4096;

    private readonly IReadOnlyDictionary<string, string> exactFfs;
    private readonly IReadOnlyDictionary<string, string> exactExecutables;
    private readonly IReadOnlySet<string> knownCleanExecutables;
    private readonly IReadOnlySet<string> retainedFamilies;
    private readonly IReadOnlyList<TurboUnlockIdentityProfile> peProfiles;
    private readonly IReadOnlyList<TurboUnlockRawProfile> rawProfiles;

    private TurboBoostUnlockIdentityCatalog(
        IReadOnlyDictionary<string, string> exactFfs,
        IReadOnlyDictionary<string, string> exactExecutables,
        IReadOnlySet<string> knownCleanExecutables,
        IReadOnlySet<string> retainedFamilies,
        IReadOnlyList<TurboUnlockIdentityProfile> peProfiles,
        IReadOnlyList<TurboUnlockRawProfile> rawProfiles)
    {
        this.exactFfs = exactFfs;
        this.exactExecutables = exactExecutables;
        this.knownCleanExecutables = knownCleanExecutables;
        this.retainedFamilies = retainedFamilies;
        this.peProfiles = peProfiles;
        this.rawProfiles = rawProfiles;
    }

    internal static TurboBoostUnlockIdentityCatalog Instance { get; } = Load();

    internal bool TryGetExactFfsFamily(string hash, out string? family) => exactFfs.TryGetValue(hash, out family);
    internal bool TryGetExactExecutableFamily(string hash, out string? family) => exactExecutables.TryGetValue(hash, out family);
    internal bool IsKnownCleanExecutable(string hash) => knownCleanExecutables.Contains(hash);
    internal bool IsRetainedFamily(string family) => retainedFamilies.Contains(family);

    internal TurboUnlockProfileMatch? MatchBestPeProfile(
        TurboBoostPeImageInfo pe,
        TurboBoostMsrEvidence semantics,
        ReadOnlySpan<byte> fullImage)
    {
        TurboUnlockProfileMatch? bestVerified = null;
        TurboUnlockProfileMatch? bestNear = null;
        foreach (TurboUnlockIdentityProfile profile in peProfiles)
        {
            TurboUnlockProfileMatch? match = profile.Match(pe, semantics, fullImage);
            if (match is null)
            {
                continue;
            }
            if (match.Verified && IsBetter(match, bestVerified))
            {
                bestVerified = match;
            }
            else if (match.Near && IsBetter(match, bestNear))
            {
                bestNear = match;
            }
        }
        return bestVerified ?? bestNear;
    }

    internal IReadOnlyList<TurboBoostUnlockFinding> ScanRawProfiles(
        ReadOnlySpan<byte> fileBytes,
        Guid fileGuid,
        long volumeOffset,
        long fileOffset,
        CancellationToken token)
    {
        if (rawProfiles.Count == 0 || fileBytes.IsEmpty)
        {
            return [];
        }

        var results = new List<TurboBoostUnlockFinding>();
        foreach (TurboUnlockRawProfile profile in rawProfiles)
        {
            token.ThrowIfCancellationRequested();
            var starts = new HashSet<int>();
            foreach (TurboUnlockRawAnchor anchor in profile.Anchors)
            {
                int search = 0;
                while (search <= fileBytes.Length - anchor.Needle.Length && starts.Count < MaximumRawCandidatesPerProfile)
                {
                    int relativeHit = fileBytes[search..].IndexOf(anchor.Needle);
                    if (relativeHit < 0)
                    {
                        break;
                    }
                    int hit = checked(search + relativeHit);
                    int candidateStart = hit - anchor.Offset;
                    if (candidateStart >= 0 && candidateStart <= fileBytes.Length - profile.Size)
                    {
                        starts.Add(candidateStart);
                    }
                    search = checked(hit + 1);
                }
                if (starts.Count >= MaximumRawCandidatesPerProfile)
                {
                    break;
                }
            }

            foreach (int start in starts.OrderBy(value => value))
            {
                ReadOnlySpan<byte> candidate = fileBytes.Slice(start, profile.Size);
                TurboBoostMsrEvidence semantics = TurboBoostSemanticAnalyzer.Analyze(candidate);
                if (!profile.RequiredMsrs.All(semantics.RelevantMsrs.Contains) || !profile.IsVerified(candidate))
                {
                    continue;
                }
                results.Add(new(
                    TurboBoostUnlockEvidenceKind.KnownFamilySemantics,
                    profile.Family,
                    fileGuid,
                    volumeOffset,
                    fileOffset,
                    Convert.ToHexString(SHA256.HashData(candidate)),
                    semantics.RelevantMsrNames,
                    []));
            }
        }
        return results;
    }

    private static bool IsBetter(TurboUnlockProfileMatch candidate, TurboUnlockProfileMatch? current)
    {
        if (current is null)
        {
            return true;
        }
        double candidateScore = Math.Max(candidate.BlockScore, candidate.MaskedScore);
        double currentScore = Math.Max(current.BlockScore, current.MaskedScore);
        return candidateScore > currentScore;
    }

    private static TurboBoostUnlockIdentityCatalog Load()
    {
        Assembly assembly = typeof(TurboBoostUnlockIdentityCatalog).Assembly;
        string resource = EmbeddedResourceNames.File(EmbeddedResourceNames.FirmwareFolder, FileName);
        using Stream stream = assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        TurboUnlockCatalogDocument? document = JsonSerializer.Deserialize<TurboUnlockCatalogDocument>(
            stream,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (document is null || document.SchemaVersion != SupportedSchemaVersion)
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }

        Dictionary<string, string> ffs = NormalizeIdentities(document.ExactFfs);
        Dictionary<string, string> executables = NormalizeIdentities(document.ExactExecutables);
        HashSet<string> clean = document.KnownCleanExecutables
            .Select(NormalizeSha256)
            .ToHashSet(StringComparer.Ordinal);
        TurboUnlockIdentityProfile[] parsedPeProfiles = document.PeProfiles
            .Select(TurboUnlockIdentityProfile.FromDocument)
            .ToArray();
        TurboUnlockRawProfile[] parsedRawProfiles = document.RawProfiles
            .Select(TurboUnlockRawProfile.FromDocument)
            .ToArray();
        HashSet<string> retained = NormalizeFamilies(document.RetainedFamilies);
        var knownFamilies = new HashSet<string>(ffs.Values, StringComparer.Ordinal);
        knownFamilies.UnionWith(executables.Values);
        knownFamilies.UnionWith(parsedPeProfiles.Select(item => item.Family));
        knownFamilies.UnionWith(parsedRawProfiles.Select(item => item.Family));
        if (retained.Any(family => !knownFamilies.Contains(family)))
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
        return new(ffs, executables, clean, retained, parsedPeProfiles, parsedRawProfiles);
    }

    private static HashSet<string> NormalizeFamilies(IEnumerable<string> source)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (string family in source)
        {
            if (string.IsNullOrWhiteSpace(family) || !result.Add(family.Trim()))
            {
                throw new InvalidDataException(OperationError.TurboUnlockCatalog);
            }
        }
        return result;
    }

    private static Dictionary<string, string> NormalizeIdentities(IEnumerable<TurboUnlockHashIdentityDocument> source)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (TurboUnlockHashIdentityDocument item in source)
        {
            string hash = NormalizeSha256(item.Sha256);
            if (string.IsNullOrWhiteSpace(item.Family) || !result.TryAdd(hash, item.Family.Trim()))
            {
                throw new InvalidDataException(OperationError.TurboUnlockCatalog);
            }
        }
        return result;
    }

    internal static string NormalizeSha256(string value)
    {
        string normalized = value.Trim().ToUpperInvariant();
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
        return normalized;
    }
}

internal sealed record TurboUnlockIdentityProfile(
    string Id,
    string Family,
    ushort Machine,
    ushort OptionalMagic,
    ushort Subsystem,
    IReadOnlyList<TurboUnlockSectionShape> Sections,
    IReadOnlyList<TurboUnlockCodeSectionProfile> CodeSections,
    IReadOnlyList<uint> RequiredMsrs,
    IReadOnlyList<string> Markers,
    TurboUnlockCalibration Calibration)
{
    internal static TurboUnlockIdentityProfile FromDocument(TurboUnlockIdentityProfileDocument source)
    {
        if (string.IsNullOrWhiteSpace(source.Id) || string.IsNullOrWhiteSpace(source.Family))
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
        return new(
            source.Id.Trim(),
            source.Family.Trim(),
            ParseU16(source.Machine),
            ParseU16(source.OptionalMagic),
            checked((ushort)source.Subsystem),
            source.Sections.Select(item => new TurboUnlockSectionShape(item.Index, item.Name ?? string.Empty, item.RawSize, item.Executable)).ToArray(),
            source.CodeSections.Select(TurboUnlockCodeSectionProfile.FromDocument).ToArray(),
            source.RequiredMsrs.Distinct().OrderBy(value => value).ToArray(),
            source.Markers.Where(marker => !string.IsNullOrWhiteSpace(marker)).Distinct(StringComparer.Ordinal).ToArray(),
            TurboUnlockCalibration.FromDocument(source.Calibration));
    }

    internal TurboUnlockProfileMatch? Match(
        TurboBoostPeImageInfo pe,
        TurboBoostMsrEvidence semantics,
        ReadOnlySpan<byte> image)
    {
        if (!Calibration.Enabled || !StructureMatches(pe) || !RequiredMsrs.All(semantics.RelevantMsrs.Contains))
        {
            return null;
        }

        IReadOnlyList<string> markerHits = MarkerHits(image);
        TurboUnlockBlockScore block = ScoreBlocks(pe);
        TurboUnlockMaskedScore masked = ScoreMasked(pe);
        bool markersOk = markerHits.Count >= Calibration.MinimumMarkerHits;
        bool blockOk = block.Score >= Calibration.VerifiedScoreThreshold &&
            block.Matched >= Calibration.MinimumMatchingStableBlocks &&
            block.Matched >= Calibration.MinimumMatchingDiscriminativeBlocks;
        bool maskedOk = Calibration.MaskedEnabled && masked.Score >= Calibration.MaskedVerifiedScoreThreshold &&
            masked.Matched >= Calibration.MinimumMatchingInvariantBytes;
        bool verified = markersOk && (blockOk || maskedOk);
        bool near = !verified &&
            (block.Score >= Math.Max(0.65, Calibration.VerifiedScoreThreshold - 0.20) ||
             masked.Score >= Math.Max(0.90, Calibration.MaskedVerifiedScoreThreshold - 0.05));
        return new(this, verified, near, block.Score, masked.Score, markerHits);
    }

    private bool StructureMatches(TurboBoostPeImageInfo pe)
    {
        if (Machine != pe.Machine || OptionalMagic != pe.OptionalMagic || Subsystem != pe.Subsystem ||
            Sections.Count != pe.Sections.Count)
        {
            return false;
        }
        for (int index = 0; index < Sections.Count; index++)
        {
            TurboUnlockSectionShape expected = Sections[index];
            TurboBoostPeCodeSection actual = pe.Sections[index];
            if (expected.Index != actual.Index || expected.RawSize != actual.RawSize || expected.Executable != actual.Executable ||
                !string.Equals(expected.Name, actual.Name, StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private TurboUnlockBlockScore ScoreBlocks(TurboBoostPeImageInfo pe)
    {
        int matched = 0;
        int total = 0;
        foreach (TurboUnlockCodeSectionProfile profile in CodeSections)
        {
            TurboBoostPeCodeSection? section = pe.Sections.FirstOrDefault(item =>
                item.Index == profile.Index && item.RawSize == profile.RawSize &&
                string.Equals(item.Name, profile.Name, StringComparison.Ordinal));
            if (section is null || section.Data.Length == 0)
            {
                return default;
            }
            foreach (TurboUnlockStableBlock block in profile.StableBlocks)
            {
                if (block.Offset < 0 || block.Length <= 0 || block.Offset > section.Data.Length - block.Length)
                {
                    continue;
                }
                total++;
                if (SHA256.HashData(section.Data.AsSpan(block.Offset, block.Length)).AsSpan().SequenceEqual(block.Sha256))
                {
                    matched++;
                }
            }
        }
        return new(matched, total);
    }

    private TurboUnlockMaskedScore ScoreMasked(TurboBoostPeImageInfo pe)
    {
        int matched = 0;
        int total = 0;
        foreach (TurboUnlockCodeSectionProfile profile in CodeSections)
        {
            if (profile.MaskedPattern.Length == 0 || profile.InvariantMask.Length == 0)
            {
                continue;
            }
            TurboBoostPeCodeSection? section = pe.Sections.FirstOrDefault(item =>
                item.Index == profile.Index && item.RawSize == profile.RawSize &&
                string.Equals(item.Name, profile.Name, StringComparison.Ordinal));
            if (section is null || section.Data.Length == 0)
            {
                return default;
            }
            int length = Math.Min(section.Data.Length, Math.Min(profile.MaskedPattern.Length, profile.InvariantMask.Length));
            for (int index = 0; index < length; index++)
            {
                if (profile.InvariantMask[index] == 0)
                {
                    continue;
                }
                total++;
                if (section.Data[index] == profile.MaskedPattern[index])
                {
                    matched++;
                }
            }
        }
        return new(matched, total);
    }

    private IReadOnlyList<string> MarkerHits(ReadOnlySpan<byte> image)
    {
        var hits = new List<string>();
        foreach (string marker in Markers)
        {
            byte[] ascii = Encoding.ASCII.GetBytes(marker);
            if (ascii.Length != 0 && image.IndexOf(ascii) >= 0)
            {
                hits.Add(marker);
                continue;
            }
            byte[] unicode = Encoding.Unicode.GetBytes(marker);
            if (unicode.Length != 0 && image.IndexOf(unicode) >= 0)
            {
                hits.Add(marker);
            }
        }
        return hits;
    }

    private static ushort ParseU16(string value)
    {
        string normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        if (!ushort.TryParse(normalized, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ushort parsed))
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
        return parsed;
    }
}

internal readonly record struct TurboUnlockBlockScore(int Matched, int Total)
{
    internal double Score => Total == 0 ? 0.0 : (double)Matched / Total;
}

internal readonly record struct TurboUnlockMaskedScore(int Matched, int Total)
{
    internal double Score => Total == 0 ? 0.0 : (double)Matched / Total;
}

internal sealed record TurboUnlockSectionShape(int Index, string Name, int RawSize, bool Executable);

internal sealed record TurboUnlockStableBlock(int Offset, int Length, byte[] Sha256);

internal sealed record TurboUnlockCodeSectionProfile(
    int Index,
    string Name,
    int RawSize,
    IReadOnlyList<TurboUnlockStableBlock> StableBlocks,
    byte[] MaskedPattern,
    byte[] InvariantMask)
{
    internal static TurboUnlockCodeSectionProfile FromDocument(TurboUnlockCodeSectionProfileDocument source) => new(
        source.Index,
        source.Name ?? string.Empty,
        source.RawSize,
        source.StableBlocks.Select(item => new TurboUnlockStableBlock(
            item.Offset,
            item.Length,
            Convert.FromHexString(TurboBoostUnlockIdentityCatalog.NormalizeSha256(item.Sha256)))).ToArray(),
        ParseHex(source.MaskedPatternHex),
        ParseHex(source.InvariantMaskHex));

    private static byte[] ParseHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }
        try
        {
            return Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
    }
}

internal sealed record TurboUnlockCalibration(
    double VerifiedScoreThreshold,
    double MaskedVerifiedScoreThreshold,
    int MinimumMatchingStableBlocks,
    int MinimumMatchingDiscriminativeBlocks,
    int MinimumMatchingInvariantBytes,
    int MinimumMarkerHits,
    bool Enabled,
    bool MaskedEnabled)
{
    internal static TurboUnlockCalibration FromDocument(TurboUnlockCalibrationDocument source)
    {
        if (source.VerifiedScoreThreshold is < 0 or > 1 || source.MaskedVerifiedScoreThreshold is < 0 or > 1 ||
            source.MinimumMatchingStableBlocks < 0 || source.MinimumMatchingDiscriminativeBlocks < 0 ||
            source.MinimumMatchingInvariantBytes < 0 || source.MinimumMarkerHits < 0)
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
        return new(
            source.VerifiedScoreThreshold,
            source.MaskedVerifiedScoreThreshold,
            source.MinimumMatchingStableBlocks,
            source.MinimumMatchingDiscriminativeBlocks,
            source.MinimumMatchingInvariantBytes,
            source.MinimumMarkerHits,
            source.Enabled,
            source.MaskedEnabled);
    }
}

internal sealed record TurboUnlockRawAnchor(int Offset, byte[] Needle);

internal sealed record TurboUnlockRawProfile(
    string Id,
    string Family,
    int Size,
    IReadOnlyList<TurboUnlockStableBlock> StableBlocks,
    byte[] MaskedPattern,
    byte[] InvariantMask,
    IReadOnlyList<TurboUnlockRawAnchor> Anchors,
    IReadOnlyList<uint> RequiredMsrs,
    double VerifiedScoreThreshold,
    int MinimumMatchingStableBlocks,
    int MinimumMatchingInvariantBytes,
    bool Enabled)
{
    internal static TurboUnlockRawProfile FromDocument(TurboUnlockRawProfileDocument source)
    {
        if (string.IsNullOrWhiteSpace(source.Id) || string.IsNullOrWhiteSpace(source.Family) || source.Size <= 0 ||
            source.Calibration.VerifiedScoreThreshold is < 0 or > 1 || source.Calibration.MinimumMatchingStableBlocks < 0 ||
            source.Calibration.MinimumMatchingInvariantBytes < 0)
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
        return new(
            source.Id.Trim(),
            source.Family.Trim(),
            source.Size,
            source.StableBlocks.Select(item => new TurboUnlockStableBlock(
                item.Offset,
                item.Length,
                Convert.FromHexString(TurboBoostUnlockIdentityCatalog.NormalizeSha256(item.Sha256)))).ToArray(),
            ParseHex(source.MaskedPatternHex),
            ParseHex(source.InvariantMaskHex),
            source.Anchors.Select(item => new TurboUnlockRawAnchor(item.Offset, ParseHex(item.Hex))).Where(item => item.Needle.Length != 0).ToArray(),
            source.RequiredMsrs.Distinct().OrderBy(value => value).ToArray(),
            source.Calibration.VerifiedScoreThreshold,
            source.Calibration.MinimumMatchingStableBlocks,
            source.Calibration.MinimumMatchingInvariantBytes,
            source.Calibration.Enabled);
    }

    internal bool IsVerified(ReadOnlySpan<byte> candidate)
    {
        if (!Enabled || candidate.Length != Size)
        {
            return false;
        }

        if (MaskedPattern.Length != 0 && InvariantMask.Length != 0)
        {
            int length = Math.Min(candidate.Length, Math.Min(MaskedPattern.Length, InvariantMask.Length));
            int matched = 0;
            int total = 0;
            for (int index = 0; index < length; index++)
            {
                if (InvariantMask[index] == 0)
                {
                    continue;
                }
                total++;
                if (candidate[index] == MaskedPattern[index])
                {
                    matched++;
                }
            }
            double score = total == 0 ? 0.0 : (double)matched / total;
            return score >= VerifiedScoreThreshold && matched >= MinimumMatchingInvariantBytes;
        }

        int matchingBlocks = 0;
        foreach (TurboUnlockStableBlock block in StableBlocks)
        {
            if (block.Offset >= 0 && block.Length > 0 && block.Offset <= candidate.Length - block.Length &&
                SHA256.HashData(candidate.Slice(block.Offset, block.Length)).AsSpan().SequenceEqual(block.Sha256))
            {
                matchingBlocks++;
            }
        }
        double blockScore = StableBlocks.Count == 0 ? 0.0 : (double)matchingBlocks / StableBlocks.Count;
        return blockScore >= VerifiedScoreThreshold && matchingBlocks >= MinimumMatchingStableBlocks;
    }

    private static byte[] ParseHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }
        try
        {
            return Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            throw new InvalidDataException(OperationError.TurboUnlockCatalog);
        }
    }
}

internal sealed class TurboUnlockCatalogDocument
{
    public int SchemaVersion { get; set; }
    public List<string> RetainedFamilies { get; set; } = [];
    public List<TurboUnlockHashIdentityDocument> ExactFfs { get; set; } = [];
    public List<TurboUnlockHashIdentityDocument> ExactExecutables { get; set; } = [];
    public List<string> KnownCleanExecutables { get; set; } = [];
    public List<TurboUnlockIdentityProfileDocument> PeProfiles { get; set; } = [];
    public List<TurboUnlockRawProfileDocument> RawProfiles { get; set; } = [];
}

internal sealed class TurboUnlockHashIdentityDocument
{
    public string Sha256 { get; set; } = string.Empty;
    public string Family { get; set; } = string.Empty;
}

internal sealed class TurboUnlockIdentityProfileDocument
{
    public string Id { get; set; } = string.Empty;
    public string Family { get; set; } = string.Empty;
    public string Machine { get; set; } = string.Empty;
    public string OptionalMagic { get; set; } = string.Empty;
    public int Subsystem { get; set; }
    public List<TurboUnlockSectionShapeDocument> Sections { get; set; } = [];
    public List<TurboUnlockCodeSectionProfileDocument> CodeSections { get; set; } = [];
    public List<uint> RequiredMsrs { get; set; } = [];
    public List<string> Markers { get; set; } = [];
    public TurboUnlockCalibrationDocument Calibration { get; set; } = new();
}

internal sealed class TurboUnlockSectionShapeDocument
{
    public int Index { get; set; }
    public string? Name { get; set; }
    public int RawSize { get; set; }
    public bool Executable { get; set; }
}

internal sealed class TurboUnlockCodeSectionProfileDocument
{
    public int Index { get; set; }
    public string? Name { get; set; }
    public int RawSize { get; set; }
    public List<TurboUnlockStableBlockDocument> StableBlocks { get; set; } = [];
    public string? MaskedPatternHex { get; set; }
    public string? InvariantMaskHex { get; set; }
}

internal sealed class TurboUnlockStableBlockDocument
{
    public int Offset { get; set; }
    public int Length { get; set; }
    public string Sha256 { get; set; } = string.Empty;
}

internal sealed class TurboUnlockCalibrationDocument
{
    public double VerifiedScoreThreshold { get; set; } = 1.0;
    public double MaskedVerifiedScoreThreshold { get; set; } = 1.0;
    public int MinimumMatchingStableBlocks { get; set; }
    public int MinimumMatchingDiscriminativeBlocks { get; set; }
    public int MinimumMatchingInvariantBytes { get; set; }
    public int MinimumMarkerHits { get; set; }
    public bool Enabled { get; set; } = true;
    public bool MaskedEnabled { get; set; }
}

internal sealed class TurboUnlockRawProfileDocument
{
    public string Id { get; set; } = string.Empty;
    public string Family { get; set; } = string.Empty;
    public int Size { get; set; }
    public List<TurboUnlockStableBlockDocument> StableBlocks { get; set; } = [];
    public string? MaskedPatternHex { get; set; }
    public string? InvariantMaskHex { get; set; }
    public List<TurboUnlockRawAnchorDocument> Anchors { get; set; } = [];
    public List<uint> RequiredMsrs { get; set; } = [];
    public TurboUnlockRawCalibrationDocument Calibration { get; set; } = new();
}

internal sealed class TurboUnlockRawAnchorDocument
{
    public int Offset { get; set; }
    public string? Hex { get; set; }
}

internal sealed class TurboUnlockRawCalibrationDocument
{
    public double VerifiedScoreThreshold { get; set; } = 1.0;
    public int MinimumMatchingStableBlocks { get; set; }
    public int MinimumMatchingInvariantBytes { get; set; }
    public bool Enabled { get; set; } = true;
}
