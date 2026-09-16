using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace XeonV3Control.Core;

public enum BootLogoKind
{
    SmallAmi,
    LargeBoot
}

public enum PersonalizationFeatureStatus
{
    NotFound,
    Available,
    Unsupported
}

public enum StartupBeeperStatus
{
    NotFound,
    Enabled,
    Disabled,
    Unsupported
}

public sealed record BootLogoInfo(
    BootLogoKind Kind,
    PersonalizationFeatureStatus Status,
    Guid FileGuid,
    long VolumeOffset,
    long FileOffset,
    string FfsSha256,
    int Width,
    int Height,
    ushort BitsPerPixel,
    int BmpBytes,
    string BmpSha256)
{
    public ReadOnlyMemory<byte> BmpData { get; init; }

    public static BootLogoInfo Missing(BootLogoKind kind, Guid guid) =>
        new(kind, PersonalizationFeatureStatus.NotFound, guid, -1, -1, string.Empty, 0, 0, 0, 0, string.Empty);
}

public sealed record StartupBeeperInfo(
    StartupBeeperStatus Status,
    Guid FileGuid,
    long VolumeOffset,
    long FileOffset,
    string FfsSha256)
{
    public static StartupBeeperInfo Missing(Guid guid) =>
        new(StartupBeeperStatus.NotFound, guid, -1, -1, string.Empty);
}

public sealed record PersonalizationReport(
    BootLogoInfo SmallLogo,
    BootLogoInfo LargeLogo,
    StartupBeeperInfo Beeper)
{
    public static PersonalizationReport Empty { get; } = new(
        BootLogoInfo.Missing(BootLogoKind.SmallAmi, PersonalizationInspector.SmallAmiLogoFileGuid),
        BootLogoInfo.Missing(BootLogoKind.LargeBoot, PersonalizationInspector.LargeBootLogoFileGuid),
        StartupBeeperInfo.Missing(PersonalizationInspector.BdsFileGuid));
}

public static class PersonalizationInspector
{
    public static readonly Guid SmallAmiLogoFileGuid = new("63819805-67bb-46ef-aa8d-1524a19a01e4");
    public static readonly Guid LargeBootLogoFileGuid = new("7bb28b99-61bb-11d5-9a5d-0090273fc14d");
    public static readonly Guid BdsFileGuid = new("8f4b8f82-9b91-4028-86e6-f4db7d4c1dff");

    private static readonly Guid ConsoleInDevicesStartedProtocolGuid =
        new("2df1e051-906d-4eff-869d-24e65378fb9e");
    private static readonly byte[] BeeperFunctionName = Encoding.ASCII.GetBytes("ConInAvailabilityBeep\0");
    private static readonly byte[] ConInDevName = Encoding.Unicode.GetBytes("ConInDev\0");
    private static readonly byte[] BeeperGuidLeaPrefix = [0x48, 0x8D, 0x15];
    private static readonly byte[] BeeperNameLeaPrefix = [0x48, 0x8D, 0x0D];
    private static readonly byte[][] BeeperInlineDisabledPrefixes =
    [
        [0x31, 0xC0, 0xC3], // xor eax,eax; ret
        [0x33, 0xC0, 0xC3], // xor eax,eax; ret (alternate encoding)
        [0x29, 0xC0, 0xC3], // sub eax,eax; ret
        [0x2B, 0xC0, 0xC3]  // sub eax,eax; ret (alternate encoding)
    ];

    public static PersonalizationReport Inspect(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(image);
        BootLogoInfo small = InspectLogo(source, image, BootLogoKind.SmallAmi, SmallAmiLogoFileGuid, token);
        BootLogoInfo large = InspectLogo(source, image, BootLogoKind.LargeBoot, LargeBootLogoFileGuid, token);
        StartupBeeperInfo beeper = InspectBeeper(source, image, token);
        return new(small, large, beeper);
    }

    internal static bool TryReadLogoBmp(
        ReadOnlySpan<byte> source,
        BiosImage image,
        BootLogoKind kind,
        CancellationToken token,
        out AmiLzmaFfsEditor.LocatedFile located,
        out AmiLzmaFfsEditor.SectionInfo section,
        out byte[] bmp,
        out BmpInfo bmpInfo)
    {
        Guid guid = kind == BootLogoKind.SmallAmi ? SmallAmiLogoFileGuid : LargeBootLogoFileGuid;
        located = default;
        section = default;
        bmp = [];
        bmpInfo = default;
        if (!AmiLzmaFfsEditor.TryLocateUniqueFile(source, image, guid, token, out located))
        {
            return false;
        }

        ReadOnlySpan<byte> ffs = source.Slice(located.File.Offset, located.File.Size);
        if (!AmiLzmaFfsEditor.TryDecodeExpandedSectionStream(
                ffs,
                token,
                out byte[] expanded,
                out _,
                out _,
                out _) ||
            !AmiLzmaFfsEditor.TryReadSections(expanded, out IReadOnlyList<AmiLzmaFfsEditor.SectionInfo> sections))
        {
            return false;
        }

        AmiLzmaFfsEditor.SectionInfo[] rawBmpSections = sections
            .Where(item => item.Type == AmiSecureBootSpecification.RawSectionType &&
                item.HeaderSize == AmiSecureBootSpecification.SectionHeaderBytes &&
                item.Size > item.HeaderSize + BmpInfo.MinimumHeaderBytes &&
                expanded[item.Offset + item.HeaderSize] == (byte)'B' &&
                expanded[item.Offset + item.HeaderSize + 1] == (byte)'M')
            .ToArray();
        if (rawBmpSections.Length != 1)
        {
            return false;
        }

        section = rawBmpSections[0];
        bmp = expanded.AsSpan(section.Offset + section.HeaderSize, section.Size - section.HeaderSize).ToArray();
        return BmpInfo.TryParse(bmp, out bmpInfo);
    }

    internal static bool TryLocateBeeperFunction(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token,
        out AmiLzmaFfsEditor.LocatedFile located,
        out AmiLzmaFfsEditor.SectionInfo peSection,
        out byte[] expanded,
        out int functionFileOffset,
        out StartupBeeperStatus status)
    {
        located = default;
        peSection = default;
        expanded = [];
        functionFileOffset = 0;
        status = StartupBeeperStatus.Unsupported;
        if (!AmiLzmaFfsEditor.TryLocateUniqueFile(source, image, BdsFileGuid, token, out located))
        {
            status = StartupBeeperStatus.NotFound;
            return false;
        }

        ReadOnlySpan<byte> ffs = source.Slice(located.File.Offset, located.File.Size);
        if (!AmiLzmaFfsEditor.TryDecodeExpandedSectionStream(
                ffs,
                token,
                out expanded,
                out _,
                out _,
                out _) ||
            !AmiLzmaFfsEditor.TryReadSections(expanded, out IReadOnlyList<AmiLzmaFfsEditor.SectionInfo> sections))
        {
            return false;
        }

        AmiLzmaFfsEditor.SectionInfo[] peSections = sections
            .Where(item => item.Type == UefiPiCode.SectionPe32 && item.Size > item.HeaderSize + 0x100)
            .ToArray();
        if (peSections.Length != 1)
        {
            return false;
        }
        peSection = peSections[0];
        ReadOnlySpan<byte> pe = expanded.AsSpan(peSection.Offset + peSection.HeaderSize, peSection.Size - peSection.HeaderSize);
        if (!PeLayout.TryParse(pe, out PeLayout layout) ||
            !TryFindBeeperFunction(pe, layout, out functionFileOffset, out status))
        {
            status = StartupBeeperStatus.Unsupported;
            return false;
        }
        return true;
    }

    private static BootLogoInfo InspectLogo(
        ReadOnlySpan<byte> source,
        BiosImage image,
        BootLogoKind kind,
        Guid guid,
        CancellationToken token)
    {
        if (TryReadLogoBmp(
                source,
                image,
                kind,
                token,
                out AmiLzmaFfsEditor.LocatedFile located,
                out _,
                out byte[] bmp,
                out BmpInfo info))
        {
            return new(
                kind,
                PersonalizationFeatureStatus.Available,
                guid,
                located.Volume.Offset,
                located.File.Offset,
                located.Sha256,
                info.Width,
                info.Height,
                info.BitsPerPixel,
                bmp.Length,
                Convert.ToHexString(SHA256.HashData(bmp)))
            {
                BmpData = bmp
            };
        }

        if (!AmiLzmaFfsEditor.TryLocateUniqueFile(source, image, guid, token, out located))
        {
            return BootLogoInfo.Missing(kind, guid);
        }
        return new(kind, PersonalizationFeatureStatus.Unsupported, guid,
            located.Volume.Offset, located.File.Offset, located.Sha256, 0, 0, 0, 0, string.Empty);
    }

    private static StartupBeeperInfo InspectBeeper(
        ReadOnlySpan<byte> source,
        BiosImage image,
        CancellationToken token)
    {
        _ = TryLocateBeeperFunction(
            source,
            image,
            token,
            out AmiLzmaFfsEditor.LocatedFile located,
            out _,
            out _,
            out _,
            out StartupBeeperStatus status);
        if (status == StartupBeeperStatus.NotFound)
        {
            return StartupBeeperInfo.Missing(BdsFileGuid);
        }
        return new(status, BdsFileGuid, located.Volume.Offset, located.File.Offset, located.Sha256);
    }

    private static bool TryFindBeeperFunction(
        ReadOnlySpan<byte> pe,
        PeLayout layout,
        out int functionFileOffset,
        out StartupBeeperStatus status)
    {
        functionFileOffset = 0;
        status = StartupBeeperStatus.Unsupported;
        int nameFileOffset = pe.IndexOf(BeeperFunctionName);
        if (nameFileOffset < 0 ||
            pe[(nameFileOffset + 1)..].IndexOf(BeeperFunctionName) >= 0 ||
            !layout.TryFileOffsetToRva(nameFileOffset, out uint nameRva))
        {
            return false;
        }

        Span<byte> namePointer = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(namePointer, nameRva);
        var references = new List<int>();
        int scan = 0;
        while (scan <= pe.Length - sizeof(ulong))
        {
            int relative = pe[scan..].IndexOf(namePointer);
            if (relative < 0)
            {
                break;
            }
            int reference = scan + relative;
            if ((reference & 7) == 0)
            {
                references.Add(reference);
            }
            scan = reference + 1;
        }
        if (references.Count != 1)
        {
            return false;
        }

        int targetNameEntry = references[0];
        int nameTableStart = targetNameEntry;
        while (nameTableStart >= sizeof(ulong) &&
               IsAsciiIdentifierPointer(pe, layout, nameTableStart - sizeof(ulong)))
        {
            nameTableStart -= sizeof(ulong);
        }
        int nameTableEnd = targetNameEntry + sizeof(ulong);
        while (nameTableEnd <= pe.Length - sizeof(ulong) &&
               IsAsciiIdentifierPointer(pe, layout, nameTableEnd))
        {
            nameTableEnd += sizeof(ulong);
        }

        int entryCount = (nameTableEnd - nameTableStart) / sizeof(ulong);
        int targetIndex = (targetNameEntry - nameTableStart) / sizeof(ulong);
        if (entryCount < 20 || targetIndex < 0 || targetIndex >= entryCount)
        {
            return false;
        }

        var candidates = new List<(int Offset, StartupBeeperStatus Status)>();
        for (int gapQwords = 0; gapQwords <= 4; gapQwords++)
        {
            int functionTableStart = nameTableStart - ((entryCount + gapQwords) * sizeof(ulong));
            if (functionTableStart < 0 || functionTableStart > pe.Length - entryCount * sizeof(ulong))
            {
                continue;
            }
            int pointerOffset = functionTableStart + targetIndex * sizeof(ulong);
            ulong functionRva64 = BinaryPrimitives.ReadUInt64LittleEndian(pe[pointerOffset..]);
            if (functionRva64 > uint.MaxValue ||
                !layout.TryRvaToFileOffset((uint)functionRva64, out int candidateOffset) ||
                !layout.IsExecutableRva((uint)functionRva64))
            {
                continue;
            }
            if (TryClassifyBeeperFunction(pe, layout, (uint)functionRva64, candidateOffset, out StartupBeeperStatus candidateStatus))
            {
                candidates.Add((candidateOffset, candidateStatus));
            }
        }

        (int Offset, StartupBeeperStatus Status)[] distinct = candidates.Distinct().ToArray();
        if (distinct.Length != 1)
        {
            return false;
        }
        functionFileOffset = distinct[0].Offset;
        status = distinct[0].Status;
        return true;
    }

    private static bool TryClassifyBeeperFunction(
        ReadOnlySpan<byte> pe,
        PeLayout layout,
        uint functionRva,
        int functionOffset,
        out StartupBeeperStatus status)
    {
        status = StartupBeeperStatus.Unsupported;
        const int BodyBytes = 19;
        if (functionOffset < 0 || functionOffset > pe.Length - BodyBytes)
        {
            return false;
        }

        ReadOnlySpan<byte> body = pe.Slice(functionOffset, BodyBytes);
        bool originalLayout = body.Slice(7, BeeperNameLeaPrefix.Length).SequenceEqual(BeeperNameLeaPrefix);
        bool swappedLayout = body.Slice(7, BeeperGuidLeaPrefix.Length).SequenceEqual(BeeperGuidLeaPrefix);
        bool enabled =
            (body[..BeeperGuidLeaPrefix.Length].SequenceEqual(BeeperGuidLeaPrefix) && originalLayout) ||
            (body[..BeeperNameLeaPrefix.Length].SequenceEqual(BeeperNameLeaPrefix) && swappedLayout);
        bool inlineDisabled = MatchesInlineDisabledPrefix(body) && (originalLayout || swappedLayout);
        bool trampolineDisabled = false;
        uint guidRva;
        uint conInDevRva;

        if ((!originalLayout && !swappedLayout) || body[14] != 0xE9)
        {
            return false;
        }

        if (originalLayout)
        {
            if (enabled || inlineDisabled)
            {
                int guidDisplacement = BinaryPrimitives.ReadInt32LittleEndian(body[3..]);
                if (!TryAddRelative(functionRva, 7, guidDisplacement, out guidRva))
                {
                    return false;
                }
            }
            else if (body[0] == 0xE9)
            {
                int trampolineDisplacement = BinaryPrimitives.ReadInt32LittleEndian(body[1..]);
                if (!TryAddRelative(functionRva, 5, trampolineDisplacement, out uint trampolineRva) ||
                    !layout.TryRvaToFileOffset(trampolineRva, out int trampolineOffset) ||
                    !layout.IsExecutableRva(trampolineRva) ||
                    !IsZeroReturnStub(pe, trampolineOffset) ||
                    !TryFindUniqueGuidRva(pe, layout, ConsoleInDevicesStartedProtocolGuid, out guidRva))
                {
                    return false;
                }
                trampolineDisabled = true;
            }
            else
            {
                return false;
            }

            int nameDisplacement = BinaryPrimitives.ReadInt32LittleEndian(body[10..]);
            if (!TryAddRelative(functionRva, 14, nameDisplacement, out conInDevRva))
            {
                return false;
            }
        }
        else
        {
            if (!enabled && !inlineDisabled)
            {
                return false;
            }
            int nameDisplacement = BinaryPrimitives.ReadInt32LittleEndian(body[3..]);
            int guidDisplacement = BinaryPrimitives.ReadInt32LittleEndian(body[10..]);
            if (!TryAddRelative(functionRva, 7, nameDisplacement, out conInDevRva) ||
                !TryAddRelative(functionRva, 14, guidDisplacement, out guidRva))
            {
                return false;
            }
        }

        int jumpDisplacement = BinaryPrimitives.ReadInt32LittleEndian(body[15..]);
        if (!TryAddRelative(functionRva, 19, jumpDisplacement, out uint jumpRva) ||
            !layout.TryRvaToFileOffset(guidRva, out int guidOffset) ||
            !layout.TryRvaToFileOffset(conInDevRva, out int conInDevOffset) ||
            !layout.TryRvaToFileOffset(jumpRva, out _) ||
            !layout.IsExecutableRva(jumpRva) ||
            guidOffset > pe.Length - 16 ||
            conInDevOffset > pe.Length - ConInDevName.Length ||
            new Guid(pe.Slice(guidOffset, 16)) != ConsoleInDevicesStartedProtocolGuid ||
            !pe.Slice(conInDevOffset, ConInDevName.Length).SequenceEqual(ConInDevName))
        {
            return false;
        }

        status = enabled ? StartupBeeperStatus.Enabled :
            inlineDisabled || trampolineDisabled ? StartupBeeperStatus.Disabled : StartupBeeperStatus.Unsupported;
        return status != StartupBeeperStatus.Unsupported;
    }

    internal static bool TryBuildBeeperDisablePatches(
        ReadOnlySpan<byte> expanded,
        AmiLzmaFfsEditor.SectionInfo peSection,
        int functionFileOffset,
        out IReadOnlyList<byte[]> patches)
    {
        patches = [];
        if (peSection.Type != UefiPiCode.SectionPe32 ||
            peSection.HeaderSize <= 0 ||
            peSection.Size <= peSection.HeaderSize ||
            peSection.Offset < 0 ||
            peSection.Offset > expanded.Length - peSection.Size)
        {
            return false;
        }

        ReadOnlySpan<byte> pe = expanded.Slice(
            peSection.Offset + peSection.HeaderSize,
            peSection.Size - peSection.HeaderSize);
        if (!PeLayout.TryParse(pe, out PeLayout layout) ||
            !layout.TryFileOffsetToRva(functionFileOffset, out uint functionRva))
        {
            return false;
        }

        bool swappedLayout = functionFileOffset >= 0 &&
            functionFileOffset <= pe.Length - 10 &&
            pe.Slice(functionFileOffset, BeeperNameLeaPrefix.Length).SequenceEqual(BeeperNameLeaPrefix) &&
            pe.Slice(functionFileOffset + 7, BeeperGuidLeaPrefix.Length).SequenceEqual(BeeperGuidLeaPrefix);
        byte[]? canonicalEnabledBody = null;
        if (swappedLayout)
        {
            if (!TryBuildBeeperEnablePatches(
                    expanded, peSection, functionFileOffset, out IReadOnlyList<byte[]> enablePatches))
            {
                return false;
            }
            canonicalEnabledBody = enablePatches[0];
        }

        var result = new List<byte[]>();
        // Search backwards so compact forward rel32 trampolines (typically xx xx 00 00) are tried first.
        // The destination must be executable code that is itself a complete "return EFI_SUCCESS" leaf.
        for (int offset = pe.Length - 3; offset >= 0; offset--)
        {
            if (!IsZeroReturnStub(pe, offset) ||
                !layout.TryFileOffsetToRva(offset, out uint targetRva) ||
                !layout.IsExecutableRva(targetRva))
            {
                continue;
            }

            long displacement = (long)targetRva - ((long)functionRva + 5);
            if (displacement is < int.MinValue or > int.MaxValue)
            {
                continue;
            }

            byte[] trampoline = new byte[5];
            trampoline[0] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(trampoline.AsSpan(1), (int)displacement);
            byte[] patch;
            if (canonicalEnabledBody is null)
            {
                patch = trampoline;
            }
            else
            {
                patch = canonicalEnabledBody.ToArray();
                trampoline.CopyTo(patch, 0);
            }

            bool duplicate = false;
            foreach (byte[] existing in result)
            {
                if (existing.AsSpan().SequenceEqual(patch))
                {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate)
            {
                result.Add(patch);
                if (result.Count >= 24)
                {
                    break;
                }
            }
        }

        // Preserve both RIP-relative targets. For the compact swapped enabled layout, normalize the
        // complete body first so every subsequent toggle can reuse the original compact disabled form.
        foreach (byte[] prefix in BeeperInlineDisabledPrefixes)
        {
            if (canonicalEnabledBody is null)
            {
                result.Add(prefix.ToArray());
            }
            else
            {
                byte[] patch = canonicalEnabledBody.ToArray();
                prefix.CopyTo(patch, 0);
                result.Add(patch);
            }
        }

        patches = result;
        return result.Count != 0;
    }

    internal static bool TryBuildBeeperEnablePatch(
        ReadOnlySpan<byte> expanded,
        AmiLzmaFfsEditor.SectionInfo peSection,
        int functionFileOffset,
        out byte[] patch)
    {
        patch = [];
        if (!TryBuildBeeperEnablePatches(expanded, peSection, functionFileOffset, out IReadOnlyList<byte[]> patches))
        {
            return false;
        }
        patch = patches[0][..7];
        return true;
    }

    internal static bool TryBuildBeeperEnablePatches(
        ReadOnlySpan<byte> expanded,
        AmiLzmaFfsEditor.SectionInfo peSection,
        int functionFileOffset,
        out IReadOnlyList<byte[]> patches)
    {
        patches = [];
        if (peSection.Type != UefiPiCode.SectionPe32 ||
            peSection.HeaderSize <= 0 ||
            peSection.Size <= peSection.HeaderSize ||
            peSection.Offset < 0 ||
            peSection.Offset > expanded.Length - peSection.Size)
        {
            return false;
        }

        ReadOnlySpan<byte> pe = expanded.Slice(
            peSection.Offset + peSection.HeaderSize,
            peSection.Size - peSection.HeaderSize);
        if (!PeLayout.TryParse(pe, out PeLayout layout) ||
            !layout.TryFileOffsetToRva(functionFileOffset, out uint functionRva) ||
            !TryFindUniqueGuidRva(pe, layout, ConsoleInDevicesStartedProtocolGuid, out uint guidRva) ||
            !TryFindUniqueRva(pe, layout, ConInDevName, out uint nameRva))
        {
            return false;
        }

        if (!TryBuildLea(functionRva, 0, BeeperGuidLeaPrefix, guidRva, out byte[] originalGuid) ||
            !TryBuildLea(functionRva, 7, BeeperNameLeaPrefix, nameRva, out byte[] originalName) ||
            !TryBuildLea(functionRva, 0, BeeperNameLeaPrefix, nameRva, out byte[] swappedName) ||
            !TryBuildLea(functionRva, 7, BeeperGuidLeaPrefix, guidRva, out byte[] swappedGuid))
        {
            return false;
        }

        byte[] original = new byte[14];
        originalGuid.CopyTo(original, 0);
        originalName.CopyTo(original, 7);
        byte[] swapped = new byte[14];
        swappedName.CopyTo(swapped, 0);
        swappedGuid.CopyTo(swapped, 7);
        patches = [original, swapped];
        return true;
    }

    private static bool TryBuildLea(
        uint functionRva,
        int instructionOffset,
        ReadOnlySpan<byte> prefix,
        uint targetRva,
        out byte[] instruction)
    {
        instruction = [];
        const int InstructionBytes = 7;
        long displacement = (long)targetRva - ((long)functionRva + instructionOffset + InstructionBytes);
        if (prefix.Length != 3 || displacement is < int.MinValue or > int.MaxValue)
        {
            return false;
        }
        instruction = new byte[InstructionBytes];
        prefix.CopyTo(instruction);
        BinaryPrimitives.WriteInt32LittleEndian(instruction.AsSpan(prefix.Length), (int)displacement);
        return true;
    }

    private static bool IsZeroReturnStub(ReadOnlySpan<byte> pe, int offset)
    {
        if (offset < 0 || offset > pe.Length - 3)
        {
            return false;
        }
        return MatchesInlineDisabledPrefix(pe.Slice(offset, 3));
    }

    private static bool MatchesInlineDisabledPrefix(ReadOnlySpan<byte> body)
    {
        foreach (byte[] prefix in BeeperInlineDisabledPrefixes)
        {
            if (body.Length >= prefix.Length && body[..prefix.Length].SequenceEqual(prefix))
            {
                return true;
            }
        }
        return false;
    }

    private static bool TryFindUniqueGuidRva(
        ReadOnlySpan<byte> pe,
        PeLayout layout,
        Guid guid,
        out uint rva) =>
        TryFindUniqueRva(pe, layout, guid.ToByteArray(), out rva);

    private static bool TryFindUniqueRva(
        ReadOnlySpan<byte> pe,
        PeLayout layout,
        ReadOnlySpan<byte> needle,
        out uint rva)
    {
        rva = 0;
        if (needle.IsEmpty)
        {
            return false;
        }
        int offset = pe.IndexOf(needle);
        if (offset < 0 ||
            pe[(offset + 1)..].IndexOf(needle) >= 0 ||
            !layout.TryFileOffsetToRva(offset, out rva))
        {
            rva = 0;
            return false;
        }
        return true;
    }

    private static bool IsAsciiIdentifierPointer(ReadOnlySpan<byte> pe, PeLayout layout, int pointerFileOffset)
    {
        if (pointerFileOffset < 0 || pointerFileOffset > pe.Length - sizeof(ulong))
        {
            return false;
        }
        ulong rva64 = BinaryPrimitives.ReadUInt64LittleEndian(pe[pointerFileOffset..]);
        if (rva64 == 0 || rva64 > uint.MaxValue || !layout.TryRvaToFileOffset((uint)rva64, out int offset))
        {
            return false;
        }
        int length = 0;
        while (offset + length < pe.Length && length <= 96)
        {
            byte value = pe[offset + length];
            if (value == 0)
            {
                return length is > 0 and <= 96;
            }
            bool valid = (value >= (byte)'A' && value <= (byte)'Z') ||
                (value >= (byte)'a' && value <= (byte)'z') ||
                (value >= (byte)'0' && value <= (byte)'9') ||
                value == (byte)'_';
            if (!valid)
            {
                return false;
            }
            length++;
        }
        return false;
    }

    private static bool TryAddRelative(uint baseRva, int instructionLength, int displacement, out uint result)
    {
        long value = (long)baseRva + instructionLength + displacement;
        if (value < 0 || value > uint.MaxValue)
        {
            result = 0;
            return false;
        }
        result = (uint)value;
        return true;
    }

    internal readonly record struct BmpInfo(
        int Width,
        int Height,
        bool TopDown,
        ushort BitsPerPixel,
        uint Compression,
        uint DibHeaderSize,
        int PixelOffset,
        int FileSize)
    {
        internal const int MinimumHeaderBytes = 54;

        internal static bool TryParse(ReadOnlySpan<byte> data, out BmpInfo info)
        {
            info = default;
            if (data.Length < MinimumHeaderBytes || data[0] != (byte)'B' || data[1] != (byte)'M')
            {
                return false;
            }
            uint declaredSize = BinaryPrimitives.ReadUInt32LittleEndian(data[2..]);
            uint pixelOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[10..]);
            uint dibSize = BinaryPrimitives.ReadUInt32LittleEndian(data[14..]);
            int width = BinaryPrimitives.ReadInt32LittleEndian(data[18..]);
            int signedHeight = BinaryPrimitives.ReadInt32LittleEndian(data[22..]);
            ushort planes = BinaryPrimitives.ReadUInt16LittleEndian(data[26..]);
            ushort bits = BinaryPrimitives.ReadUInt16LittleEndian(data[28..]);
            uint compression = BinaryPrimitives.ReadUInt32LittleEndian(data[30..]);
            if (declaredSize != data.Length || dibSize < 40 || width <= 0 || signedHeight == 0 ||
                signedHeight == int.MinValue || planes != 1 ||
                bits is not (1 or 4 or 8 or 16 or 24 or 32) ||
                compression != 0 ||
                pixelOffset < 14 + dibSize || pixelOffset >= data.Length)
            {
                return false;
            }
            int height = Math.Abs(signedHeight);
            long requiredPixels;
            try
            {
                long rowBits = checked((long)width * bits);
                long rowBytes = checked(((rowBits + 31) / 32) * 4);
                requiredPixels = checked(rowBytes * height);
            }
            catch (OverflowException)
            {
                return false;
            }
            if (requiredPixels <= 0 || requiredPixels > data.Length - pixelOffset)
            {
                return false;
            }
            info = new(
                width,
                height,
                signedHeight < 0,
                bits,
                compression,
                dibSize,
                checked((int)pixelOffset),
                data.Length);
            return true;
        }
    }

    private readonly record struct PeSection(
        uint VirtualAddress,
        uint VirtualSize,
        uint RawAddress,
        uint RawSize,
        uint Characteristics);

    private sealed class PeLayout
    {
        private const uint SectionMemExecute = 0x20000000;
        private readonly int headerSize;
        private readonly IReadOnlyList<PeSection> sections;

        private PeLayout(int headerSize, IReadOnlyList<PeSection> sections)
        {
            this.headerSize = headerSize;
            this.sections = sections;
        }

        internal static bool TryParse(ReadOnlySpan<byte> pe, out PeLayout layout)
        {
            layout = null!;
            if (pe.Length < 0x100 || BinaryPrimitives.ReadUInt16LittleEndian(pe) != 0x5A4D)
            {
                return false;
            }
            int peOffset = BinaryPrimitives.ReadInt32LittleEndian(pe[0x3C..]);
            if (peOffset < 0x40 || peOffset > pe.Length - 24 ||
                BinaryPrimitives.ReadUInt32LittleEndian(pe[peOffset..]) != 0x00004550)
            {
                return false;
            }
            ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(pe[(peOffset + 6)..]);
            ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(pe[(peOffset + 20)..]);
            int optionalOffset = peOffset + 24;
            if (sectionCount is 0 or > 96 || optionalSize < 64 || optionalOffset > pe.Length - optionalSize)
            {
                return false;
            }
            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(pe[optionalOffset..]);
            if (magic is not (0x10B or 0x20B))
            {
                return false;
            }
            uint sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(pe[(optionalOffset + 60)..]);
            if (sizeOfHeaders == 0 || sizeOfHeaders > pe.Length)
            {
                return false;
            }
            int sectionTable = optionalOffset + optionalSize;
            if (sectionTable > pe.Length - sectionCount * 40)
            {
                return false;
            }

            var sections = new List<PeSection>(sectionCount);
            for (int index = 0; index < sectionCount; index++)
            {
                int offset = sectionTable + index * 40;
                uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(pe[(offset + 8)..]);
                uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(pe[(offset + 12)..]);
                uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(pe[(offset + 16)..]);
                uint rawAddress = BinaryPrimitives.ReadUInt32LittleEndian(pe[(offset + 20)..]);
                uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(pe[(offset + 36)..]);
                if (rawSize != 0 && (rawAddress > pe.Length || rawSize > pe.Length - rawAddress))
                {
                    return false;
                }
                sections.Add(new(virtualAddress, virtualSize, rawAddress, rawSize, characteristics));
            }
            layout = new(checked((int)sizeOfHeaders), sections);
            return true;
        }

        internal bool TryRvaToFileOffset(uint rva, out int offset)
        {
            if (rva < headerSize)
            {
                offset = checked((int)rva);
                return true;
            }
            foreach (PeSection section in sections)
            {
                uint mappedSize = Math.Max(section.VirtualSize, section.RawSize);
                if (rva < section.VirtualAddress || (ulong)rva >= (ulong)section.VirtualAddress + mappedSize)
                {
                    continue;
                }
                uint delta = rva - section.VirtualAddress;
                if (delta >= section.RawSize)
                {
                    break;
                }
                offset = checked((int)(section.RawAddress + delta));
                return true;
            }
            offset = 0;
            return false;
        }

        internal bool TryFileOffsetToRva(int fileOffset, out uint rva)
        {
            if (fileOffset < 0)
            {
                rva = 0;
                return false;
            }
            if (fileOffset < headerSize)
            {
                rva = checked((uint)fileOffset);
                return true;
            }
            foreach (PeSection section in sections)
            {
                if ((uint)fileOffset < section.RawAddress ||
                    (ulong)(uint)fileOffset >= (ulong)section.RawAddress + section.RawSize)
                {
                    continue;
                }
                rva = checked(section.VirtualAddress + ((uint)fileOffset - section.RawAddress));
                return true;
            }
            rva = 0;
            return false;
        }

        internal bool IsExecutableRva(uint rva)
        {
            foreach (PeSection section in sections)
            {
                uint mappedSize = Math.Max(section.VirtualSize, section.RawSize);
                if (rva >= section.VirtualAddress &&
                    (ulong)rva < (ulong)section.VirtualAddress + mappedSize)
                {
                    return (section.Characteristics & SectionMemExecute) != 0;
                }
            }
            return false;
        }
    }
}

