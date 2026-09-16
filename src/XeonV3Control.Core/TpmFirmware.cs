using System.Buffers.Binary;
using System.Text;

namespace XeonV3Control.Core;

public enum TpmFirmwareSupportStatus
{
    NoEvidence,
    SupportPresent,
    DiagnosticDriverInstalled,
    Inconclusive
}

public sealed record TpmFirmwareEvidence(string Key, int Occurrences);

public enum TpmTransportHint
{
    Unknown,
    Lpc,
    Spi
}

public sealed record TpmDescriptorReport(
    bool Available,
    int PchStrapBase,
    int DeclaredStrapCount,
    IReadOnlyList<uint> PchStraps,
    TpmTransportHint Transport)
{
    public static TpmDescriptorReport Empty { get; } = new(false, 0, 0, [], TpmTransportHint.Unknown);
}


/// <summary>
/// TPM-related information derived exclusively from bytes in the opened firmware image.
/// It deliberately does not query Windows, ACPI exposed by the running OS, WMI, registry, or TPM APIs.
/// </summary>
public sealed record TpmFirmwareReport(
    TpmFirmwareSupportStatus Status,
    bool DebugDriverInstalled,
    int DebugDriverCopies,
    IReadOnlyList<TpmFirmwareEvidence> Evidence,
    TpmDescriptorReport Descriptor)
{
    public static TpmFirmwareReport Empty { get; } = new(TpmFirmwareSupportStatus.NoEvidence, false, 0, [], TpmDescriptorReport.Empty);
}

public static class TpmFirmwareInspector
{
    public static readonly Guid DebugDriverFileGuid = new("9f0ebf4b-c7c8-4ed3-9eae-0ccecd34345a");
    private static readonly byte[] DebugDriverGuidBytes = DebugDriverFileGuid.ToByteArray();

    private static readonly (string Key, byte[] Ascii, byte[] Utf16)[] Markers =
    [
        Marker("TPM2"),
        Marker("TCG2"),
        Marker("Trusted Computing"),
        Marker("Security Device Support"),
        Marker("TPM Device Selection"),
        Marker("NO SECURE DEVICE"),
        Marker("MSFT0101"),
        Marker("TrEE"),
        Marker("PTP")
    ];

    public static TpmFirmwareReport Inspect(ReadOnlySpan<byte> source, UefiDriverReport drivers)
    {
        ArgumentNullException.ThrowIfNull(drivers);
        UefiDriverInfo[] debugDrivers = drivers.Drivers
            .Where(driver => driver.FileGuid == DebugDriverFileGuid)
            .ToArray();

        var excludedRanges = new List<(int Start, int End)>(FindDebugDriverRanges(source));
        int sourceLength = source.Length;
        foreach (UefiDriverInfo driver in debugDrivers)
        {
            if (driver.FileOffset < 0 || driver.FileSize <= 0 || driver.FileOffset > sourceLength - driver.FileSize)
            {
                continue;
            }

            int start = checked((int)driver.FileOffset);
            int end = checked(start + driver.FileSize);
            excludedRanges.Add((start, end));
        }

        (int Start, int End)[] excluded = excludedRanges
            .Distinct()
            .OrderBy(range => range.Start)
            .ToArray();

        var evidence = new List<TpmFirmwareEvidence>();
        foreach ((string key, byte[] ascii, byte[] utf16) in Markers)
        {
            // Do not let the diagnostic driver's own strings manufacture TPM evidence in a modified image.
            int occurrences = CountOutsideRanges(source, ascii, excluded) + CountOutsideRanges(source, utf16, excluded);
            if (occurrences != 0)
            {
                evidence.Add(new(key, occurrences));
            }
        }
        bool installed = debugDrivers.Length == 1;
        TpmFirmwareSupportStatus status = debugDrivers.Length > 1 || drivers.Incomplete
            ? TpmFirmwareSupportStatus.Inconclusive
            : installed
                ? TpmFirmwareSupportStatus.DiagnosticDriverInstalled
                : evidence.Count != 0
                    ? TpmFirmwareSupportStatus.SupportPresent
                    : TpmFirmwareSupportStatus.NoEvidence;
        return new(status, installed, debugDrivers.Length, evidence, InspectDescriptor(source));
    }

    private static TpmDescriptorReport InspectDescriptor(ReadOnlySpan<byte> source)
    {
        const uint descriptorSignature = 0x0FF0A55A;
        const int descriptorSignatureOffset = 0x10;
        const int flashMap1Offset = 0x18;
        const int descriptorBytes = 0x1000;
        if (source.Length < descriptorBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(descriptorSignatureOffset, 4)) != descriptorSignature)
        {
            return TpmDescriptorReport.Empty;
        }

        uint flmap1 = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(flashMap1Offset, 4));
        int pchStrapBase = checked((int)(flmap1 & 0xFFu) << 4);
        int declaredCount = checked((int)((flmap1 >> 24) & 0xFFu));
        if (declaredCount <= 0 || pchStrapBase < 0 || pchStrapBase > descriptorBytes - 4)
        {
            return new(true, pchStrapBase, declaredCount, [], TpmTransportHint.Unknown);
        }

        int availableCount = Math.Min(declaredCount, (descriptorBytes - pchStrapBase) / 4);
        var straps = new uint[availableCount];
        for (int index = 0; index < straps.Length; index++)
        {
            straps[index] = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(pchStrapBase + index * 4, 4));
        }

        // The public C610/X99 datasheet confirms that TPM transport is selected by a PCH soft strap,
        // but does not publish the specific descriptor bit.  Keep the interpretation fail-safe and
        // expose the raw strap words rather than inventing a board-specific hardcoded mapping.
        return new(true, pchStrapBase, declaredCount, straps, TpmTransportHint.Unknown);
    }

    private static IReadOnlyList<(int Start, int End)> FindDebugDriverRanges(ReadOnlySpan<byte> source)
    {
        var ranges = new List<(int Start, int End)>();
        int cursor = 0;
        while (cursor <= source.Length - AmiSecureBootSpecification.FfsFileHeaderBytes)
        {
            int relative = source[cursor..].IndexOf(DebugDriverGuidBytes);
            if (relative < 0) break;
            int start = checked(cursor + relative);
            if (start <= source.Length - AmiSecureBootSpecification.FfsFileHeaderBytes &&
                source[start + AmiSecureBootSpecification.FfsTypeOffset] == UefiPiCode.FfsDriver)
            {
                int size = source[start + AmiSecureBootSpecification.FfsSizeOffset] |
                    source[start + AmiSecureBootSpecification.FfsSizeOffset + 1] << 8 |
                    source[start + AmiSecureBootSpecification.FfsSizeOffset + 2] << 16;
                if (size >= AmiSecureBootSpecification.FfsFileHeaderBytes && size <= source.Length - start)
                {
                    ranges.Add((start, checked(start + size)));
                }
            }
            cursor = checked(start + DebugDriverGuidBytes.Length);
        }
        return ranges;
    }

    private static (string Key, byte[] Ascii, byte[] Utf16) Marker(string value) =>
        (value, Encoding.ASCII.GetBytes(value), Encoding.Unicode.GetBytes(value));

    private static int CountOutsideRanges(ReadOnlySpan<byte> source, ReadOnlySpan<byte> pattern, (int Start, int End)[] excluded)
    {
        if (excluded.Length == 0)
        {
            return CountNonOverlapping(source, pattern);
        }

        int count = 0;
        int cursor = 0;
        foreach ((int start, int end) in excluded)
        {
            if (start > cursor)
            {
                count += CountNonOverlapping(source[cursor..start], pattern);
            }
            if (end > cursor) cursor = end;
        }
        if (cursor < source.Length)
        {
            count += CountNonOverlapping(source[cursor..], pattern);
        }
        return count;
    }

    private static int CountNonOverlapping(ReadOnlySpan<byte> source, ReadOnlySpan<byte> pattern)
    {
        if (pattern.Length == 0 || source.Length < pattern.Length)
        {
            return 0;
        }

        int count = 0;
        int offset = 0;
        while (offset <= source.Length - pattern.Length)
        {
            int found = source[offset..].IndexOf(pattern);
            if (found < 0)
            {
                break;
            }
            count++;
            offset += found + pattern.Length;
        }
        return count;
    }
}
