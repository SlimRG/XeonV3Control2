using System.Text;
using System.Text.Json;

namespace XeonV3Control.Core;

/// <summary>
/// Identity supported only by bytes in the analyzed firmware image. Values that cannot be proven
/// from that image (for example a per-machine board serial number absent from a stock BIOS) remain null.
/// </summary>
public sealed record FirmwareImageIdentity(
    string? BiosManufacturer,
    string? BiosVersion,
    string? BiosReleaseDate,
    string? BoardManufacturer,
    string? BoardName,
    string? BoardVersion,
    string? BoardSerialNumber)
{
    public static FirmwareImageIdentity Empty { get; } = new(null, null, null, null, null, null, null);
}

internal static class FirmwareImageIdentityInspector
{
    private const int MaximumAsciiFieldBytes = 160;
    private const int MaximumFidProbeBytes = 96;
    private static readonly byte[] BiosMessageMarker = Encoding.ASCII.GetBytes("BIOS Message:");
    private static readonly byte[] FidMarker = Encoding.ASCII.GetBytes("$FID");
    private static readonly (byte[] Marker, string Name)[] VendorMarkers =
    [
        (Encoding.ASCII.GetBytes("American Megatrends, Inc."), "American Megatrends, Inc."),
        (Encoding.ASCII.GetBytes("American Megatrends"), "American Megatrends, Inc."),
        (Encoding.ASCII.GetBytes("Phoenix Technologies"), "Phoenix Technologies"),
        (Encoding.ASCII.GetBytes("Insyde Software"), "Insyde Software")
    ];
    private static readonly FirmwareBoardIdentityCatalog BoardCatalog = FirmwareBoardIdentityCatalog.LoadOrEmpty();

    internal static FirmwareImageIdentity Inspect(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return FirmwareImageIdentity.Empty;
        }

        string? biosMessage = TryReadAsciiValue(source, BiosMessageMarker, MaximumAsciiFieldBytes);
        string? biosVersion = null;
        string? biosReleaseDate = null;
        string? biosId = null;
        if (!string.IsNullOrWhiteSpace(biosMessage))
        {
            ParseBiosMessage(biosMessage, out biosVersion, out biosReleaseDate);
            biosId = FirstToken(biosVersion);
        }
        biosId ??= TryReadFidBiosId(source);

        FirmwareBoardIdentityEntry? board = BoardCatalog.Find(biosId);
        return new(
            DetectVendor(source),
            biosVersion ?? biosId,
            biosReleaseDate,
            board?.Manufacturer,
            board?.Name,
            board?.Version,
            null);
    }

    private static string? DetectVendor(ReadOnlySpan<byte> source)
    {
        foreach ((byte[] marker, string name) in VendorMarkers)
        {
            if (source.IndexOf(marker) >= 0)
            {
                return name;
            }
        }
        return null;
    }

    private static string? TryReadAsciiValue(ReadOnlySpan<byte> source, ReadOnlySpan<byte> marker, int maximumBytes)
    {
        int markerOffset = source.IndexOf(marker);
        if (markerOffset < 0)
        {
            return null;
        }

        int start = checked(markerOffset + marker.Length);
        while (start < source.Length && source[start] == (byte)' ')
        {
            start++;
        }
        int end = start;
        int limit = Math.Min(source.Length, checked(start + Math.Min(maximumBytes, source.Length - start)));
        while (end < limit)
        {
            byte value = source[end];
            if (value == 0 || value is (byte)'\r' or (byte)'\n' || value < 0x20 || value > 0x7E)
            {
                break;
            }
            end++;
        }

        return end == start ? null : Encoding.ASCII.GetString(source[start..end]).Trim();
    }

    private static void ParseBiosMessage(string message, out string? version, out string? date)
    {
        version = null;
        date = null;
        for (int index = 0; index <= message.Length - 10; index++)
        {
            if (!LooksLikeDate(message, index))
            {
                continue;
            }

            date = message.Substring(index, 10);
            string prefix = message[..index].Trim();
            version = string.IsNullOrWhiteSpace(prefix) ? null : prefix;
            return;
        }

        version = string.IsNullOrWhiteSpace(message) ? null : message.Trim();
    }

    private static bool LooksLikeDate(string value, int offset) =>
        char.IsAsciiDigit(value[offset]) && char.IsAsciiDigit(value[offset + 1]) &&
        value[offset + 2] == '/' &&
        char.IsAsciiDigit(value[offset + 3]) && char.IsAsciiDigit(value[offset + 4]) &&
        value[offset + 5] == '/' &&
        char.IsAsciiDigit(value[offset + 6]) && char.IsAsciiDigit(value[offset + 7]) &&
        char.IsAsciiDigit(value[offset + 8]) && char.IsAsciiDigit(value[offset + 9]);

    private static string? FirstToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        int separator = value.IndexOf(' ');
        return separator < 0 ? value : value[..separator];
    }

    private static string? TryReadFidBiosId(ReadOnlySpan<byte> source)
    {
        int markerOffset = source.IndexOf(FidMarker);
        if (markerOffset < 0)
        {
            return null;
        }

        int start = checked(markerOffset + FidMarker.Length);
        int end = Math.Min(source.Length, checked(start + Math.Min(MaximumFidProbeBytes, source.Length - start)));
        for (int index = start; index < end;)
        {
            while (index < end && !IsBiosIdCharacter(source[index]))
            {
                index++;
            }
            int tokenStart = index;
            while (index < end && IsBiosIdCharacter(source[index]))
            {
                index++;
            }
            int length = index - tokenStart;
            if (length >= 5)
            {
                string token = Encoding.ASCII.GetString(source.Slice(tokenStart, length));
                if (token.Any(char.IsAsciiLetter) && token.Any(char.IsAsciiDigit))
                {
                    return token;
                }
            }
        }
        return null;
    }

    private static bool IsBiosIdCharacter(byte value) =>
        value is >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_';
}

internal sealed record FirmwareBoardIdentityEntry(
    string BiosIdPrefix,
    string Manufacturer,
    string Name,
    string? Version);

internal sealed record FirmwareBoardIdentityCatalogDocument(
    int SchemaVersion,
    IReadOnlyList<FirmwareBoardIdentityEntry> Boards);

internal sealed class FirmwareBoardIdentityCatalog
{
    private readonly IReadOnlyList<FirmwareBoardIdentityEntry> boards;

    private FirmwareBoardIdentityCatalog(IReadOnlyList<FirmwareBoardIdentityEntry> boards) => this.boards = boards;

    internal static FirmwareBoardIdentityCatalog LoadOrEmpty()
    {
        try
        {
            return Load();
        }
        catch (InvalidDataException)
        {
            return new([]);
        }
        catch (JsonException)
        {
            return new([]);
        }
    }

    private static FirmwareBoardIdentityCatalog Load()
    {
        string resourceName = EmbeddedResourceNames.File(
            EmbeddedResourceNames.FirmwareFolder,
            "firmware-board-identities.json");
        using Stream resource = typeof(FirmwareBoardIdentityCatalog).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException("FirmwareIdentityCatalog");
        FirmwareBoardIdentityCatalogDocument document =
            JsonSerializer.Deserialize<FirmwareBoardIdentityCatalogDocument>(resource)
            ?? throw new InvalidDataException("FirmwareIdentityCatalog");
        if (document.SchemaVersion != 1 || document.Boards.Count == 0)
        {
            throw new InvalidDataException("FirmwareIdentityCatalog");
        }

        var prefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (FirmwareBoardIdentityEntry board in document.Boards)
        {
            if (string.IsNullOrWhiteSpace(board.BiosIdPrefix) ||
                string.IsNullOrWhiteSpace(board.Manufacturer) ||
                string.IsNullOrWhiteSpace(board.Name) ||
                !prefixes.Add(board.BiosIdPrefix.Trim()))
            {
                throw new InvalidDataException("FirmwareIdentityCatalog");
            }
        }

        return new(document.Boards
            .OrderByDescending(item => item.BiosIdPrefix.Length)
            .ToArray());
    }

    internal FirmwareBoardIdentityEntry? Find(string? biosId)
    {
        if (string.IsNullOrWhiteSpace(biosId))
        {
            return null;
        }
        return boards.FirstOrDefault(item => biosId.StartsWith(item.BiosIdPrefix, StringComparison.OrdinalIgnoreCase));
    }
}
