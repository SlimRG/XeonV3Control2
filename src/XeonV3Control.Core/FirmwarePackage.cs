using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace XeonV3Control.Core;

/// <summary>A structurally validated BIOS image discovered inside an archive or vendor updater package.</summary>
public sealed record FirmwarePackageCandidate(
    string LogicalPath,
    ReadOnlyMemory<byte> Data,
    BiosImage Image,
    int ConfidenceScore);

/// <summary>Result of read-only package inspection. Vendor executables are never started.</summary>
public sealed record FirmwarePackageInspection(
    string PackagePath,
    IReadOnlyList<FirmwarePackageCandidate> Candidates);

/// <summary>
/// Opens common BIOS archives and self-extracting/vendor EXE packages without executing package code.
/// Nested containers are inspected conservatively and bounded to avoid archive-bomb resource exhaustion.
/// </summary>
public static class FirmwarePackageLoader
{
    public const int MaximumContainerDepth = 4;
    public const int MaximumEntries = 10_000;
    public const long MaximumExpandedBytes = 1024L * 1024 * 1024;
    public const int MaximumNestedContainerBytes = 256 * 1024 * 1024;
    public const int MaximumCandidates = 64;

    private const int CopyBufferBytes = 128 * 1024;
    private const int SelfExtractingScanBytes = 16 * 1024 * 1024;
    private const int MaximumEmbeddedArchiveCandidates = 32;
    private const int DellPfsMaximumBytes = 128 * 1024 * 1024;
    private const string PackageRootLogicalPath = "<PACKAGE>";
    private const string SelfExtractingLogicalPath = "<SFX>";
    private const string DellPfsLogicalPath = "<DELL_PFS>";

    private static readonly byte[] s_dellPfsHeaderTag = "PFS.HDR."u8.ToArray();
    private static readonly byte[] s_dellPfsFooterTag = "PFS.FTR."u8.ToArray();
    private static readonly byte[] s_dellSectionMagic =
        [0xAA, 0xEE, 0xAA, 0x76, 0x1B, 0xEC, 0xBB, 0x20, 0xF1, 0xE6, 0x51];
    private static readonly byte[] s_dellSectionFooterMagic =
        [0xEE, 0xAA, 0xEE, 0x8F, 0x49, 0x1B, 0xE8, 0xAE, 0x14, 0x37, 0x90];
    private static readonly byte[] s_elfMagic = [0x7F, 0x45, 0x4C, 0x46];
    private static readonly byte[] s_gzipMagic = [0x1F, 0x8B];
    private static readonly byte[] s_xzMagic = [0xFD, 0x37, 0x7A, 0x58, 0x5A];

    private static readonly HashSet<string> s_dellInformationGuids = new(StringComparer.OrdinalIgnoreCase)
    {
        "E0717CE3A9BB25824B9F0DC8FD041960",
        "B033CB16EC9B45A14055F80E4D583FD3"
    };

    private static readonly HashSet<string> s_packageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".tar", ".tgz", ".tbz", ".tbz2", ".txz",
        ".gz", ".bz2", ".xz", ".zst", ".lzip", ".exe"
    };

    private static readonly HashSet<string> s_singleStreamCompressionExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".gz", ".bz2", ".xz", ".zst", ".lzip"
    };

    private static readonly HashSet<string> s_obviousNonFirmwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".pdf", ".html", ".htm", ".xml", ".json", ".csv", ".ini", ".inf",
        ".cat", ".dll", ".sys", ".pdb", ".chm", ".bat", ".cmd", ".ps1", ".sh", ".com",
        ".efi", ".vbs", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".rtf",
        ".doc", ".docx", ".xls", ".xlsx", ".lnk", ".sig", ".cer", ".crt", ".pem",
        ".key", ".md", ".nsh"
    };

    private static readonly HashSet<string> s_auxiliaryTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "ec", "ecfw", "bmc", "ipmi", "cpld", "me", "mefw", "intelme", "descriptor",
        "fdregion", "gbe", "lanrom", "nvram", "microcode", "network", "nic", "vga",
        "vbios", "optionrom", "oprom", "raidrom"
    };

    private static readonly HashSet<string> s_positiveTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "bios", "uefi", "firmware", "rom", "systembios"
    };

    private static readonly byte[][] s_embeddedArchiveMagic =
    [
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        [0x50, 0x4B, 0x03, 0x04]
    ];

    public static IReadOnlyList<string> SupportedPackageExtensions { get; } =
        s_packageExtensions.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();

    public static IReadOnlyList<string> SupportedInputExtensions { get; } =
        BiosImageLoader.SupportedFileExtensions
            .Concat(SupportedPackageExtensions)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static bool HasSupportedInputExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string extension = Path.GetExtension(path) ?? string.Empty;
        return SupportedInputExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    public static bool IsPackagePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        return s_packageExtensions.Contains(Path.GetExtension(path) ?? string.Empty);
    }

    public static async Task<FirmwarePackageInspection> InspectAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(OperationError.ImageUnavailable, fullPath);
        }
        if (!IsPackagePath(fullPath))
        {
            throw new InvalidDataException(OperationError.UnsupportedFileType);
        }

        return await Task.Run(() => Inspect(fullPath, cancellationToken), cancellationToken);
    }

    private static FirmwarePackageInspection Inspect(string path, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var context = new InspectionContext(Path.GetFileName(path), cancellationToken);
        string extension = Path.GetExtension(path);
        bool opened = false;

        if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            opened = TryInspectDellPfs(path, context);
        }

        if (!opened)
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                CopyBufferBytes,
                FileOptions.SequentialScan);
            opened = TryInspectContainer(stream, PackageRootLogicalPath, extension, 0, context);

            if (!opened && extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                opened = TryInspectEmbeddedSelfExtractingArchive(stream, PackageRootLogicalPath, context);
            }
        }


        if (!opened)
        {
            throw new InvalidDataException(OperationError.PackageUnreadable);
        }

        IReadOnlyList<FirmwarePackageCandidate> candidates = context.Candidates
            .Values
            .OrderByDescending(candidate => candidate.ConfidenceScore)
            .ThenBy(candidate => candidate.LogicalPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new FirmwarePackageInspection(path, candidates);
    }

    private static bool TryInspectContainer(
        Stream stream,
        string logicalPath,
        string extensionHint,
        int depth,
        InspectionContext context)
    {
        if (depth >= MaximumContainerDepth)
        {
            return false;
        }
        if (!stream.CanSeek || !stream.CanRead)
        {
            return false;
        }

        context.Token.ThrowIfCancellationRequested();
        long start = stream.Position;
        ReaderOptions options = CreateReaderOptions(extensionHint);

        try
        {
            stream.Position = start;
            using IArchive archive = ArchiveFactory.OpenArchive(stream, options);
            ValidateArchiveMetadata(archive);
            if (archive.IsSolid || archive.Type == ArchiveType.SevenZip)
            {
                using IReader reader = archive.ExtractAllEntries();
                InspectReader(reader, logicalPath, depth, context);
            }
            else
            {
                foreach (IArchiveEntry entry in archive.Entries)
                {
                    context.Token.ThrowIfCancellationRequested();
                    if (entry.IsDirectory)
                    {
                        continue;
                    }
                    InspectArchiveEntry(entry, logicalPath, depth, context);
                }
            }
            return true;
        }
        catch (Exception error) when (IsArchiveFormatFailure(error))
        {
            stream.Position = start;
        }

        try
        {
            using IReader reader = ReaderFactory.OpenReader(stream, options);
            InspectReader(reader, logicalPath, depth, context);
            return true;
        }
        catch (Exception error) when (IsArchiveFormatFailure(error))
        {
            stream.Position = start;
            return false;
        }
    }

    private static ReaderOptions CreateReaderOptions(string extensionHint)
    {
        string extension = extensionHint.TrimStart('.');
        return new ReaderOptions
        {
            LeaveStreamOpen = true,
            LookForHeader = extension.Equals("exe", StringComparison.OrdinalIgnoreCase),
            RewindableBufferSize = 1024 * 1024,
            ExtensionHint = extension.Length == 0 || extension.Equals("exe", StringComparison.OrdinalIgnoreCase)
                ? null
                : extension
        };
    }

    private static void ValidateArchiveMetadata(IArchive archive)
    {
        int entries = 0;
        long expandedBytes = 0;
        foreach (IArchiveEntry entry in archive.Entries)
        {
            if (entry.IsDirectory)
            {
                continue;
            }

            entries++;
            if (entries > MaximumEntries)
            {
                throw new InvalidDataException(OperationError.PackageLimits);
            }

            long? size = SafeEntrySize(entry);
            if (size is > 0)
            {
                if (size.Value > MaximumExpandedBytes - expandedBytes)
                {
                    throw new InvalidDataException(OperationError.PackageLimits);
                }
                expandedBytes += size.Value;
            }
        }
    }

    private static void InspectReader(
        IReader reader,
        string parentLogicalPath,
        int depth,
        InspectionContext context)
    {
        while (reader.MoveToNextEntry())
        {
            context.Token.ThrowIfCancellationRequested();
            IEntry entry = reader.Entry;
            if (entry.IsDirectory)
            {
                continue;
            }
            InspectEntry(
                entry.Key,
                SafeEntrySize(entry),
                entry.IsEncrypted,
                reader.OpenEntryStream,
                parentLogicalPath,
                depth,
                context);
        }
    }

    private static void InspectArchiveEntry(
        IArchiveEntry entry,
        string parentLogicalPath,
        int depth,
        InspectionContext context) =>
        InspectEntry(
            entry.Key,
            SafeEntrySize(entry),
            entry.IsEncrypted,
            entry.OpenEntryStream,
            parentLogicalPath,
            depth,
            context);

    private static void InspectEntry(
        string? key,
        long? declaredSize,
        bool encrypted,
        Func<Stream> openStream,
        string parentLogicalPath,
        int depth,
        InspectionContext context)
    {
        context.RegisterEntry();
        if (encrypted)
        {
            return;
        }

        string entryPath = NormalizeLogicalEntryPath(key);
        if (entryPath.Length == 0)
        {
            if (!string.IsNullOrWhiteSpace(key))
            {
                return;
            }
            entryPath = SingleStreamPayloadName(parentLogicalPath, context.PackageFileName);
        }
        if (entryPath.Length == 0 || !ShouldReadEntry(entryPath, declaredSize))
        {
            return;
        }

        int maximumBytes = EntryReadLimit(entryPath, declaredSize);
        using Stream entryStream = openStream();
        byte[] data = ReadBounded(entryStream, maximumBytes, context);
        if (data.Length == 0)
        {
            return;
        }

        string logicalPath = CombineLogicalPath(parentLogicalPath, entryPath);
        InspectPayload(data, logicalPath, depth + 1, context);
    }

    private static void InspectPayload(
        byte[] data,
        string logicalPath,
        int depth,
        InspectionContext context)
    {
        context.Token.ThrowIfCancellationRequested();

        if (LooksLikeExecutable(data))
        {
            if (TryInspectDellPfs(data, CombineLogicalPath(logicalPath, DellPfsLogicalPath), context))
            {
                return;
            }

            if (depth < MaximumContainerDepth)
            {
                using var executable = new MemoryStream(data, writable: false);
                if (TryInspectContainer(executable, logicalPath, ".exe", depth, context))
                {
                    return;
                }
                _ = TryInspectEmbeddedSelfExtractingArchive(executable, logicalPath, context, depth);
            }
            return;
        }

        string extension = Path.GetExtension(LogicalLeaf(logicalPath));
        bool packageLike = s_packageExtensions.Contains(extension) || LooksLikeArchiveHeader(data);
        if (packageLike && depth < MaximumContainerDepth)
        {
            using var nested = new MemoryStream(data, writable: false);
            if (TryInspectContainer(nested, logicalPath, extension, depth, context))
            {
                return;
            }
        }

        TryAddCandidate(data, logicalPath, context);
    }

    private static bool TryInspectEmbeddedSelfExtractingArchive(
        Stream source,
        string logicalPath,
        InspectionContext context,
        int depth = 0)
    {
        if (!source.CanSeek || source.Length <= 0 || depth >= MaximumContainerDepth)
        {
            return false;
        }

        long original = source.Position;
        try
        {
            source.Position = 0;
            int scanLength = checked((int)Math.Min(source.Length, SelfExtractingScanBytes));
            byte[] prefix = new byte[scanLength];
            ReadExactlyOrLess(source, prefix);

            int inspectedOffsets = 0;
            foreach (byte[] magic in s_embeddedArchiveMagic)
            {
                int searchFrom = 1;
                while (searchFrom <= prefix.Length - magic.Length)
                {
                    int relativeOffset = IndexOf(prefix.AsSpan(searchFrom), magic);
                    if (relativeOffset < 0)
                    {
                        break;
                    }

                    int offset = searchFrom + relativeOffset;
                    searchFrom = offset + 1;
                    inspectedOffsets++;
                    if (inspectedOffsets > MaximumEmbeddedArchiveCandidates)
                    {
                        return false;
                    }

                    long remaining = source.Length - offset;
                    if (remaining <= 0 || remaining > MaximumNestedContainerBytes)
                    {
                        continue;
                    }

                    source.Position = offset;
                    byte[] embedded = ReadBounded(source, checked((int)remaining), context, countExpanded: false);
                    using var nested = new MemoryStream(embedded, writable: false);
                    string extension = magic.AsSpan().SequenceEqual(s_embeddedArchiveMagic[0]) ? ".7z" :
                        magic.AsSpan().SequenceEqual(s_embeddedArchiveMagic[1]) ? ".rar" : ".zip";
                    if (TryInspectContainer(nested, CombineLogicalPath(logicalPath, SelfExtractingLogicalPath), extension, depth, context))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        finally
        {
            source.Position = original;
        }
    }

    private static bool TryInspectDellPfs(string path, InspectionContext context)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length <= 0 || info.Length > DellPfsMaximumBytes)
        {
            return false;
        }

        return TryInspectDellPfs(File.ReadAllBytes(path), DellPfsLogicalPath, context);
    }

    private static bool TryInspectDellPfs(
        byte[] executable,
        string logicalPrefix,
        InspectionContext context)
    {
        if (executable.Length == 0 || executable.Length > DellPfsMaximumBytes ||
            !TryLocateDellPfsSection(executable, out int compressedStart, out int compressedSize))
        {
            return false;
        }

        byte[] volume;
        try
        {
            using var input = new MemoryStream(executable, compressedStart, compressedSize, writable: false);
            using var inflater = new ZLibStream(input, CompressionMode.Decompress);
            volume = ReadBounded(inflater, checked((int)Math.Min(MaximumExpandedBytes, int.MaxValue)), context);
        }
        catch (Exception error) when (error is InvalidDataException or IOException)
        {
            throw new InvalidDataException(OperationError.PackageUnreadable, error);
        }

        IReadOnlyList<DellPfsEntry> entries = ParseDellPfsEntries(volume);
        Dictionary<string, string> names = ParseDellPfsNames(entries);
        bool namedSystemBiosFound = false;
        foreach (DellPfsEntry entry in entries)
        {
            if (!names.TryGetValue(entry.Guid, out string? name) ||
                !name.Equals("System BIOS", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            namedSystemBiosFound = true;
            TryAddCandidate(
                entry.Data,
                logicalPrefix + "/" + SafeLogicalName(name) + ".bin",
                context,
                confidenceBonus: 40);
        }

        if (!namedSystemBiosFound)
        {
            foreach (DellPfsEntry entry in entries)
            {
                TryAddCandidate(
                    entry.Data,
                    logicalPrefix + "/" + entry.Guid + ".bin",
                    context,
                    confidenceBonus: 10);
            }
        }

        return true;
    }

    private static bool TryLocateDellPfsSection(byte[] data, out int compressedStart, out int compressedSize)
    {
        compressedStart = 0;
        compressedSize = 0;
        int searchFrom = 0;
        while (searchFrom <= data.Length - s_dellSectionMagic.Length)
        {
            int magic = IndexOf(data.AsSpan(searchFrom), s_dellSectionMagic);
            if (magic < 0)
            {
                return false;
            }
            magic += searchFrom;
            int headerStart = magic - sizeof(uint);
            int candidateStart = magic + s_dellSectionMagic.Length + 1;
            if (headerStart >= 0 && candidateStart <= data.Length)
            {
                ReadOnlySpan<byte> header = data.AsSpan(headerStart, candidateStart - headerStart);
                if (header.Length == 16 && Xor8(header[..15]) == header[15])
                {
                    uint size = BinaryPrimitives.ReadUInt32LittleEndian(header);
                    long end = (long)candidateStart + size;
                    long footerEnd = end + 16;
                    if (size > 0 && size <= DellPfsMaximumBytes && footerEnd <= data.Length)
                    {
                        ReadOnlySpan<byte> footer = data.AsSpan(checked((int)end), 16);
                        if (footer.Slice(4, 11).SequenceEqual(s_dellSectionFooterMagic) &&
                            Xor8(footer[..15]) == footer[15] &&
                            BinaryPrimitives.ReadUInt32LittleEndian(footer) == size)
                        {
                            compressedStart = candidateStart;
                            compressedSize = checked((int)size);
                            return true;
                        }
                    }
                }
            }
            searchFrom = magic + 1;
        }
        return false;
    }

    private static IReadOnlyList<DellPfsEntry> ParseDellPfsEntries(byte[] volume)
    {
        if (volume.Length < 32 || !volume.AsSpan(0, 8).SequenceEqual(s_dellPfsHeaderTag))
        {
            throw new InvalidDataException(OperationError.PackageUnreadable);
        }

        uint headerVersion = BinaryPrimitives.ReadUInt32LittleEndian(volume.AsSpan(8));
        uint payloadSize = BinaryPrimitives.ReadUInt32LittleEndian(volume.AsSpan(12));
        if (headerVersion is not (1 or 2))
        {
            throw new InvalidDataException(OperationError.PackageUnreadable);
        }

        const int payloadStart = 16;
        long payloadEndLong = (long)payloadStart + payloadSize;
        if (payloadEndLong + 16 > volume.Length)
        {
            throw new InvalidDataException(OperationError.PackageUnreadable);
        }
        int payloadEnd = checked((int)payloadEndLong);
        ReadOnlySpan<byte> footer = volume.AsSpan(payloadEnd, 16);
        if (!footer.Slice(8, 8).SequenceEqual(s_dellPfsFooterTag) ||
            BinaryPrimitives.ReadUInt32LittleEndian(footer) != payloadSize)
        {
            throw new InvalidDataException(OperationError.PackageUnreadable);
        }

        ReadOnlySpan<byte> payload = volume.AsSpan(payloadStart, checked((int)payloadSize));
        uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(footer[4..]);
        if (storedCrc != ~ComputeCrc32(payload))
        {
            throw new InvalidDataException(OperationError.PackageUnreadable);
        }

        var entries = new List<DellPfsEntry>();
        int position = 0;
        while (position < payload.Length)
        {
            if (position + 0x38 > payload.Length)
            {
                throw new InvalidDataException(OperationError.PackageUnreadable);
            }
            uint entryVersion = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(position + 0x10, 4));
            int headerSize = entryVersion switch
            {
                1 => 0x48,
                2 => 0x58,
                _ => 0
            };
            if (headerSize == 0 || position + headerSize > payload.Length)
            {
                throw new InvalidDataException(OperationError.PackageUnreadable);
            }

            uint dataSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(position + 0x28, 4));
            uint dataSignatureSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(position + 0x2C, 4));
            uint metadataSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(position + 0x30, 4));
            uint metadataSignatureSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(position + 0x34, 4));
            long totalSize = (long)headerSize + dataSize + dataSignatureSize + metadataSize + metadataSignatureSize;
            if (totalSize < headerSize || position + totalSize > payload.Length)
            {
                throw new InvalidDataException(OperationError.PackageUnreadable);
            }

            int dataStart = position + headerSize;
            byte[] data = payload.Slice(dataStart, checked((int)dataSize)).ToArray();
            string guid = DellGuid(payload.Slice(position, 16));
            entries.Add(new DellPfsEntry(guid, data));
            position = checked(position + (int)totalSize);
            if (entries.Count > MaximumEntries)
            {
                throw new InvalidDataException(OperationError.PackageLimits);
            }
        }
        return entries;
    }

    private static Dictionary<string, string> ParseDellPfsNames(IReadOnlyList<DellPfsEntry> entries)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DellPfsEntry entry in entries)
        {
            if (!s_dellInformationGuids.Contains(entry.Guid))
            {
                continue;
            }

            ReadOnlySpan<byte> data = entry.Data;
            int position = 0;
            while (position + 0x22 <= data.Length)
            {
                uint infoVersion = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(position, 4));
                if (infoVersion != 1)
                {
                    break;
                }

                string guid = DellGuid(data.Slice(position + 4, 16));
                ushort characters = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(position + 0x20, 2));
                long nameEndLong = position + 0x22L + characters * 2L;
                if (nameEndLong > data.Length)
                {
                    break;
                }
                int nameEnd = checked((int)nameEndLong);
                string name = Encoding.Unicode.GetString(data.Slice(position + 0x22, characters * 2)).Trim(' ', '\0', '\uFEFF');
                if (!string.IsNullOrWhiteSpace(name))
                {
                    names[guid] = name;
                }
                position = nameEnd + 2;
            }
        }
        return names;
    }

    private static void TryAddCandidate(
        byte[] data,
        string logicalPath,
        InspectionContext context,
        int confidenceBonus = 0)
    {
        if (data.Length is < BiosImageLoader.MinBiosImageBytes or > BiosImageLoader.MaxImageBytes ||
            LooksLikeExecutable(data) || IsAuxiliaryPath(logicalPath))
        {
            return;
        }

        BiosImage image;
        try
        {
            image = BiosImageLoader.Analyze(data, logicalPath, context.Token);
            BiosImageLoader.EnsureValidBiosImage(image);
        }
        catch (InvalidDataException)
        {
            return;
        }

        int score = 100 + confidenceBonus;
        score += image.Kind switch
        {
            ImageKind.IntelSpiImage => 20,
            ImageKind.Capsule => 12,
            ImageKind.UefiImage => 10,
            _ => 0
        };
        string extension = Path.GetExtension(LogicalLeaf(logicalPath));
        if (BiosImageLoader.SupportedFileExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            score += 8;
        }
        if (Tokenize(logicalPath).Any(s_positiveTokens.Contains))
        {
            score += 6;
        }
        if (IsCommonFirmwareSize(data.Length))
        {
            score += 4;
        }

        var candidate = new FirmwarePackageCandidate(logicalPath, data, image, score);
        if (context.Candidates.TryGetValue(image.Sha256, out FirmwarePackageCandidate? existing))
        {
            if (candidate.ConfidenceScore > existing.ConfidenceScore ||
                candidate.ConfidenceScore == existing.ConfidenceScore &&
                candidate.LogicalPath.Length < existing.LogicalPath.Length)
            {
                context.Candidates[image.Sha256] = candidate;
            }
            return;
        }

        if (context.Candidates.Count >= MaximumCandidates)
        {
            throw new InvalidDataException(OperationError.PackageLimits);
        }
        context.Candidates.Add(image.Sha256, candidate);
    }

    private static bool ShouldReadEntry(string path, long? size)
    {
        if (size is <= 0)
        {
            return false;
        }
        if (size > MaximumNestedContainerBytes)
        {
            return false;
        }

        string extension = Path.GetExtension(LogicalLeaf(path));
        if (s_obviousNonFirmwareExtensions.Contains(extension))
        {
            return false;
        }
        return true;
    }

    private static int EntryReadLimit(string path, long? declaredSize)
    {
        string extension = Path.GetExtension(LogicalLeaf(path));
        bool packageLike = s_packageExtensions.Contains(extension);
        int limit = packageLike ? MaximumNestedContainerBytes : BiosImageLoader.MaxImageBytes;
        if (declaredSize is > 0 and <= int.MaxValue)
        {
            limit = Math.Min(limit, checked((int)declaredSize));
        }
        return limit;
    }

    private static byte[] ReadBounded(
        Stream source,
        int maximumBytes,
        InspectionContext context,
        bool countExpanded = true)
    {
        if (maximumBytes <= 0)
        {
            return [];
        }

        var output = new MemoryStream(Math.Min(maximumBytes, 4 * 1024 * 1024));
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferBytes);
        try
        {
            int total = 0;
            while (true)
            {
                context.Token.ThrowIfCancellationRequested();
                int remaining = maximumBytes - total;
                if (remaining == 0)
                {
                    int extra = source.ReadByte();
                    if (extra >= 0)
                    {
                        throw new InvalidDataException(OperationError.PackageLimits);
                    }
                    break;
                }
                int read = source.Read(buffer, 0, Math.Min(buffer.Length, remaining));
                if (read == 0)
                {
                    break;
                }
                output.Write(buffer, 0, read);
                total += read;
                if (countExpanded)
                {
                    context.AddExpanded(read);
                }
            }
            return output.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            output.Dispose();
        }
    }

    private static void ReadExactlyOrLess(Stream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read == 0)
            {
                break;
            }
            offset += read;
        }
    }

    private static long? SafeEntrySize(IEntry entry)
    {
        try
        {
            return entry.Size;
        }
        catch (Exception error) when (error is NotImplementedException or InvalidOperationException or SharpCompressException)
        {
            return null;
        }
    }

    private static bool IsArchiveFormatFailure(Exception error)
    {
        if (error is InvalidDataException invalidData &&
            invalidData.Message == OperationError.PackageLimits)
        {
            return false;
        }

        return FirmwareCompressionFailure.IsMalformedInput(error) ||
            error is NotSupportedException or System.Security.Cryptography.CryptographicException or InvalidOperationException;
    }

    private static bool LooksLikeExecutable(ReadOnlySpan<byte> data) =>
        data.StartsWith("MZ"u8) || data.StartsWith(s_elfMagic) || data.StartsWith("#!"u8);

    private static bool LooksLikeArchiveHeader(ReadOnlySpan<byte> data)
    {
        foreach (byte[] magic in s_embeddedArchiveMagic)
        {
            if (data.StartsWith(magic))
            {
                return true;
            }
        }
        return data.StartsWith(s_gzipMagic) || data.StartsWith("BZh"u8) || data.StartsWith(s_xzMagic);
    }

    private static bool IsAuxiliaryPath(string logicalPath)
    {
        int boundary = logicalPath.LastIndexOf('!');
        string entryPath = boundary >= 0 ? logicalPath[(boundary + 1)..] : logicalPath;
        return Tokenize(entryPath).Any(s_auxiliaryTokens.Contains);
    }

    private static IEnumerable<string> Tokenize(string value)
    {
        var current = new StringBuilder();
        foreach (char character in value)
        {
            if (char.IsLetterOrDigit(character))
            {
                current.Append(char.ToLowerInvariant(character));
                continue;
            }
            if (current.Length > 0)
            {
                yield return current.ToString();
                current.Clear();
            }
        }
        if (current.Length > 0)
        {
            yield return current.ToString();
        }
    }

    private static bool IsCommonFirmwareSize(int size)
    {
        if (size < BiosImageLoader.MinBiosImageBytes)
        {
            return false;
        }
        for (int power = 20; power <= 27; power++)
        {
            int target = 1 << power;
            if (Math.Abs((long)size - target) <= 128 * 1024)
            {
                return true;
            }
        }
        return size % (1024 * 1024) == 0;
    }

    private static string NormalizeLogicalEntryPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('\0'))
        {
            return string.Empty;
        }

        string normalized = value.Replace('\\', '/');
        if (normalized.StartsWith('/') ||
            normalized.Length >= 2 && char.IsAsciiLetter(normalized[0]) && normalized[1] == ':')
        {
            return string.Empty;
        }

        string[] parts = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Any(part => part == ".."))
        {
            return string.Empty;
        }

        return string.Join('/', parts.Where(part => part != "."));
    }

    private static string CombineLogicalPath(string parent, string child) =>
        parent == PackageRootLogicalPath ? child : parent + "!" + child;

    private static string SingleStreamPayloadName(string parentLogicalPath, string packageFileName)
    {
        string sourceName = parentLogicalPath == PackageRootLogicalPath
            ? packageFileName
            : LogicalLeaf(parentLogicalPath);
        if (string.IsNullOrWhiteSpace(sourceName) ||
            !s_singleStreamCompressionExtensions.Contains(Path.GetExtension(sourceName)))
        {
            return string.Empty;
        }

        return Path.GetFileNameWithoutExtension(sourceName);
    }

    private static string LogicalLeaf(string logicalPath)
    {
        int boundary = logicalPath.LastIndexOf('!');
        string entry = boundary >= 0 ? logicalPath[(boundary + 1)..] : logicalPath;
        int slash = entry.LastIndexOf('/');
        return slash >= 0 ? entry[(slash + 1)..] : entry;
    }

    private static string SafeLogicalName(string name)
    {
        var builder = new StringBuilder(name.Length);
        foreach (char character in name)
        {
            builder.Append(character is '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' ? '_' : character);
        }
        return builder.ToString().Trim();
    }

    private static int IndexOf(ReadOnlySpan<byte> source, ReadOnlySpan<byte> pattern) => source.IndexOf(pattern);

    private static byte Xor8(ReadOnlySpan<byte> data)
    {
        byte value = 0;
        foreach (byte item in data)
        {
            value ^= item;
        }
        return value;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte item in data)
        {
            crc ^= item;
            for (int bit = 0; bit < 8; bit++)
            {
                uint mask = unchecked((uint)-(int)(crc & 1));
                crc = (crc >> 1) ^ (0xEDB88320U & mask);
            }
        }
        return ~crc;
    }

    private static string DellGuid(ReadOnlySpan<byte> raw)
    {
        if (raw.Length != 16)
        {
            return Convert.ToHexString(raw);
        }
        uint a = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(0, 4));
        uint b = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(4, 4));
        uint c = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(8, 4));
        uint d = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(12, 4));
        return string.Concat(
            d.ToString("X8", CultureInfo.InvariantCulture),
            c.ToString("X8", CultureInfo.InvariantCulture),
            b.ToString("X8", CultureInfo.InvariantCulture),
            a.ToString("X8", CultureInfo.InvariantCulture));
    }

    private sealed record DellPfsEntry(string Guid, byte[] Data);

    private sealed class InspectionContext(string packageFileName, CancellationToken token)
    {
        private int _entries;
        private long _expandedBytes;

        internal string PackageFileName { get; } = packageFileName;
        internal CancellationToken Token { get; } = token;
        internal Dictionary<string, FirmwarePackageCandidate> Candidates { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        internal void RegisterEntry()
        {
            _entries++;
            if (_entries > MaximumEntries)
            {
                throw new InvalidDataException(OperationError.PackageLimits);
            }
        }

        internal void AddExpanded(int bytes)
        {
            _expandedBytes += bytes;
            if (_expandedBytes > MaximumExpandedBytes)
            {
                throw new InvalidDataException(OperationError.PackageLimits);
            }
        }

    }
}
