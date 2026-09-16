using System.Reflection;
using System.Security.Cryptography;

namespace XeonV3Control.Core;

public enum TpmDebugDriverMutation
{
    None,
    Install,
    Remove
}

public enum TpmDebugDriverDisposition
{
    NotInstalled,
    Installed,
    Duplicate,
    InstallBlocked,
    AnalysisIncomplete
}

public sealed record TpmDebugDriverPlan(
    TpmDebugDriverDisposition Disposition,
    TpmDebugDriverMutation Mutation,
    string Reason,
    string SourceImageSha256,
    long? VolumeOffset,
    long? FileOffset,
    int DriverSize)
{
    public bool CanExecute => Mutation != TpmDebugDriverMutation.None &&
        string.Equals(Reason, TpmDebugDriverReason.None, StringComparison.Ordinal);
}

public static class TpmDebugDriverReason
{
    public const string None = "TpmDebugNone";
    public const string AlreadyInstalled = "TpmDebugAlreadyInstalled";
    public const string NotInstalled = "TpmDebugNotInstalled";
    public const string Duplicate = "TpmDebugDuplicate";
    public const string Incomplete = "TpmDebugIncomplete";
    public const string NoSpace = "TpmDebugNoSpace";
    public const string SourceChanged = "TpmDebugSourceChanged";
    public const string OutputInvalid = "TpmDebugOutputInvalid";
}

/// <summary>Installs/removes only the embedded XeonV3Control TPM diagnostic FFS.</summary>
public static class TpmDebugDriverImageUpdater
{
    private const string ResourceFolder = "Firmware.TpmDebug";
    private const string ResourceFile = "XeonV3TpmDebug.ffs";

    public static bool IsCurrentInstallation(ReadOnlySpan<byte> source, BiosImage image)
    {
        UefiDriverMutationPlanner.EnsureImageMatches(source, image);
        UefiDriverInfo[] existing = image.UefiDrivers.Drivers
            .Where(driver => driver.FileGuid == TpmFirmwareInspector.DebugDriverFileGuid)
            .ToArray();
        if (existing.Length != 1)
        {
            return false;
        }

        UefiDriverInfo driver = existing[0];
        FirmwareVolume? volume = image.Volumes.SingleOrDefault(item => item.Offset == driver.VolumeOffset);
        if (volume is null || !UefiFfsVolumeScanner.TryGetLayout(source, volume, out UefiFfsVolumeLayout layout))
        {
            return false;
        }

        byte[] current = AdaptPhysicalState(EmbeddedTemplate(), layout.EraseByte);
        if (driver.FileOffset < 0 || driver.FileSize != current.Length ||
            driver.FileOffset > source.Length - driver.FileSize)
        {
            return false;
        }

        return source.Slice(checked((int)driver.FileOffset), driver.FileSize).SequenceEqual(current);
    }

    public static TpmDebugDriverPlan Plan(ReadOnlySpan<byte> source, BiosImage image, CancellationToken token = default)
    {
        UefiDriverMutationPlanner.EnsureImageMatches(source, image);
        if (image.UefiDrivers.Incomplete)
        {
            return new(TpmDebugDriverDisposition.AnalysisIncomplete, TpmDebugDriverMutation.None,
                TpmDebugDriverReason.Incomplete, image.Sha256, null, null, EmbeddedTemplate().Length);
        }

        UefiDriverInfo[] existing = image.UefiDrivers.Drivers
            .Where(driver => driver.FileGuid == TpmFirmwareInspector.DebugDriverFileGuid)
            .ToArray();
        if (existing.Length > 1)
        {
            return new(TpmDebugDriverDisposition.Duplicate, TpmDebugDriverMutation.None,
                TpmDebugDriverReason.Duplicate, image.Sha256, null, null, EmbeddedTemplate().Length);
        }
        if (existing.Length == 1)
        {
            UefiDriverInfo driver = existing[0];
            return new(TpmDebugDriverDisposition.Installed, TpmDebugDriverMutation.Remove,
                TpmDebugDriverReason.None, image.Sha256, driver.VolumeOffset, driver.FileOffset, driver.FileSize);
        }

        byte[] template = EmbeddedTemplate();
        UefiDriverMutationPlan? best = null;
        int bestDriverCount = -1;
        foreach (FirmwareVolume volume in image.Volumes.OrderByDescending(volume => volume.Length))
        {
            token.ThrowIfCancellationRequested();
            if (!UefiFfsVolumeScanner.TryGetLayout(source, volume, out UefiFfsVolumeLayout layout))
            {
                continue;
            }
            byte[] candidate = AdaptPhysicalState(template, layout.EraseByte);
            UefiDriverMutationPlan mutation = UefiDriverMutationPlanner.PlanAdd(source, image, volume.Offset, candidate, token);
            if (mutation.Feasibility == UefiDriverMutationFeasibility.InPlace && mutation.DestinationOffset is not null)
            {
                int driverCount = image.UefiDrivers.Drivers.Count(driver => driver.VolumeOffset == volume.Offset);
                // Prefer the FV that already hosts the active DXE population; only then minimize unused tail space.
                if (best is null || driverCount > bestDriverCount ||
                    (driverCount == bestDriverCount && mutation.AvailableBytes < best.AvailableBytes))
                {
                    best = mutation;
                    bestDriverCount = driverCount;
                }
            }
        }

        return best is null
            ? new(TpmDebugDriverDisposition.InstallBlocked, TpmDebugDriverMutation.None,
                TpmDebugDriverReason.NoSpace, image.Sha256, null, null, template.Length)
            : new(TpmDebugDriverDisposition.NotInstalled, TpmDebugDriverMutation.Install,
                TpmDebugDriverReason.None, image.Sha256, best.VolumeOffset, best.DestinationOffset, best.NewFileSize);
    }

    public static byte[] Apply(ReadOnlySpan<byte> source, TpmDebugDriverPlan requestedPlan, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(requestedPlan);
        token.ThrowIfCancellationRequested();
        FirmwareMutationFileIo.VerifySha256(source, requestedPlan.SourceImageSha256, TpmDebugDriverReason.SourceChanged);

        BiosImage sourceImage = BiosImageLoader.Analyze(source, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(sourceImage);
        TpmDebugDriverPlan fresh = Plan(source, sourceImage, token);
        if (!fresh.CanExecute || fresh.Mutation != requestedPlan.Mutation || fresh.VolumeOffset != requestedPlan.VolumeOffset ||
            fresh.FileOffset != requestedPlan.FileOffset || fresh.DriverSize != requestedPlan.DriverSize)
        {
            throw new InvalidDataException(TpmDebugDriverReason.SourceChanged);
        }

        byte[] output = requestedPlan.Mutation switch
        {
            TpmDebugDriverMutation.Install => Install(source, sourceImage, fresh, token),
            TpmDebugDriverMutation.Remove => Remove(source, sourceImage, fresh, token),
            _ => throw new InvalidDataException(TpmDebugDriverReason.SourceChanged)
        };
        ValidateOutput(source, output, sourceImage, requestedPlan.Mutation, token);
        return output;
    }

    public static async Task<BiosImage> ApplyFileAsync(
        string sourcePath,
        string destinationPath,
        TpmDebugDriverPlan plan,
        CancellationToken token = default)
    {
        byte[] source = await FirmwareMutationFileIo.ReadImageAsync(sourcePath, token);
        byte[] updated = Apply(source, plan, token);
        string expected = Convert.ToHexString(SHA256.HashData(updated));
        bool committed = false;
        try
        {
            await FirmwareMutationFileIo.WriteNewVerifiedImageAsync(destinationPath, updated, token);
            committed = true;
            BiosImage result = await BiosImageLoader.LoadValidatedAsync(destinationPath, token);
            if (!string.Equals(result.Sha256, expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException(TpmDebugDriverReason.OutputInvalid);
            }
            return result;
        }
        catch
        {
            if (committed)
            {
                _ = FileSystemCleanup.TryDeleteFile(destinationPath, out _);
            }
            throw;
        }
    }

    private static byte[] Install(ReadOnlySpan<byte> source, BiosImage image, TpmDebugDriverPlan plan, CancellationToken token)
    {
        FirmwareVolume volume = image.Volumes.Single(item => item.Offset == plan.VolumeOffset);
        if (!UefiFfsVolumeScanner.TryGetLayout(source, volume, out UefiFfsVolumeLayout layout))
        {
            throw new InvalidDataException(TpmDebugDriverReason.SourceChanged);
        }
        byte[] candidate = AdaptPhysicalState(EmbeddedTemplate(), layout.EraseByte);
        UefiDriverMutationPlan mutation = UefiDriverMutationPlanner.PlanAdd(source, image, volume.Offset, candidate, token);
        if (mutation.Feasibility != UefiDriverMutationFeasibility.InPlace || mutation.DestinationOffset is not long destination ||
            destination != plan.FileOffset || candidate.Length != plan.DriverSize)
        {
            throw new InvalidDataException(TpmDebugDriverReason.SourceChanged);
        }

        int offset = checked((int)destination);
        if (offset > source.Length - candidate.Length || source.Slice(offset, candidate.Length).IndexOfAnyExcept(layout.EraseByte) >= 0)
        {
            throw new InvalidDataException(TpmDebugDriverReason.SourceChanged);
        }
        byte[] output = source.ToArray();
        candidate.CopyTo(output.AsSpan(offset));
        return output;
    }

    private static byte[] Remove(ReadOnlySpan<byte> source, BiosImage image, TpmDebugDriverPlan plan, CancellationToken token)
    {
        UefiDriverInfo driver = image.UefiDrivers.Drivers.Single(item =>
            item.FileGuid == TpmFirmwareInspector.DebugDriverFileGuid &&
            item.VolumeOffset == plan.VolumeOffset && item.FileOffset == plan.FileOffset);
        var target = new UefiFfsRemovalTarget(driver.FileGuid, driver.VolumeOffset, driver.FileOffset,
            driver.FileSize, driver.FfsType, driver.Sha256);
        UefiFfsRemovalPreflight preflight = UefiFfsMutationPlanner.PlanRemoveExact(source, image, target, token);
        if (!preflight.IsReady)
        {
            throw new InvalidDataException(TpmDebugDriverReason.SourceChanged);
        }
        byte[] output = source.ToArray();
        output.AsSpan(preflight.File.Offset, preflight.File.Size).Fill(preflight.Layout.EraseByte);
        return output;
    }

    private static void ValidateOutput(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> output,
        BiosImage sourceImage,
        TpmDebugDriverMutation mutation,
        CancellationToken token)
    {
        if (output.Length != source.Length)
        {
            throw new InvalidDataException(TpmDebugDriverReason.OutputInvalid);
        }
        BiosImage result = BiosImageLoader.Analyze(output, cancellationToken: token);
        BiosImageLoader.EnsureValidBiosImage(result);
        int sourceCount = sourceImage.UefiDrivers.Drivers.Count(d => d.FileGuid == TpmFirmwareInspector.DebugDriverFileGuid);
        int resultCount = result.UefiDrivers.Drivers.Count(d => d.FileGuid == TpmFirmwareInspector.DebugDriverFileGuid);
        int expected = mutation == TpmDebugDriverMutation.Install ? sourceCount + 1 : sourceCount - 1;
        if (resultCount != expected || result.UefiDrivers.Incomplete ||
            !sourceImage.Regions.SequenceEqual(result.Regions) || !sourceImage.Volumes.SequenceEqual(result.Volumes))
        {
            throw new InvalidDataException(TpmDebugDriverReason.OutputInvalid);
        }

        var sourceOther = sourceImage.UefiDrivers.Drivers
            .Where(d => d.FileGuid != TpmFirmwareInspector.DebugDriverFileGuid)
            .Select(DriverIdentity).OrderBy(v => v, StringComparer.Ordinal).ToArray();
        var resultOther = result.UefiDrivers.Drivers
            .Where(d => d.FileGuid != TpmFirmwareInspector.DebugDriverFileGuid)
            .Select(DriverIdentity).OrderBy(v => v, StringComparer.Ordinal).ToArray();
        if (!sourceOther.SequenceEqual(resultOther, StringComparer.Ordinal))
        {
            throw new InvalidDataException(TpmDebugDriverReason.OutputInvalid);
        }
    }

    private static string DriverIdentity(UefiDriverInfo d) =>
        $"{d.FileGuid:D}|{d.VolumeOffset:X}|{d.FileOffset:X}|{d.FileSize:X}|{d.FfsType:X2}|{d.Sha256}";

    private static byte[] EmbeddedTemplate()
    {
        string resourceName = EmbeddedResourceNames.File(ResourceFolder, ResourceFile);
        using Stream stream = typeof(TpmDebugDriverImageUpdater).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException(TpmDebugDriverReason.OutputInvalid);
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static byte[] AdaptPhysicalState(ReadOnlySpan<byte> template, byte eraseByte)
    {
        byte[] candidate = template.ToArray();
        byte logical = AmiSecureBootSpecification.FfsDataValidPrerequisiteMask;
        candidate[AmiSecureBootSpecification.FfsStateOffset] = eraseByte == byte.MaxValue
            ? unchecked((byte)~logical)
            : logical;
        if (!UefiFfsChecksum.TryRecalculate(candidate, AmiSecureBootSpecification.FfsFileHeaderBytes) ||
            !UefiFfsFileParser.TryRead(candidate, 0, candidate.Length, eraseByte, out FfsFileHeaderInfo header) ||
            header.Guid != TpmFirmwareInspector.DebugDriverFileGuid || header.Type != UefiPiCode.FfsDriver ||
            header.State != FfsFileState.DataValid)
        {
            throw new InvalidDataException(TpmDebugDriverReason.OutputInvalid);
        }
        return candidate;
    }
}
