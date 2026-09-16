using System.Security.Cryptography;

namespace XeonV3Control.Core;

public enum FirmwareReadScope
{
    BiosRegion,
    PartialSpi,
    FullSpi
}

public sealed record FirmwareCapabilities(bool CanRead, bool CanWrite, FirmwareReadScope Scope);

public sealed record FirmwareRegionReadStatus(
    FlashRegionKind Kind,
    uint Start,
    int Length,
    bool Readable);

public sealed record FirmwareReadSnapshot(
    byte[] Data,
    FirmwareReadScope Scope,
    IReadOnlyList<FirmwareRegionReadStatus> Regions);

public sealed record VerifiedFirmwareDump(
    BiosImage Image,
    FirmwareReadScope Scope,
    IReadOnlyList<FirmwareRegionReadStatus> Regions);

public interface IFirmwareReader
{
    FirmwareCapabilities Capabilities { get; }
    FirmwareReadSnapshot ReadFirmware(IProgress<double>? progress, CancellationToken cancellationToken);
}

public static class VerifiedDump
{
    private const double ReadPassProgressWeight = 0.5d;

    public static async Task<VerifiedFirmwareDump> CreateAsync(
        IFirmwareReader reader,
        string destination,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!reader.Capabilities.CanRead)
        {
            throw new NotSupportedException(OperationError.ReadUnavailable);
        }

        FirmwareReadSnapshot snapshot = await Task.Run(() =>
        {
            FirmwareReadSnapshot first = CopySnapshot(reader.ReadFirmware(
                new InlineProgress(p => progress?.Report(p * ReadPassProgressWeight)),
                cancellationToken));
            cancellationToken.ThrowIfCancellationRequested();
            ValidateSnapshot(first);

            FirmwareReadSnapshot second = reader.ReadFirmware(
                new InlineProgress(p => progress?.Report(ReadPassProgressWeight + p * ReadPassProgressWeight)),
                cancellationToken);
            if (!SnapshotsMatch(first, second))
            {
                throw new InvalidDataException(OperationError.DumpMismatch);
            }

            var report = BiosImageLoader.Analyze(first.Data, cancellationToken: cancellationToken);
            try
            {
                BiosImageLoader.EnsureValidBiosImage(report);
            }
            catch (InvalidDataException error)
            {
                throw new InvalidDataException(OperationError.DumpInvalid, error);
            }

            return first;
        }, cancellationToken);

        string fullPath = Path.GetFullPath(destination);
        string temp = fullPath + "." + Guid.NewGuid().ToString("N") + ".partial";
        Exception? operationError = null;
        try
        {
            await using (var output = new FileStream(
                temp,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                UefiFirmwareSpecification.FileIoBufferBytes,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(snapshot.Data, cancellationToken);
                await output.FlushAsync(cancellationToken);
                output.Flush(true);
            }

            BiosImage result = await BiosImageLoader.LoadValidatedAsync(temp, cancellationToken);
            if (!Sha256Identity.Matches(snapshot.Data, result.Sha256))
            {
                throw new IOException(OperationError.DumpMismatch);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temp, fullPath, overwrite: false);
            return new VerifiedFirmwareDump(
                result with { FilePath = fullPath },
                snapshot.Scope,
                snapshot.Regions.ToArray());
        }
        catch (Exception error)
        {
            operationError = error;
            throw;
        }
        finally
        {
            if (!FileSystemCleanup.TryDeleteFile(temp, out Exception? cleanupError) &&
                operationError is not null && cleanupError is not null)
            {
                FileSystemCleanup.AttachCleanupFailure(operationError, cleanupError);
            }
        }
    }

    private static FirmwareReadSnapshot CopySnapshot(FirmwareReadSnapshot snapshot) =>
        new(snapshot.Data.ToArray(), snapshot.Scope, snapshot.Regions.ToArray());

    private static void ValidateSnapshot(FirmwareReadSnapshot snapshot)
    {
        if (snapshot.Data.Length is < BiosImageLoader.MinBiosImageBytes or > BiosImageLoader.MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }

        if (snapshot.Regions.Count == 0)
        {
            throw new InvalidDataException(FirmwareValidationError.InvalidBiosRegion);
        }
    }

    private static bool SnapshotsMatch(FirmwareReadSnapshot first, FirmwareReadSnapshot second)
    {
        if (first.Scope != second.Scope ||
            first.Data.Length != second.Data.Length ||
            !first.Regions.SequenceEqual(second.Regions))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(first.Data),
            SHA256.HashData(second.Data));
    }

    private sealed class InlineProgress(Action<double> callback) : IProgress<double>
    {
        public void Report(double value) => callback(value);
    }
}
