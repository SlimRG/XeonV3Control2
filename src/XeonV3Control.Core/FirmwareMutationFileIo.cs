using System.Security.Cryptography;

namespace XeonV3Control.Core;

/// <summary>Shared fail-closed file I/O primitives for managed firmware mutation paths.</summary>
internal static class FirmwareMutationFileIo
{
    internal static async Task<byte[]> ReadImageAsync(string path, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        await using var input = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            UefiFirmwareSpecification.FileIoBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length is < BiosImageLoader.MinBiosImageBytes or > BiosImageLoader.MaxImageBytes)
        {
            throw new InvalidDataException(FirmwareValidationError.ImageSize);
        }

        byte[] image = new byte[checked((int)input.Length)];
        await input.ReadExactlyAsync(image, token);
        return image;
    }

    internal static void VerifySha256(ReadOnlySpan<byte> source, string expectedSha256, string mismatchError)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mismatchError);
        if (string.IsNullOrWhiteSpace(expectedSha256))
        {
            throw new InvalidDataException(mismatchError);
        }

        byte[] expected;
        try
        {
            expected = Convert.FromHexString(expectedSha256);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException(mismatchError, error);
        }
        if (expected.Length != SHA256.HashSizeInBytes)
        {
            throw new InvalidDataException(mismatchError);
        }

        byte[] actual = SHA256.HashData(source);
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            throw new InvalidDataException(mismatchError);
        }
    }

    internal static async Task WriteNewVerifiedImageAsync(
        string destinationPath,
        ReadOnlyMemory<byte> image,
        CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        string destination = Path.GetFullPath(destinationPath);
        string partial = destination + "." + Guid.NewGuid().ToString("N") + ".partial";
        byte[] expectedHash = SHA256.HashData(image.Span);
        Exception? operationError = null;
        try
        {
            await using (var output = new FileStream(
                partial,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                UefiFirmwareSpecification.FileIoBufferBytes,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(image, token);
                await output.FlushAsync(token);
                output.Flush(flushToDisk: true);
            }

            await using (var verification = new FileStream(
                partial,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                UefiFirmwareSpecification.FileIoBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                byte[] actualHash = await SHA256.HashDataAsync(verification, token);
                if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
                {
                    throw new IOException(OperationError.OutputVerification);
                }
            }

            token.ThrowIfCancellationRequested();
            File.Move(partial, destination, overwrite: false);
        }
        catch (Exception error)
        {
            operationError = error;
            throw;
        }
        finally
        {
            if (!FileSystemCleanup.TryDeleteFile(partial, out Exception? cleanupError) &&
                operationError is not null && cleanupError is not null)
            {
                FileSystemCleanup.AttachCleanupFailure(operationError, cleanupError);
            }
        }
    }
}
