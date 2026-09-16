using System.Security.Cryptography;

namespace XeonV3Control.Core;

internal static class Sha256Identity
{
    internal const int ByteCount = 32;
    internal const int HexCharacterCount = ByteCount * 2;

    internal static string Normalize(string? value, string errorKey)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(errorKey);
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(value);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException(errorKey, error);
        }

        if (bytes.Length != ByteCount)
        {
            throw new InvalidDataException(errorKey);
        }
        return Convert.ToHexString(bytes);
    }

    internal static bool Matches(ReadOnlySpan<byte> data, string expectedHash) =>
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), Convert.FromHexString(expectedHash));
}
