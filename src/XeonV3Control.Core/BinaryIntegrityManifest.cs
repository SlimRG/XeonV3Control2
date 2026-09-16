using System.Text.Json;

namespace XeonV3Control.Core;

/// <summary>Immutable identity metadata for a bundled binary whose exact bytes are security-sensitive.</summary>
public sealed record BinaryIntegrityManifest(string FileName, string Sha256, string SignerCertificateSha256)
{
    public const int Sha256ByteCount = Sha256Identity.ByteCount;

    public static BinaryIntegrityManifest Load(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        BinaryIntegrityManifest manifest = JsonSerializer.Deserialize<BinaryIntegrityManifest>(stream)
            ?? throw new InvalidDataException(OperationError.IntegrityManifest);

        string fileName = ValidateFileName(manifest.FileName);
        string binaryHash = NormalizeSha256(manifest.Sha256);
        string signerHash = NormalizeSha256(manifest.SignerCertificateSha256);
        return new(fileName, binaryHash, signerHash);
    }

    public byte[] GetSha256Bytes() => Convert.FromHexString(Sha256);
    public byte[] GetSignerCertificateSha256Bytes() => Convert.FromHexString(SignerCertificateSha256);

    private static string ValidateFileName(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) ||
            !string.Equals(fileName, Path.GetFileName(fileName), StringComparison.Ordinal) ||
            fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new InvalidDataException(OperationError.IntegrityManifest);
        }

        return fileName;
    }

    private static string NormalizeSha256(string? value) =>
        Sha256Identity.Normalize(value, OperationError.IntegrityManifest);
}
