using System.Security.Cryptography;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class SupplyChainTests
{
    [TestMethod]
    public void BundledThrottleStopDriverMatchesIntegrityManifest()
    {
        string manifestPath = RepositoryTestFiles.Find("third_party", "ThrottleStop", "integrity.json");
        BinaryIntegrityManifest manifest;
        using (var manifestStream = File.OpenRead(manifestPath))
            manifest = BinaryIntegrityManifest.Load(manifestStream);

        string driverPath = RepositoryTestFiles.Find("third_party", "ThrottleStop", manifest.FileName);
        using var driverStream = File.OpenRead(driverPath);
        string actual = Convert.ToHexString(SHA256.HashData(driverStream));
        Assert.AreEqual(manifest.Sha256, actual);
    }

    [TestMethod]
    public void IntegrityManifestRejectsPathTraversalAndMalformedHashes()
    {
        const string invalidManifest = """
            {
              "FileName": "../driver.sys",
              "Sha256": "00",
              "SignerCertificateSha256": "00"
            }
            """;
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(invalidManifest));
        Assert.Throws<InvalidDataException>(() => BinaryIntegrityManifest.Load(stream));
    }

}
