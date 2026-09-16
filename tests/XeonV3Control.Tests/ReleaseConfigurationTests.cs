using System.Xml.Linq;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class ReleaseConfigurationTests
{
    [TestMethod]
    public void PortableReleaseRemainsCompressedAndSizeGuarded()
    {
        string projectPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "XeonV3Control.App.csproj");
        XDocument project = XDocument.Load(projectPath);

        string Property(string name) => project
            .Descendants(name)
            .Select(element => element.Value.Trim())
            .FirstOrDefault(value => value.Length > 0)
            ?? string.Empty;

        Assert.AreEqual("true", Property("SelfContained"));
        Assert.AreEqual("true", Property("WindowsAppSDKSelfContained"));
        Assert.AreEqual("true", Property("PublishSingleFile"));
        Assert.AreEqual("true", Property("EnableCompressionInSingleFile"));
        Assert.AreEqual("true", Property("IncludeAllContentForSelfExtract"));
        Assert.AreEqual("false", Property("PublishReadyToRun"));
        Assert.AreEqual("false", Property("PublishTrimmed"));

        Assert.IsTrue(int.TryParse(Property("ReleaseMaximumExecutableMiB"), out int maximumMiB));
        Assert.IsTrue(maximumMiB > 0 && maximumMiB <= 384);

        string buildScriptPath = RepositoryTestFiles.Find("scripts", "Build-Release.ps1");
        string buildScript = File.ReadAllText(buildScriptPath);
        StringAssert.Contains(buildScript, "ReleaseMaximumExecutableMiB");
        StringAssert.Contains(buildScript, "Single-file compression must remain enabled");
        StringAssert.Contains(buildScript, "Release executable exceeds configured size limit");
        StringAssert.Contains(buildScript, "Release size:");
        StringAssert.Contains(buildScript, "Get-FileHash -LiteralPath $publishedExecutable -Algorithm SHA256");
    }

    [TestMethod]
    public void SelfContainedManifestPreservesRequiredElevation()
    {
        string projectPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "XeonV3Control.App.csproj");
        XDocument project = XDocument.Load(projectPath);

        XElement target = project
            .Descendants("Target")
            .Single(element => (string?)element.Attribute("Name") == "RequireAdministratorInSelfContainedManifest");

        Assert.AreEqual("CreateWinRTRegistration", (string?)target.Attribute("AfterTargets"));
        Assert.AreEqual("requireAdministrator", (string?)target.Element("XmlPoke")?.Attribute("Value"));
        Assert.IsNotNull(target.Element("XmlPeek"));
        Assert.IsNotNull(target.Element("Error"));

        string manifestPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "app.manifest");
        XDocument manifest = XDocument.Load(manifestPath);
        XNamespace manifestV3 = "urn:schemas-microsoft-com:asm.v3";
        XElement executionLevel = manifest.Descendants(manifestV3 + "requestedExecutionLevel").Single();

        Assert.AreEqual("requireAdministrator", (string?)executionLevel.Attribute("level"));
    }
}
