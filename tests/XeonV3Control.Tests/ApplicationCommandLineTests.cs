using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.App;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class ApplicationCommandLineTests
{
    [TestMethod]
    public void EmptyLaunchHasNoExternalImageOrSmokeRequest()
    {
        ApplicationLaunchRequest request = ApplicationLaunchRequest.Parse(["app.exe"]);
        Assert.IsNull(request.ImagePath);
        Assert.IsNull(request.UiSmoke);
    }

    [TestMethod]
    public void SingleExternalArgumentIsTreatedAsImagePath()
    {
        const string image = "firmware.rom";
        ApplicationLaunchRequest request = ApplicationLaunchRequest.Parse(["app.exe", image]);
        Assert.AreEqual(image, request.ImagePath);
        Assert.IsNull(request.UiSmoke);
    }

    [TestMethod]
    public void UiSmokeRequiresExactlyOutputCultureAndImageArguments()
    {
        ApplicationLaunchRequest request = ApplicationLaunchRequest.Parse(
            ["app.exe", ApplicationLaunchRequest.UiSmokeSwitch, "out", "culture", "bios.bin"]);
        Assert.IsNull(request.ImagePath);
        UiSmokeRequest smoke = request.UiSmoke ?? throw new AssertFailedException("UI smoke request was not parsed.");
        Assert.AreEqual("out", smoke.OutputDirectory);
        Assert.AreEqual("culture", smoke.Culture);
        Assert.AreEqual("bios.bin", smoke.ImagePath);

        Assert.Throws<ArgumentException>(() => ApplicationLaunchRequest.Parse(
            ["app.exe", ApplicationLaunchRequest.UiSmokeSwitch, "out", "culture"]));
    }

    [TestMethod]
    public void UnexpectedExtraArgumentsAreRejected() =>
        Assert.Throws<ArgumentException>(() => ApplicationLaunchRequest.Parse(
            ["app.exe", "one.bin", "two.bin"]));
}
