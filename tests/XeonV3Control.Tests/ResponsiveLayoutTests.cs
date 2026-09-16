using XeonV3Control.App;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class ResponsiveLayoutTests
{
    private const double MaxContentWidth = 1280;
    private const double MediumBreakpoint = 641;
    private const double TwoColumnActionsBreakpoint = 1120;

    [TestMethod]
    [DataRow(600, 600, true, false)]
    [DataRow(900, 900, false, false)]
    [DataRow(1075, 1075, false, false)]
    [DataRow(1120, 1120, false, true)]
    [DataRow(1440, 1280, false, true)]
    [DataRow(2400, 1280, false, true)]
    public void LayoutUsesAvailableContentWidth(
        double viewportWidth,
        double expectedContentWidth,
        bool expectedNarrowPadding,
        bool expectedTwoColumns)
    {
        ResponsiveLayoutState result = ResponsiveLayout.Calculate(
            viewportWidth,
            MaxContentWidth,
            MediumBreakpoint,
            TwoColumnActionsBreakpoint);

        Assert.AreEqual(expectedContentWidth, result.ContentWidth);
        Assert.AreEqual(expectedNarrowPadding, result.UseNarrowPadding);
        Assert.AreEqual(expectedTwoColumns, result.UseTwoColumnActions);
    }

    [TestMethod]
    public void InvalidViewportIsRejected()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ResponsiveLayout.Calculate(
            0,
            MaxContentWidth,
            MediumBreakpoint,
            TwoColumnActionsBreakpoint));
    }
}
