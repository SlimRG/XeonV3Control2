namespace XeonV3Control.App;

internal readonly record struct ResponsiveLayoutState(
    double ContentWidth,
    bool UseNarrowPadding,
    bool UseTwoColumnActions);

internal static class ResponsiveLayout
{
    internal static ResponsiveLayoutState Calculate(
        double viewportWidth,
        double maxContentWidth,
        double mediumBreakpoint,
        double twoColumnActionsBreakpoint)
    {
        ValidatePositiveFinite(viewportWidth, nameof(viewportWidth));
        ValidatePositiveFinite(maxContentWidth, nameof(maxContentWidth));
        ValidateNonNegativeFinite(mediumBreakpoint, nameof(mediumBreakpoint));
        ValidatePositiveFinite(twoColumnActionsBreakpoint, nameof(twoColumnActionsBreakpoint));

        if (twoColumnActionsBreakpoint < mediumBreakpoint)
        {
            throw new ArgumentOutOfRangeException(
                nameof(twoColumnActionsBreakpoint),
                twoColumnActionsBreakpoint,
                "The two-column breakpoint cannot be smaller than the medium breakpoint.");
        }

        double contentWidth = Math.Min(viewportWidth, maxContentWidth);
        return new ResponsiveLayoutState(
            contentWidth,
            contentWidth < mediumBreakpoint,
            contentWidth >= twoColumnActionsBreakpoint);
    }

    private static void ValidatePositiveFinite(double value, string parameterName)
    {
        if (!double.IsFinite(value) || value <= 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Value must be finite and greater than zero.");
        }
    }

    private static void ValidateNonNegativeFinite(double value, string parameterName)
    {
        if (!double.IsFinite(value) || value < 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Value must be finite and non-negative.");
        }
    }
}
