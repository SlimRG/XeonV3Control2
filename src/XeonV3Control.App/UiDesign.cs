using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using System.Runtime.InteropServices;
using Windows.Graphics;

namespace XeonV3Control.App;

internal static class UiDesign
{
    internal static readonly SizeInt32 DefaultWindowSize = new(1440, 1000);

    internal static SizeInt32 GetWindowSize(WindowId windowId, SizeInt32 logicalSize,
        double rasterizationScale)
    {
        double scale = double.IsFinite(rasterizationScale) && rasterizationScale > 0d
            ? rasterizationScale
            : 1d;
        var physicalSize = new SizeInt32(
            ScaleDimension(logicalSize.Width, scale),
            ScaleDimension(logicalSize.Height, scale));

        DisplayArea displayArea = DisplayArea.GetFromWindowId(windowId, DisplayAreaFallback.Primary);
        RectInt32 workArea = displayArea.WorkArea;
        if (workArea.Width <= 0 || workArea.Height <= 0)
        {
            return physicalSize;
        }

        return new SizeInt32(
            Math.Min(physicalSize.Width, workArea.Width),
            Math.Min(physicalSize.Height, workArea.Height));
    }

    internal static double GetRasterizationScale(nint windowHandle)
    {
        uint dpi = Native.GetDpiForWindow(windowHandle);
        return dpi > 0 ? dpi / StandardDpi : 1d;
    }

    private static int ScaleDimension(int value, double scale)
    {
        double scaled = Math.Round(value * scale, MidpointRounding.AwayFromZero);
        return (int)Math.Clamp(scaled, 1d, int.MaxValue);
    }

    private static class Native
    {
        [DllImport("user32.dll")]
        internal static extern uint GetDpiForWindow(nint windowHandle);
    }

    internal static readonly SizeInt32 SmokeNarrowWindowSize = new(620, 760);
    internal static readonly SizeInt32 SmokeMediumWindowSize = new(900, 800);
    internal static readonly SizeInt32 SmokeWideWindowSize = DefaultWindowSize;
    internal const int AdaptiveLayoutSettleMilliseconds = 100;
    internal const int SmokeRenderSettleMilliseconds = 150;
    internal const int LanguageChangeSettleMilliseconds = 150;
    internal const int ThemeChangeSettleMilliseconds = 150;
    internal const int ResultFadeDurationMilliseconds = 180;
    internal const double DialogContentSpacing = 8d;
    internal const int MaximumDisplayedFirmwareVolumes = 128;
    internal const int MaximumDisplayedUefiDrivers = 512;
    internal const int MaximumExpandedUefiDriverSearchResults = 64;
    internal const int BytesPerKibibyte = 1024;
    internal const int BytesPerMebibyte = 1024 * BytesPerKibibyte;
    internal const double ProgressPercentageScale = 100d;
    internal const double StandardDpi = 96d;
    internal const double SmokeScrollOffset = 360;
}

internal static class UiResourceKeys
{
    internal const string LayoutContentMaxWidth = "LayoutContentMaxWidth";
    internal const string LayoutMediumBreakpoint = "LayoutMediumBreakpoint";
    internal const string LayoutActionCardsTwoColumnMinWidth = "LayoutActionCardsTwoColumnMinWidth";
    internal const string LayoutContentPaddingNarrow = "LayoutContentPaddingNarrow";
    internal const string LayoutContentPaddingMedium = "LayoutContentPaddingMedium";
    internal const string LayoutContentPaddingWide = "LayoutContentPaddingWide";
    internal const string LayoutStatusPaddingNarrow = "LayoutStatusPaddingNarrow";
    internal const string LayoutStatusPaddingMedium = "LayoutStatusPaddingMedium";
    internal const string LayoutStatusPaddingWide = "LayoutStatusPaddingWide";
    internal const string LayoutWideActionSpacing = "LayoutWideActionSpacing";
    internal const string LayoutStackedActionSpacing = "LayoutStackedActionSpacing";
    internal const string CardBorderStyle = "CardBorderStyle";
    internal const string PrimaryActionButtonStyle = "PrimaryActionButtonStyle";
    internal const string SectionTitleTextStyle = "SectionTitleTextStyle";
    internal const string UefiDriverBorderStyle = "UefiDriverBorderStyle";
    internal const string UefiDriverWarningBorderStyle = "UefiDriverWarningBorderStyle";
    internal const string UefiDriverErrorBorderStyle = "UefiDriverErrorBorderStyle";
    internal const string UefiDriverInformationBorderStyle = "UefiDriverInformationBorderStyle";
    internal const string UefiDriverSuccessTextStyle = "UefiDriverSuccessTextStyle";
    internal const string UefiDriverWarningTextStyle = "UefiDriverWarningTextStyle";
    internal const string UefiDriverErrorTextStyle = "UefiDriverErrorTextStyle";
    internal const string UefiDriverInformationTextStyle = "UefiDriverInformationTextStyle";
    internal const string LayoutDynamicCardSpacing = "LayoutDynamicCardSpacing";
    internal const string LayoutHeaderStackSpacing = "LayoutHeaderStackSpacing";
    internal const string LayoutNoticeSpacing = "LayoutNoticeSpacing";
    internal const string LayoutNoticeStackSpacing = "LayoutNoticeStackSpacing";
    internal const string LayoutRowColumnSpacing = "LayoutRowColumnSpacing";
    internal const string LayoutRowLabelMaxWidth = "LayoutRowLabelMaxWidth";
    internal const string LayoutSecondaryTextOpacity = "LayoutSecondaryTextOpacity";
    internal const string LayoutBootLogoPreviewHeight = "LayoutBootLogoPreviewHeight";
    internal const string LayoutCardCornerRadius = "LayoutCardCornerRadius";
    internal const string LayoutInlineIconSpacing = "LayoutInlineIconSpacing";
    internal const string LayoutInlineIconFontSize = "LayoutInlineIconFontSize";
    internal const string LayoutSecureBootMetricsColumnSpacing = "LayoutSecureBootMetricsColumnSpacing";
    internal const string LayoutMetricSpacing = "LayoutMetricSpacing";
    internal const string LayoutMetricValueFontSize = "LayoutMetricValueFontSize";
    internal const string LayoutMetricCaptionOpacity = "LayoutMetricCaptionOpacity";
    internal const string LayoutCertificateListSpacing = "LayoutCertificateListSpacing";
    internal const string LayoutCertificateItemSpacing = "LayoutCertificateItemSpacing";
    internal const string LayoutCertificateItemPadding = "LayoutCertificateItemPadding";
    internal const string LayoutCertificateItemBorderThickness = "LayoutCertificateItemBorderThickness";
    internal const string LayoutCertificateItemCornerRadius = "LayoutCertificateItemCornerRadius";
    internal const string SemanticSuccessBrush = "SystemFillColorSuccessBrush";
    internal const string SemanticWarningBrush = "SystemFillColorCautionBrush";
    internal const string SemanticErrorBrush = "SystemFillColorCriticalBrush";
    internal const string SemanticInformationBrush = "AccentTextFillColorPrimaryBrush";
    internal const string SemanticSuccessBackgroundBrush = "SystemFillColorSuccessBackgroundBrush";
    internal const string SemanticWarningBackgroundBrush = "SystemFillColorCautionBackgroundBrush";
    internal const string SemanticErrorBackgroundBrush = "SystemFillColorCriticalBackgroundBrush";
    internal const string SemanticInformationBackgroundBrush = "SystemFillColorAttentionBackgroundBrush";
    internal const string CardStrokeBrush = "CardStrokeColorDefaultBrush";
    internal const string ControlFillBrush = "ControlFillColorDefaultBrush";
}

internal static class UiResources
{
    internal static T Get<T>(string key)
    {
        if (Application.Current.Resources.TryGetValue(key, out object? value) && value is T typed)
        {
            return typed;
        }
        throw new InvalidOperationException("Missing or invalid UI resource: " + key);
    }
}

internal static class UiGlyphs
{
    internal const string OpenFile = "\uE8E5";
    internal const string ReadFirmware = "\uE896";
    internal const string UpdateCertificate = "\uE895";
    internal const string Cancel = "\uE711";
    internal const string Navigate = "\uE72E";
    internal const string Search = "\uE721";
    internal const string Audio = "\uE767";
    internal const string Delete = "\uE74D";
    internal const string Apply = "\uE73E";
}


