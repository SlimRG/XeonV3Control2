using System.Xml.Linq;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class XamlResourceTests
{
    private static readonly XNamespace Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    [TestMethod]
    public void GridDefinitionResourcesUseGridLengthRatherThanDouble()
    {
        string appPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "App.xaml");
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument resources = XDocument.Load(appPath);
        XDocument window = XDocument.Load(windowPath);

        Dictionary<string, string> resourceTypes = resources
            .Descendants()
            .Where(element => element.Attribute(Xaml + "Key") is not null)
            .ToDictionary(
                element => element.Attribute(Xaml + "Key")!.Value,
                element => element.Name.LocalName,
                StringComparer.Ordinal);

        AssertGridLengthResources(window.Descendants(Presentation + "RowDefinition"), "Height", resourceTypes);
        AssertGridLengthResources(window.Descendants(Presentation + "ColumnDefinition"), "Width", resourceTypes);
    }



    [TestMethod]
    public void UefiDriverStylesUseThemeResourcesForRuntimeThemeSwitching()
    {
        string appPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "App.xaml");
        XDocument resources = XDocument.Load(appPath);

        string[] borderStyles =
        [
            "UefiDriverBorderStyle",
            "UefiDriverWarningBorderStyle",
            "UefiDriverErrorBorderStyle",
            "UefiDriverInformationBorderStyle"
        ];
        foreach (string key in borderStyles)
        {
            XElement style = ResourceElement(resources, key);
            XElement[] setters = style.Elements(Presentation + "Setter").ToArray();
            foreach (XElement setter in setters.Where(item =>
                         item.Attribute("Property")?.Value is "Background" or "BorderBrush"))
            {
                Assert.IsTrue((setter.Attribute("Value")?.Value ?? string.Empty).StartsWith("{ThemeResource ", StringComparison.Ordinal));
            }
        }

        string[] textStyles =
        [
            "UefiDriverSuccessTextStyle",
            "UefiDriverWarningTextStyle",
            "UefiDriverErrorTextStyle",
            "UefiDriverInformationTextStyle"
        ];
        foreach (string key in textStyles)
        {
            XElement style = ResourceElement(resources, key);
            XElement foreground = style.Elements(Presentation + "Setter")
                .Single(item => item.Attribute("Property")?.Value == "Foreground");
            Assert.IsTrue((foreground.Attribute("Value")?.Value ?? string.Empty).StartsWith("{ThemeResource ", StringComparison.Ordinal));
        }
    }

    [TestMethod]
    public void ShellUsesAdaptiveNavigationViewWithBuiltInSettings()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);
        XElement navigation = window.Descendants(Presentation + "NavigationView").Single();

        Assert.AreEqual("Auto", navigation.Attribute("PaneDisplayMode")?.Value);
        Assert.AreEqual("True", navigation.Attribute("IsSettingsVisible")?.Value);
        Assert.AreEqual("ShellNavigationItemInvoked", navigation.Attribute("ItemInvoked")?.Value);
        Assert.AreEqual("{StaticResource LayoutMediumBreakpoint}", navigation.Attribute("CompactModeThresholdWidth")?.Value);
        Assert.AreEqual("{StaticResource LayoutWideBreakpoint}", navigation.Attribute("ExpandedModeThresholdWidth")?.Value);
        Assert.IsFalse(window.Descendants(Presentation + "ListView").Any(),
            "Do not reintroduce the legacy hand-built sidebar navigation.");
        Assert.IsFalse(navigation.Elements(Presentation + "NavigationView.PaneHeader").Any(),
            "Platform context belongs in the TitleBar subtitle, not in a custom NavigationView pane header.");
    }



    [TestMethod]
    public void ShellUsesWinUiTitleBarWithoutManualCaptionButtonPadding()
    {
        string appPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "App.xaml");
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument resources = XDocument.Load(appPath);
        XDocument window = XDocument.Load(windowPath);

        XElement titleBar = window.Descendants(Presentation + "TitleBar").Single();
        Assert.AreEqual("AppTitleBar", titleBar.Attribute(Xaml + "Name")?.Value);
        Assert.AreEqual("True", titleBar.Attribute("IsPaneToggleButtonVisible")?.Value);
        Assert.AreEqual("AppTitleBarPaneToggleRequested", titleBar.Attribute("PaneToggleRequested")?.Value);
        XElement navigation = window.Descendants(Presentation + "NavigationView").Single();
        Assert.AreEqual("False", navigation.Attribute("IsPaneToggleButtonVisible")?.Value);
        Assert.IsFalse(resources.Descendants().Any(element =>
            (element.Attribute(Xaml + "Key")?.Value ?? string.Empty).StartsWith("LayoutTitleBarPadding", StringComparison.Ordinal)));
        Assert.IsFalse(resources.Descendants().Any(element =>
            string.Equals(element.Attribute(Xaml + "Key")?.Value, "LayoutTitleBarHeight", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void MicaFoundationIsNotCoveredByOpaqueRootSurface()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement root = window.Descendants(Presentation + "Grid")
            .Single(element => string.Equals(element.Attribute(Xaml + "Name")?.Value, "Root", StringComparison.Ordinal));
        XElement navigation = window.Descendants(Presentation + "NavigationView").Single();
        Assert.AreEqual("Transparent", root.Attribute("Background")?.Value);
        Assert.AreEqual("Transparent", navigation.Attribute("Background")?.Value);
        Assert.IsNotNull(window.Root?.Element(Presentation + "Window.SystemBackdrop")?.Element(Presentation + "MicaBackdrop"));
    }


    [TestMethod]
    public void SourceActionCardsUseSafeStackedDefaultsBeforeViewportSizing()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement actionCards = NamedElement(window, "Grid", "ActionCards");
        XElement fileCard = NamedElement(window, "Border", "FileCard");
        XElement systemCard = NamedElement(window, "Border", "SystemCard");
        XElement secondaryColumn = window.Descendants(Presentation + "ColumnDefinition")
            .Single(element => string.Equals(element.Attribute(Xaml + "Name")?.Value, "SecondaryActionColumn", StringComparison.Ordinal));

        Assert.IsNull(fileCard.Attribute("Grid.Column"), "The primary file action must remain in column 0 by default.");
        Assert.AreEqual("1", systemCard.Attribute("Grid.Row")?.Value);
        Assert.AreEqual("0", systemCard.Attribute("Grid.Column")?.Value);
        Assert.AreEqual("0", secondaryColumn.Attribute("Width")?.Value);
        Assert.AreEqual("0", actionCards.Attribute("ColumnSpacing")?.Value);
        Assert.AreEqual("{StaticResource LayoutStackedActionSpacing}", actionCards.Attribute("RowSpacing")?.Value);
    }

    [TestMethod]
    public void ContentSizingIsDrivenByTheNavigationViewport()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement scroller = NamedElement(window, "ScrollViewer", "ContentScroller");
        XElement contentPanel = NamedElement(window, "StackPanel", "ContentPanel");
        XElement statusHost = NamedElement(window, "Grid", "StatusHost");

        Assert.AreEqual("ContentScrollerSizeChanged", scroller.Attribute("SizeChanged")?.Value);
        Assert.AreEqual("Disabled", scroller.Attribute("HorizontalScrollMode")?.Value);
        Assert.IsNull(contentPanel.Attribute("Width"), "Viewport width must be assigned from the SizeChanged handler, not a stale ActualWidth binding.");
        Assert.IsNull(statusHost.Attribute("Width"), "Status width must follow the same viewport sizing path as page content.");
        Assert.AreEqual("{StaticResource LayoutContentMaxWidth}", contentPanel.Attribute("MaxWidth")?.Value);
        Assert.IsFalse(window.Descendants(Presentation + "AdaptiveTrigger").Any(),
            "Internal page layout must not use outer-window AdaptiveTrigger breakpoints.");
    }

    [TestMethod]
    public void BusyStatusKeepsCancelActionInDedicatedColumn()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement cancelButton = NamedElement(window, "Button", "CancelButton");
        Assert.AreEqual("1", cancelButton.Attribute("Grid.Column")?.Value,
            "Cancel must not overlap the busy-status text.");
    }

    [TestMethod]
    public void PaneFooterTruncatesLongCurrentFileName()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement currentFile = NamedElement(window, "TextBlock", "CurrentFileLabel");
        Assert.AreEqual("NoWrap", currentFile.Attribute("TextWrapping")?.Value);
        Assert.AreEqual("CharacterEllipsis", currentFile.Attribute("TextTrimming")?.Value);
    }

    [TestMethod]
    public void ContentUsesMicaFoundationAndWindowsNavigationGutters()
    {
        string appPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "App.xaml");
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument resources = XDocument.Load(appPath);
        XDocument window = XDocument.Load(windowPath);

        XElement contentHost = NamedElement(window, "Grid", "ContentHost");
        Assert.AreEqual("Grid", contentHost.Name.LocalName,
            "Do not cover the Mica foundation with one application-sized card surface.");
        Assert.AreEqual("12", ResourceValue(resources, "LayoutContentPaddingNarrow"));
        Assert.AreEqual("24", ResourceValue(resources, "LayoutContentPaddingMedium"));
        Assert.AreEqual("24", ResourceValue(resources, "LayoutContentPaddingWide"));
    }

    [TestMethod]
    public void HeadingsUseWindowsTypeRampResources()
    {
        string appPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "App.xaml");
        XDocument resources = XDocument.Load(appPath);

        XElement pageHeading = ResourceElement(resources, "PageHeadingTextStyle");
        XElement sectionHeading = ResourceElement(resources, "SectionTitleTextStyle");
        Assert.AreEqual("{StaticResource TitleTextBlockStyle}", pageHeading.Attribute("BasedOn")?.Value);
        Assert.AreEqual("{StaticResource SubtitleTextBlockStyle}", sectionHeading.Attribute("BasedOn")?.Value);
        Assert.IsNull(pageHeading.Attribute("FontSize"));
        Assert.IsNull(sectionHeading.Attribute("FontSize"));
    }

    [TestMethod]
    public void AnalysisPageDoesNotExposeUnimplementedFirmwareWriteAction()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        string[] forbiddenNames = ["WriteArea", "WriteButton", "WriteHint"];
        foreach (string name in forbiddenNames)
        {
            Assert.IsFalse(window.Descendants().Any(element =>
                string.Equals(element.Attribute(Xaml + "Name")?.Value, name, StringComparison.Ordinal)),
                $"Unimplemented firmware-write placeholder '{name}' must not be exposed in the product UI.");
        }
    }

    [TestMethod]
    public void SecureBootUsesOneDedicatedNoticeArea()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement noticePanel = NamedElement(window, "StackPanel", "SecureBootNoticePanel");
        XElement operationNotice = NamedElement(window, "InfoBar", "SecureBootNoticeBar");
        XElement issueHost = NamedElement(window, "StackPanel", "SecureBootIssueHost");
        Assert.IsTrue(noticePanel.DescendantsAndSelf().Contains(operationNotice));
        Assert.IsTrue(noticePanel.DescendantsAndSelf().Contains(issueHost));
        Assert.AreEqual("{StaticResource LayoutNoticeStackSpacing}", noticePanel.Attribute("Spacing")?.Value);
    }

    [TestMethod]
    public void SupportScopeIsPersistentWhileTransientStatusRemainsClosable()
    {
        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        XDocument window = XDocument.Load(windowPath);

        XElement support = NamedElement(window, "InfoBar", "SupportBar");
        XElement status = NamedElement(window, "InfoBar", "StatusBar");
        Assert.AreEqual("False", support.Attribute("IsClosable")?.Value,
            "Supported-platform scope must remain visible on the source page.");
        Assert.AreEqual("True", status.Attribute("IsClosable")?.Value,
            "Transient operation status may remain dismissible.");
    }

    private static XElement NamedElement(XDocument document, string localName, string name)
    {
        return document.Descendants(Presentation + localName).Single(element =>
            string.Equals(element.Attribute(Xaml + "Name")?.Value, name, StringComparison.Ordinal));
    }


    private static XElement ResourceElement(XDocument resources, string key)
    {
        return resources.Descendants().Single(element =>
            string.Equals(element.Attribute(Xaml + "Key")?.Value, key, StringComparison.Ordinal));
    }

    private static string ResourceValue(XDocument resources, string key)
    {
        return ResourceElement(resources, key).Value.Trim();
    }

    private static void AssertGridLengthResources(
        IEnumerable<XElement> definitions,
        string propertyName,
        IReadOnlyDictionary<string, string> resourceTypes)
    {
        foreach (XElement definition in definitions)
        {
            string? value = definition.Attribute(propertyName)?.Value;
            if (!TryGetStaticResourceKey(value, out string key))
            {
                continue;
            }

            if (!resourceTypes.TryGetValue(key, out string? resourceType) || resourceType is null)
            {
                throw new AssertFailedException(
                    $"StaticResource '{key}' referenced by {definition.Name.LocalName}.{propertyName} is missing.");
            }
            Assert.AreEqual("GridLength", resourceType,
                $"StaticResource '{key}' used by {definition.Name.LocalName}.{propertyName} must be GridLength, not {resourceType}.");
        }
    }


    private static bool TryGetStaticResourceKey(string? value, out string key)
    {
        const string prefix = "{StaticResource ";
        key = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith(prefix, StringComparison.Ordinal) || value[^1] != '}')
        {
            return false;
        }

        key = value[prefix.Length..^1].Trim();
        return key.Length > 0;
    }
}
