using System.ComponentModel;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Graphics;
using XeonV3Control.App.Hardware;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow : Window
{
    // Temporary product feature gate: keep the TPM implementation intact, but do not expose
    // it until hardware validation can resume with the required test equipment.
    private static readonly bool TpmUiEnabled = false;

    private LocalizationCatalog text;
    private readonly UserPreferences preferences;
    private readonly bool settingsPersistenceEnabled;
    private readonly SessionLifetime temporary;
    private readonly Action releaseResources;
    private readonly string? smokeDirectory;
    private readonly string? smokeImage;
    private readonly string? startupImage;
    private CancellationTokenSource? operation;
    private UiOperationKind? currentOperationKind;
    private BiosImage? activeImage;
    private ImageSourceKind? activeSource;
    private IReadOnlyList<FirmwareRegionReadStatus> activeDumpRegions = [];
    private string? activeInputPath;
    private string? activePackageEntry;
    private string? materializedWindowIconPath;
    private bool closing;
    private bool navigationSync;
    private bool alreadyRunningDialogOpen;
    private ElevatedFileDropTarget? elevatedFileDropTarget;
    private readonly SemaphoreSlim dialogGate = new(1, 1);
    private readonly Dictionary<WorkspacePage, double> pageScrollOffsets = [];
    private WorkspacePage currentPage = WorkspacePage.Source;
    private WorkspacePage pageBeforeSettings = WorkspacePage.Source;

    private enum WorkspacePage
    {
        Source,
        Analysis,
        SecureBoot,
        Drivers,
        TurboBoost,
        Personalization,
        Tpm,
        Save,
        Settings
    }

    private enum ImageSourceKind
    {
        File,
        FullSpi,
        PartialSpi,
        BiosRegion,
        UpdatedImage
    }

    private enum UiOperationKind
    {
        Loading,
        Dumping,
        UpdatingCertificates,
        UpdatingUefiDriver,
        RemovingCpuPatch,
        RemovingForeignUnlock,
        UpdatingBootLogo,
        UpdatingBeeper,
        UpdatingTpmDebugDriver,
        SavingImage,
        FlashingImage
    }


    public MainWindow(string? culture, SessionLifetime temporary, Action releaseResources,
        string? smokeDirectory = null, string? smokeImage = null, string? startupImage = null)
    {
        settingsPersistenceEnabled = smokeDirectory is null;
        preferences = settingsPersistenceEnabled ? UserPreferences.Load() : new UserPreferences();
        text = new LocalizationCatalog(culture ?? preferences.Culture);
        this.temporary = temporary;
        this.releaseResources = releaseResources;
        this.smokeDirectory = smokeDirectory;
        this.smokeImage = smokeImage;
        this.startupImage = startupImage;

        InitializeComponent();
        Title = ApplicationIdentity.DisplayName;
        AppTitleBar.Title = ApplicationIdentity.DisplayName;
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        ResizeWindow(UiDesign.DefaultWindowSize);

        ApplyThemePreference(preferences.Theme);
        ApplyLocalization();
        ApplyImageAvailabilityState();
        NavigateTo(WorkspacePage.Source);

        ConfigureCaptionButtons();
        ApplyWindowIcon();
        AppWindow.Closing += (_, e) =>
        {
            if (operation is not null)
            {
                e.Cancel = true;
                closing = true;
                operation.Cancel();
                return;
            }

            elevatedFileDropTarget?.Dispose();
            elevatedFileDropTarget = null;
            releaseResources();
        };

        Root.Loaded += RootLoaded;
    }

    private void ApplyLocalization()
    {
        SetNavigationItemText(SourceNavigationItem, text["NavSource"]);
        SetNavigationItemText(AnalysisNavigationItem, text["NavAnalysis"]);
        SetNavigationItemText(SecureBootNavigationItem, text["NavSecureBoot"]);
        SetNavigationItemText(DriversNavigationItem, text["NavDrivers"]);
        SetNavigationItemText(TurboBoostNavigationItem, text["NavTurboBoostUnlock"]);
        SetNavigationItemText(PersonalizationNavigationItem, text["NavPersonalization"]);
        SetNavigationItemText(TpmNavigationItem, text["NavTpm"]);
        SetNavigationItemText(SaveNavigationItem, text["NavSave"]);
        AppTitleBar.Subtitle = text["PlatformName"];
        if (ShellNavigation.SettingsItem is NavigationViewItem settingsItem)
        {
            settingsItem.Content = text["Settings"];
            ToolTipService.SetToolTip(settingsItem, text["Settings"]);
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(settingsItem, text["Settings"]);
        }

        Heading.Text = text["Title"];
        Subtitle.Text = text["Subtitle"];
        AnalysisHeading.Text = text["AnalysisTitle"];
        AnalysisSubtitle.Text = text["AnalysisSubtitle"];
        SecureBootHeading.Text = text["SecureBootTitle"];
        SecureBootSubtitle.Text = text["SecureBootSubtitle"];
        DriversHeading.Text = text["UefiDriversTitle"];
        DriversSubtitle.Text = text["UefiDriversSubtitle"];
        TurboBoostHeading.Text = text["TurboBoostTitle"];
        TurboBoostSubtitle.Text = text["TurboBoostSubtitle"];
        PersonalizationHeading.Text = text["PersonalizationTitle"];
        PersonalizationSubtitle.Text = text["PersonalizationSubtitle"];
        TpmHeading.Text = text["TpmTitle"];
        TpmSubtitle.Text = text["TpmSubtitle"];
        SaveHeading.Text = text["SaveTitle"];
        SaveSubtitle.Text = text["SaveSubtitle"];

        SetNotice(SupportBar, string.Empty, text["Support"], InfoBarSeverity.Informational);
        SupportBar.IsClosable = false;
        FileTitle.Text = text["File"];
        FileHint.Text = text["FileHint"];
        SystemTitle.Text = text["System"];
        SystemHint.Text = text["SystemHint"];
        EmptyTitle.Text = text["Empty"];
        EmptyHint.Text = text["EmptyHint"];
        DropHint.Text = text["DropBiosHere"];

        DecorateButtons();
        ApplySettingsLocalization();

        if (currentOperationKind is UiOperationKind operationKind)
        {
            BusyLabel.Text = text[operationKind.ToString()];
        }

        if (activeImage is not null)
        {
            RenderActiveImageViews();
            ApplyImageAvailabilityState();
        }
    }

    private async void RootLoaded(object sender, RoutedEventArgs e)
    {
        _ = sender;
        _ = e;
        Root.Loaded -= RootLoaded;
        ApplyResponsiveLayout(ContentScroller.ActualWidth);
        try
        {
            if (smokeDirectory is null)
            {
                InitializeElevatedFileDrop();
            }

            if (smokeDirectory is not null && smokeImage is not null)
            {
                await RunUiSmokeAsync(smokeDirectory, smokeImage);
                return;
            }

            if (!string.IsNullOrWhiteSpace(startupImage))
            {
                await LoadFileAsync(startupImage);
            }
        }
        catch (Exception error)
        {
            ShowError(error);
        }
    }

    private static void SetNavigationItemText(NavigationViewItem item, string value)
    {
        item.Content = value;
        ToolTipService.SetToolTip(item, value);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(item, value);
    }

    private async Task RunUiSmokeAsync(string smokeDirectory, string smokeImage)
    {
        try
        {
            Directory.CreateDirectory(smokeDirectory);
            UiSmoke.VerifyStaDataTransfer();
            if (AnalysisNavigationItem.Visibility != Visibility.Collapsed ||
                SecureBootNavigationItem.Visibility != Visibility.Collapsed ||
                DriversNavigationItem.Visibility != Visibility.Collapsed ||
                TurboBoostNavigationItem.Visibility != Visibility.Collapsed ||
                PersonalizationNavigationItem.Visibility != Visibility.Collapsed ||
                TpmNavigationItem.Visibility != Visibility.Collapsed ||
                SaveNavigationItem.Visibility != Visibility.Collapsed || !SourcePage.AllowDrop)
            {
                throw new IOException("Initial source state is invalid.");
            }

            string empty = Path.Combine(smokeDirectory, "empty.png");
            File.WriteAllBytes(empty, []);
            await UiSmoke.CaptureAsync(Root, empty);
            if (ShellNavigation.DisplayMode != NavigationViewDisplayMode.Expanded ||
                Grid.GetRow(SystemCard) != 0 || Grid.GetColumn(SystemCard) != 1)
            {
                throw new IOException("Wide adaptive navigation failed.");
            }

            ResizeWindow(UiDesign.SmokeNarrowWindowSize);
            string narrow = Path.Combine(smokeDirectory, "narrow.png");
            File.WriteAllBytes(narrow, []);
            await UiSmoke.CaptureAsync(Root, narrow);
            if (ShellNavigation.DisplayMode != NavigationViewDisplayMode.Minimal ||
                CurrentFileLabel.Visibility != Visibility.Collapsed ||
                Grid.GetRow(SystemCard) != 1 || Grid.GetColumn(SystemCard) != 0)
            {
                throw new IOException("Narrow adaptive layout failed.");
            }

            ResizeWindow(UiDesign.SmokeMediumWindowSize);
            string medium = Path.Combine(smokeDirectory, "medium.png");
            File.WriteAllBytes(medium, []);
            await UiSmoke.CaptureAsync(Root, medium);
            if (ShellNavigation.DisplayMode != NavigationViewDisplayMode.Compact ||
                CurrentFileLabel.Visibility != Visibility.Collapsed ||
                Grid.GetRow(SystemCard) != 1 || Grid.GetColumn(SystemCard) != 0)
            {
                throw new IOException("Medium adaptive layout failed.");
            }

            ResizeWindow(UiDesign.DefaultWindowSize);
            await Task.Delay(UiDesign.AdaptiveLayoutSettleMilliseconds);
            Root.UpdateLayout();
            var before = OpenButton.TransformToVisual(Root).TransformPoint(new Windows.Foundation.Point());
            var operationStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseOperation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task smokeOperation = RunOperation(async token =>
            {
                operationStarted.TrySetResult(true);
                await releaseOperation.Task.WaitAsync(token);
            }, UiOperationKind.Dumping);
            try
            {
                await operationStarted.Task;
                Root.UpdateLayout();

                if (operation is null || SourcePage.AllowDrop || OpenButton.IsEnabled || ReadButton.IsEnabled ||
                    ContentPanel.IsEnabled || SourceNavigationItem.IsEnabled ||
                    ShellNavigation.SettingsItem is not NavigationViewItem { IsEnabled: false } ||
                    !CancelButton.IsEnabled || BusyPanel.Visibility != Visibility.Visible ||
                    StatusHost.Visibility != Visibility.Visible || Progress.IsIndeterminate)
                {
                    throw new IOException("Operation interlock did not disable source actions and file drop.");
                }

                string busy = Path.Combine(smokeDirectory, "busy.png");
                File.WriteAllBytes(busy, []);
                await UiSmoke.CaptureAsync(Root, busy);
                var during = OpenButton.TransformToVisual(Root).TransformPoint(new Windows.Foundation.Point());
                if (before != during)
                {
                    throw new IOException($"Busy indicator moved the content: before={before}, during={during}.");
                }
            }
            finally
            {
                releaseOperation.TrySetResult(true);
                await smokeOperation;
            }
            Root.UpdateLayout();
            if (operation is not null || !SourcePage.AllowDrop || !OpenButton.IsEnabled || !ReadButton.IsEnabled ||
                !ContentPanel.IsEnabled || !SourceNavigationItem.IsEnabled ||
                ShellNavigation.SettingsItem is not NavigationViewItem { IsEnabled: true } ||
                CancelButton.IsEnabled || BusyPanel.Visibility != Visibility.Collapsed ||
                StatusHost.Visibility != Visibility.Collapsed)
            {
                throw new IOException("Operation interlock did not restore source actions and file drop.");
            }

            await LoadFileAsync(smokeImage);
            if (AnalysisPage.Visibility != Visibility.Visible || SourcePage.Visibility != Visibility.Collapsed ||
                AnalysisNavigationItem.Visibility != Visibility.Visible || SecureBootNavigationItem.Visibility != Visibility.Visible ||
                DriversNavigationItem.Visibility != Visibility.Visible || TurboBoostNavigationItem.Visibility != Visibility.Visible ||
                PersonalizationNavigationItem.Visibility != Visibility.Visible ||
                TpmNavigationItem.Visibility != Visibility.Collapsed || SaveNavigationItem.Visibility != Visibility.Visible ||
                !AnalysisNavigationItem.IsEnabled || !SecureBootNavigationItem.IsEnabled || !DriversNavigationItem.IsEnabled ||
                !TurboBoostNavigationItem.IsEnabled || !PersonalizationNavigationItem.IsEnabled ||
                TpmNavigationItem.IsEnabled || !SaveNavigationItem.IsEnabled ||
                !ReferenceEquals(ShellNavigation.SelectedItem, AnalysisNavigationItem) ||
                CurrentFileLabel.Visibility != Visibility.Visible || CurrentImageContextLabel.Visibility != Visibility.Collapsed ||
                StatusHost.Visibility != Visibility.Collapsed ||
                SourcePage.AllowDrop || StatusBar.Severity == InfoBarSeverity.Error)
            {
                throw new IOException("Image workflow failed: " + NoticeMessage(StatusBar));
            }

            NavigateTo(WorkspacePage.SecureBoot);
            if (SecureBootPage.Visibility != Visibility.Visible || SecureBootResults.Children.Count == 0 ||
                SecureBootIssueHost.Children.Count == 0)
            {
                throw new IOException("Secure Boot page failed.");
            }

            NavigateTo(WorkspacePage.Drivers);
            if (DriversPage.Visibility != Visibility.Visible || DriversResults.Children.Count == 0)
            {
                throw new IOException("UEFI drivers page failed.");
            }

            NavigateTo(WorkspacePage.TurboBoost);
            if (TurboBoostPage.Visibility != Visibility.Visible || TurboBoostResults.Children.Count == 0 ||
                !ReferenceEquals(ShellNavigation.SelectedItem, TurboBoostNavigationItem))
            {
                throw new IOException("TurboBoost Unlock page failed.");
            }

            NavigateTo(WorkspacePage.Personalization);
            if (PersonalizationPage.Visibility != Visibility.Visible || PersonalizationResults.Children.Count == 0 ||
                !ReferenceEquals(ShellNavigation.SelectedItem, PersonalizationNavigationItem))
            {
                throw new IOException("Personalization page failed.");
            }

            NavigateTo(WorkspacePage.Tpm);
            if (TpmNavigationItem.Visibility != Visibility.Collapsed || TpmNavigationItem.IsEnabled ||
                TpmPage.Visibility != Visibility.Collapsed || AnalysisPage.Visibility != Visibility.Visible ||
                !ReferenceEquals(ShellNavigation.SelectedItem, AnalysisNavigationItem))
            {
                throw new IOException("Hidden TPM page became reachable.");
            }

            NavigateTo(WorkspacePage.Save);
            if (SavePage.Visibility != Visibility.Visible || !ReferenceEquals(ShellNavigation.SelectedItem, SaveNavigationItem))
            {
                throw new IOException("Save page failed.");
            }

            // Keep the driver page as the settings return target for the dark-theme regression.
            NavigateTo(WorkspacePage.Drivers);
            NavigateTo(WorkspacePage.Settings);
            if (SettingsPage.Visibility != Visibility.Visible ||
                !ReferenceEquals(ShellNavigation.SelectedItem, ShellNavigation.SettingsItem) || SourcePage.AllowDrop)
            {
                throw new IOException("Settings navigation failed.");
            }

            string initialLanguage = text.Language;
            string languageTarget = LocalizationCatalog.SupportedCultures.First(culture =>
                !string.Equals(culture, initialLanguage, StringComparison.OrdinalIgnoreCase));
            SelectTaggedItem(LanguageComboBox, languageTarget);
            await Task.Delay(UiDesign.LanguageChangeSettleMilliseconds);
            Root.UpdateLayout();
            if (!string.Equals(text.Language, languageTarget, StringComparison.OrdinalIgnoreCase) ||
                SettingsPage.Visibility != Visibility.Visible)
            {
                throw new IOException("Runtime language switching failed.");
            }

            SelectTaggedItem(LanguageComboBox, initialLanguage);
            await Task.Delay(UiDesign.LanguageChangeSettleMilliseconds);
            Root.UpdateLayout();
            if (!string.Equals(text.Language, initialLanguage, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Repeated runtime language switching failed.");
            }

            ThemePreference initialTheme = preferences.Theme;

            // Exercise the UEFI driver page in a forced dark theme. Driver cards are created in code,
            // so this catches regressions where a ThemeResource is accidentally resolved to a Brush snapshot.
            SelectTaggedItem(ThemeComboBox, ThemePreference.Dark.ToString());
            await Task.Delay(UiDesign.ThemeChangeSettleMilliseconds);
            Root.UpdateLayout();
            if (preferences.Theme != ThemePreference.Dark || Root.RequestedTheme != ElementTheme.Dark)
            {
                throw new IOException("Runtime dark-theme switching failed.");
            }

            CloseSettings();
            await Task.Delay(UiDesign.ThemeChangeSettleMilliseconds);
            Root.UpdateLayout();
            if (SettingsPage.Visibility != Visibility.Collapsed || DriversPage.Visibility != Visibility.Visible ||
                !ReferenceEquals(ShellNavigation.SelectedItem, DriversNavigationItem) || Root.ActualTheme != ElementTheme.Dark)
            {
                throw new IOException("UEFI drivers page did not preserve the dark theme.");
            }
            string driversDark = Path.Combine(smokeDirectory, "drivers-dark.png");
            File.WriteAllBytes(driversDark, []);
            await UiSmoke.CaptureAsync(Root, driversDark);

            NavigateTo(WorkspacePage.Settings);
            SelectTaggedItem(ThemeComboBox, initialTheme.ToString());
            await Task.Delay(UiDesign.ThemeChangeSettleMilliseconds);
            Root.UpdateLayout();
            if (preferences.Theme != initialTheme || Root.RequestedTheme != ElementThemeFor(initialTheme))
            {
                throw new IOException("Runtime theme restoration failed.");
            }

            CloseSettings();
            if (SettingsPage.Visibility != Visibility.Collapsed || DriversPage.Visibility != Visibility.Visible ||
                !ReferenceEquals(ShellNavigation.SelectedItem, DriversNavigationItem))
            {
                throw new IOException("Repeated settings invocation did not restore the previous page.");
            }

            NavigateTo(WorkspacePage.Source);
            if (!SourcePage.AllowDrop)
            {
                throw new IOException("Source page did not enable file drop.");
            }
            ResetActiveImageState();
            if (AnalysisNavigationItem.Visibility != Visibility.Collapsed ||
                SecureBootNavigationItem.Visibility != Visibility.Collapsed ||
                DriversNavigationItem.Visibility != Visibility.Collapsed ||
                TurboBoostNavigationItem.Visibility != Visibility.Collapsed ||
                PersonalizationNavigationItem.Visibility != Visibility.Collapsed ||
                TpmNavigationItem.Visibility != Visibility.Collapsed ||
                SaveNavigationItem.Visibility != Visibility.Collapsed ||
                CurrentFileLabel.Visibility != Visibility.Collapsed ||
                AnalysisPage.Visibility == Visibility.Visible || SecureBootPage.Visibility == Visibility.Visible ||
                DriversPage.Visibility == Visibility.Visible || TurboBoostPage.Visibility == Visibility.Visible ||
                PersonalizationPage.Visibility == Visibility.Visible || TpmPage.Visibility == Visibility.Visible ||
                SavePage.Visibility == Visibility.Visible)
            {
                throw new IOException("Image reset state failed.");
            }

            await LoadFileAsync(smokeImage);
            NavigateTo(WorkspacePage.Source);
            ResizeWindow(UiDesign.SmokeNarrowWindowSize);
            await Task.Delay(UiDesign.AdaptiveLayoutSettleMilliseconds);
            Root.UpdateLayout();
            if (SourcePage.Visibility != Visibility.Visible || AnalysisPage.Visibility != Visibility.Collapsed ||
                ShellNavigation.DisplayMode != NavigationViewDisplayMode.Minimal ||
                CurrentFileLabel.Visibility != Visibility.Collapsed)
            {
                throw new IOException("Responsive source navigation failed.");
            }

            NavigateTo(WorkspacePage.Analysis);
            if (AnalysisPage.Visibility != Visibility.Visible || SourcePage.Visibility != Visibility.Collapsed ||
                CurrentImageContextLabel.Visibility != Visibility.Visible)
            {
                throw new IOException("Responsive analysis navigation failed.");
            }

            ResizeWindow(UiDesign.DefaultWindowSize);
            await Task.Delay(UiDesign.AdaptiveLayoutSettleMilliseconds);
            Root.UpdateLayout();
            if (ShellNavigation.DisplayMode != NavigationViewDisplayMode.Expanded ||
                CurrentFileLabel.Visibility != Visibility.Visible || CurrentImageContextLabel.Visibility != Visibility.Collapsed)
            {
                throw new IOException("Expanded navigation did not restore the current file label.");
            }
            ContentScroller.ChangeView(null, UiDesign.SmokeScrollOffset, null, true);
            string loaded = Path.Combine(smokeDirectory, "loaded.png");
            File.WriteAllBytes(loaded, []);
            await UiSmoke.CaptureAsync(Root, loaded);
            File.WriteAllText(Path.Combine(smokeDirectory, "result.txt"), "PASS " + text.Language + " " + Root.ActualTheme);
        }
        catch (Exception error)
        {
            AppLog.Error(error);
            File.WriteAllText(Path.Combine(smokeDirectory, "result.txt"), "FAIL " + error);
            Environment.ExitCode = 1;
        }
        finally
        {
            Close();
        }
    }

    private void AppTitleBarPaneToggleRequested(TitleBar sender, object args)
    {
        _ = sender;
        _ = args;
        if (operation is not null)
        {
            return;
        }
        ShellNavigation.IsPaneOpen = !ShellNavigation.IsPaneOpen;
    }

    private void ShellNavigationDisplayModeChanged(NavigationView sender, NavigationViewDisplayModeChangedEventArgs args)
    {
        _ = sender;
        _ = args;
        UpdateCurrentFileLabelVisibility();
    }

    private void ShellNavigationSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (navigationSync)
        {
            return;
        }
        if (operation is not null)
        {
            SynchronizeNavigationSelection();
            return;
        }

        WorkspacePage page;
        if (args.IsSettingsSelected)
        {
            page = WorkspacePage.Settings;
        }
        else if (ReferenceEquals(args.SelectedItem, AnalysisNavigationItem))
        {
            page = WorkspacePage.Analysis;
        }
        else if (ReferenceEquals(args.SelectedItem, SecureBootNavigationItem))
        {
            page = WorkspacePage.SecureBoot;
        }
        else if (ReferenceEquals(args.SelectedItem, DriversNavigationItem))
        {
            page = WorkspacePage.Drivers;
        }
        else if (ReferenceEquals(args.SelectedItem, TurboBoostNavigationItem))
        {
            page = WorkspacePage.TurboBoost;
        }
        else if (ReferenceEquals(args.SelectedItem, PersonalizationNavigationItem))
        {
            page = WorkspacePage.Personalization;
        }
        else if (ReferenceEquals(args.SelectedItem, TpmNavigationItem))
        {
            page = WorkspacePage.Tpm;
        }
        else if (ReferenceEquals(args.SelectedItem, SaveNavigationItem))
        {
            page = WorkspacePage.Save;
        }
        else
        {
            page = WorkspacePage.Source;
        }
        NavigateTo(page);
    }

    private void ShellNavigationItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        _ = sender;
        if (operation is not null || navigationSync || !args.IsSettingsInvoked || currentPage != WorkspacePage.Settings)
        {
            return;
        }

        CloseSettings();
    }

    private void CloseSettings() => NavigateTo(pageBeforeSettings);

    private void ContentScrollerSizeChanged(object sender, SizeChangedEventArgs args)
    {
        _ = sender;
        ApplyResponsiveLayout(args.NewSize.Width);
    }

    private void ApplyResponsiveLayout(double viewportWidth)
    {
        if (!double.IsFinite(viewportWidth) || viewportWidth <= 0)
        {
            return;
        }

        ResponsiveLayoutState layout = ResponsiveLayout.Calculate(
            viewportWidth,
            UiResources.Get<double>(UiResourceKeys.LayoutContentMaxWidth),
            UiResources.Get<double>(UiResourceKeys.LayoutMediumBreakpoint),
            UiResources.Get<double>(UiResourceKeys.LayoutActionCardsTwoColumnMinWidth));
        ContentPanel.Width = layout.ContentWidth;
        StatusHost.Width = layout.ContentWidth;

        ContentPanel.Padding = UiResources.Get<Thickness>(layout.UseTwoColumnActions
            ? UiResourceKeys.LayoutContentPaddingWide
            : layout.UseNarrowPadding
                ? UiResourceKeys.LayoutContentPaddingNarrow
                : UiResourceKeys.LayoutContentPaddingMedium);
        StatusHost.Padding = UiResources.Get<Thickness>(layout.UseTwoColumnActions
            ? UiResourceKeys.LayoutStatusPaddingWide
            : layout.UseNarrowPadding
                ? UiResourceKeys.LayoutStatusPaddingNarrow
                : UiResourceKeys.LayoutStatusPaddingMedium);

        ActionCards.ColumnSpacing = layout.UseTwoColumnActions
            ? UiResources.Get<double>(UiResourceKeys.LayoutWideActionSpacing)
            : 0;
        ActionCards.RowSpacing = layout.UseTwoColumnActions
            ? 0
            : UiResources.Get<double>(UiResourceKeys.LayoutStackedActionSpacing);
        PrimaryActionColumn.Width = new GridLength(1, GridUnitType.Star);
        SecondaryActionColumn.Width = layout.UseTwoColumnActions
            ? new GridLength(1, GridUnitType.Star)
            : new GridLength(0);
        Grid.SetRow(SystemCard, layout.UseTwoColumnActions ? 0 : 1);
        Grid.SetColumn(SystemCard, layout.UseTwoColumnActions ? 1 : 0);
    }

    private void ShowSecureBootPage(object sender, RoutedEventArgs e) => NavigateTo(WorkspacePage.SecureBoot);

    private void ShowDriversPage(object sender, RoutedEventArgs e) => NavigateTo(WorkspacePage.Drivers);

    private void ShowTurboBoostPage(object sender, RoutedEventArgs e) => NavigateTo(WorkspacePage.TurboBoost);

    private void NavigateTo(WorkspacePage page)
    {
        if (page == WorkspacePage.Tpm && !TpmUiEnabled)
        {
            page = activeImage is null ? WorkspacePage.Source : WorkspacePage.Analysis;
        }

        if ((page is WorkspacePage.Analysis or WorkspacePage.SecureBoot or WorkspacePage.Drivers or
            WorkspacePage.TurboBoost or WorkspacePage.Personalization or WorkspacePage.Tpm or WorkspacePage.Save) && activeImage is null)
        {
            page = WorkspacePage.Source;
        }

        if (page == WorkspacePage.Settings && currentPage != WorkspacePage.Settings)
        {
            pageBeforeSettings = currentPage;
        }

        if (currentPage != page)
        {
            pageScrollOffsets[currentPage] = ContentScroller.VerticalOffset;
        }

        currentPage = page;
        SourcePage.Visibility = page == WorkspacePage.Source ? Visibility.Visible : Visibility.Collapsed;
        AnalysisPage.Visibility = page == WorkspacePage.Analysis ? Visibility.Visible : Visibility.Collapsed;
        SecureBootPage.Visibility = page == WorkspacePage.SecureBoot ? Visibility.Visible : Visibility.Collapsed;
        DriversPage.Visibility = page == WorkspacePage.Drivers ? Visibility.Visible : Visibility.Collapsed;
        TurboBoostPage.Visibility = page == WorkspacePage.TurboBoost ? Visibility.Visible : Visibility.Collapsed;
        PersonalizationPage.Visibility = page == WorkspacePage.Personalization ? Visibility.Visible : Visibility.Collapsed;
        TpmPage.Visibility = page == WorkspacePage.Tpm ? Visibility.Visible : Visibility.Collapsed;
        SavePage.Visibility = page == WorkspacePage.Save ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = page == WorkspacePage.Settings ? Visibility.Visible : Visibility.Collapsed;

        SynchronizeNavigationSelection();

        double targetOffset = pageScrollOffsets.TryGetValue(page, out double savedOffset) ? savedOffset : 0d;
        ContentScroller.ChangeView(null, targetOffset, null, true);
        UpdateCurrentFileLabelVisibility();
        UpdateFileDropAvailability();
    }

    private void SynchronizeNavigationSelection()
    {
        navigationSync = true;
        try
        {
            ShellNavigation.SelectedItem = currentPage switch
            {
                WorkspacePage.Analysis => AnalysisNavigationItem,
                WorkspacePage.SecureBoot => SecureBootNavigationItem,
                WorkspacePage.Drivers => DriversNavigationItem,
                WorkspacePage.TurboBoost => TurboBoostNavigationItem,
                WorkspacePage.Personalization => PersonalizationNavigationItem,
                WorkspacePage.Tpm => TpmNavigationItem,
                WorkspacePage.Save => SaveNavigationItem,
                WorkspacePage.Settings => ShellNavigation.SettingsItem,
                _ => SourceNavigationItem
            };
        }
        finally
        {
            navigationSync = false;
        }
    }

    private void UpdateCurrentFileLabelVisibility()
    {
        bool hasImage = activeImage is not null;
        bool expanded = ShellNavigation.DisplayMode == NavigationViewDisplayMode.Expanded;
        CurrentFileLabel.Visibility = hasImage && expanded
            ? Visibility.Visible
            : Visibility.Collapsed;
        CurrentImageContextLabel.Visibility = hasImage && !expanded &&
            currentPage is not WorkspacePage.Source and not WorkspacePage.Settings
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void UpdateFileDropAvailability()
    {
        bool enabled = currentPage == WorkspacePage.Source && operation is null;
        SourcePage.AllowDrop = enabled;
        elevatedFileDropTarget?.SetEnabled(enabled);
    }

    private void ApplyImageAvailabilityState()
    {
        bool available = activeImage is not null && activeSource is not null;
        Visibility imageNavigationVisibility = available ? Visibility.Visible : Visibility.Collapsed;

        AnalysisNavigationItem.Visibility = imageNavigationVisibility;
        SecureBootNavigationItem.Visibility = imageNavigationVisibility;
        DriversNavigationItem.Visibility = imageNavigationVisibility;
        TurboBoostNavigationItem.Visibility = imageNavigationVisibility;
        PersonalizationNavigationItem.Visibility = imageNavigationVisibility;
        TpmNavigationItem.Visibility = TpmUiEnabled ? imageNavigationVisibility : Visibility.Collapsed;
        SaveNavigationItem.Visibility = imageNavigationVisibility;
        EmptyPanel.Visibility = available ? Visibility.Collapsed : Visibility.Visible;
        UpdateInteractionState();

        if (activeImage is BiosImage image && activeSource is ImageSourceKind source)
        {
            string displayName = ImageDisplayName(image, source);
            string tooltip = source == ImageSourceKind.File ? ActiveFileTooltip(image) : displayName;
            CurrentFileLabel.Text = displayName;
            CurrentImageContextLabel.Text = displayName;
            UpdateCurrentFileLabelVisibility();
            ToolTipService.SetToolTip(CurrentFileLabel, tooltip);
            ToolTipService.SetToolTip(CurrentImageContextLabel, tooltip);
        }
        else
        {
            CurrentFileLabel.Text = string.Empty;
            CurrentImageContextLabel.Text = string.Empty;
            CurrentFileLabel.Visibility = Visibility.Collapsed;
            CurrentImageContextLabel.Visibility = Visibility.Collapsed;
            ToolTipService.SetToolTip(CurrentFileLabel, null);
            ToolTipService.SetToolTip(CurrentImageContextLabel, null);
        }
    }

    private void UpdateInteractionState()
    {
        bool idle = operation is null;
        bool imageAvailable = activeImage is not null && activeSource is not null;

        ContentPanel.IsEnabled = idle;
        SourceNavigationItem.IsEnabled = idle;
        AnalysisNavigationItem.IsEnabled = idle && imageAvailable;
        SecureBootNavigationItem.IsEnabled = idle && imageAvailable;
        DriversNavigationItem.IsEnabled = idle && imageAvailable;
        TurboBoostNavigationItem.IsEnabled = idle && imageAvailable;
        PersonalizationNavigationItem.IsEnabled = idle && imageAvailable;
        TpmNavigationItem.IsEnabled = TpmUiEnabled && idle && imageAvailable;
        SaveNavigationItem.IsEnabled = idle && imageAvailable;
        if (ShellNavigation.SettingsItem is NavigationViewItem settingsItem)
        {
            settingsItem.IsEnabled = idle;
        }

        OpenButton.IsEnabled = idle;
        ReadButton.IsEnabled = idle;
        CancelButton.IsEnabled = !idle;
    }

    private void ResetActiveImageState()
    {
        activeImage = null;
        activeSource = null;
        activeDumpRegions = [];
        activeInputPath = null;
        activePackageEntry = null;
        pageScrollOffsets.Clear();
        Results.Children.Clear();
        SecureBootResults.Children.Clear();
        DriversResults.Children.Clear();
        TurboBoostResults.Children.Clear();
        PersonalizationResults.Children.Clear();
        TpmResults.Children.Clear();
        SaveResults.Children.Clear();
        SecureBootIssueHost.Children.Clear();
        SecureBootNoticeBar.IsOpen = false;
        TurboBoostNoticeBar.IsOpen = false;
        PersonalizationNoticeBar.IsOpen = false;
        NavigateTo(WorkspacePage.Source);
        ApplyImageAvailabilityState();
        StatusBar.IsOpen = false;
        StatusHost.Visibility = Visibility.Collapsed;
    }

    internal async Task NotifyAlreadyRunningAsync()
    {
        await EnqueueOnUiThreadAsync(async () =>
        {
            BringToForeground();
            if (alreadyRunningDialogOpen)
            {
                return;
            }

            alreadyRunningDialogOpen = true;
            try
            {
                var dialog = new ContentDialog
                {
                    Title = string.Format(text.Culture, text["AlreadyRunningTitleFormat"], ApplicationIdentity.DisplayName),
                    Content = new TextBlock
                    {
                        Text = text["AlreadyRunningMessage"],
                        TextWrapping = TextWrapping.Wrap,
                        IsTextSelectionEnabled = true
                    },
                    CloseButtonText = text["Close"],
                    DefaultButton = ContentDialogButton.Close
                };
                await ShowDialogAsync(dialog);
            }
            finally
            {
                alreadyRunningDialogOpen = false;
            }
        });
    }

    private void ResizeWindow(SizeInt32 logicalSize)
    {
        double scale = Root.XamlRoot?.RasterizationScale ?? 0d;
        if (!double.IsFinite(scale) || scale <= 0d)
        {
            nint windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            scale = UiDesign.GetRasterizationScale(windowHandle);
        }

        AppWindow.Resize(UiDesign.GetWindowSize(AppWindow.Id, logicalSize, scale));
    }

    private void BringToForeground()
    {
        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        Activate();
        ForegroundActivationInterop.RestoreAndRequestForeground(hwnd);
    }

    private async Task<ContentDialogResult> ShowDialogAsync(ContentDialog dialog)
    {
        if (!DispatcherQueue.HasThreadAccess)
        {
            return await EnqueueOnUiThreadAsync(() => ShowDialogAsync(dialog));
        }

        await dialogGate.WaitAsync();
        try
        {
            if (Root.XamlRoot is null)
            {
                await WaitForRootLoadedAsync();
            }
            dialog.XamlRoot = Root.XamlRoot;
            dialog.RequestedTheme = Root.ActualTheme;
            return await dialog.ShowAsync();
        }
        finally
        {
            dialogGate.Release();
        }
    }


    private Task EnqueueOnUiThreadAsync(Func<Task> action) =>
        EnqueueOnUiThreadAsync(async () =>
        {
            await action();
            return true;
        });

    private Task<T> EnqueueOnUiThreadAsync<T>(Func<Task<T>> action)
    {
        if (DispatcherQueue.HasThreadAccess)
        {
            return action();
        }

        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!DispatcherQueue.TryEnqueue(() => _ = ExecuteEnqueuedActionAsync(action, completion)))
        {
            completion.TrySetException(new InvalidOperationException(OperationError.UiDispatcherUnavailable));
        }
        return completion.Task;
    }

    private static async Task ExecuteEnqueuedActionAsync<T>(Func<Task<T>> action, TaskCompletionSource<T> completion)
    {
        try
        {
            completion.TrySetResult(await action());
        }
        catch (Exception error)
        {
            completion.TrySetException(error);
        }
    }

    private Task WaitForRootLoadedAsync()
    {
        if (Root.XamlRoot is not null)
        {
            return Task.CompletedTask;
        }

        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        RoutedEventHandler? loaded = null;
        loaded = (_, _) =>
        {
            Root.Loaded -= loaded;
            completion.TrySetResult(true);
        };
        Root.Loaded += loaded;
        return completion.Task;
    }

    private IReadOnlyList<SystemFileOpenDialog.Filter> OpenFileFilters() =>
    [
        new(
            text["FileTypeAllSupported"],
            FirmwarePackageLoader.SupportedInputExtensions),
        new(
            text["FileTypeBiosImages"],
            BiosImageLoader.SupportedFileExtensions),
        new(
            text["FileTypeArchives"],
            FirmwarePackageLoader.SupportedPackageExtensions
                .Where(extension => !extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                .ToArray()),
        new(
            text["FileTypeManufacturerPackages"],
            [".exe"])
    ];

    private void ApplyWindowIcon()
    {
        try
        {
            AppWindow.SetIcon(MaterializeWindowIcon());
        }
        catch (Exception error)
        {
            // The executable still carries ApplicationIcon metadata. A cosmetic icon refresh must never break startup/theme changes.
            AppLog.Error(error);
        }
    }

    private string MaterializeWindowIcon()
    {
        if (materializedWindowIconPath is not null)
        {
            return materializedWindowIconPath;
        }

        string iconPath = temporary.WindowIconPath;
        using Stream resource = typeof(MainWindow).Assembly.GetManifestResourceStream("XeonV3Control.window-icon")
            ?? throw new InvalidDataException("Embedded application icon resource is missing.");
        if (resource.CanSeek && resource.Length <= 0)
        {
            throw new InvalidDataException("Embedded application icon resource is empty.");
        }

        try
        {
            using (var output = new FileStream(iconPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                       bufferSize: 16 * 1024, FileOptions.WriteThrough))
            {
                resource.CopyTo(output);
                output.Flush(flushToDisk: true);
            }
        }
        catch
        {
            try
            {
                File.Delete(iconPath);
            }
            catch (Exception cleanupError) when (cleanupError is IOException or UnauthorizedAccessException)
            {
                AppLog.Error(cleanupError);
            }
            throw;
        }

        materializedWindowIconPath = iconPath;
        return iconPath;
    }

    private void ConfigureCaptionButtons()
    {
        if (!Microsoft.UI.Windowing.AppWindowTitleBar.IsCustomizationSupported())
        {
            return;
        }

        AppWindow.TitleBar.ButtonBackgroundColor = Colors.Transparent;
        AppWindow.TitleBar.ButtonInactiveBackgroundColor = Colors.Transparent;
        // Keep foreground colors under Windows control so High Contrast and system accessibility colors remain authoritative.
        AppWindow.TitleBar.ButtonForegroundColor = null;
        AppWindow.TitleBar.ButtonInactiveForegroundColor = null;
    }

    private async void OpenFile(object sender, RoutedEventArgs e)
    {
        if (operation is not null)
        {
            return;
        }
        try
        {
            nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            string? path = SystemFileOpenDialog.PickSingleFile(hwnd, OpenFileFilters());
            if (path is not null)
            {
                await LoadFileAsync(path);
            }
        }
        catch (Exception error)
        {
            ShowError(error);
        }
    }

    private void SourceDragOver(object sender, DragEventArgs e)
    {
        if (currentPage != WorkspacePage.Source || operation is not null || !e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            e.AcceptedOperation = DataPackageOperation.None;
            return;
        }

        e.AcceptedOperation = DataPackageOperation.Copy;
        e.DragUIOverride.Caption = text["DropBiosHere"];
        e.DragUIOverride.IsCaptionVisible = true;
        e.Handled = true;
    }

    private async void SourceDrop(object sender, DragEventArgs e)
    {
        if (currentPage != WorkspacePage.Source || operation is not null)
        {
            return;
        }

        e.Handled = true;
        var deferral = e.GetDeferral();
        try
        {
            IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();
            IReadOnlyList<string> paths = items.Count == 1 && items[0] is StorageFile file && !string.IsNullOrWhiteSpace(file.Path)
                ? [file.Path]
                : [];
            await ProcessDroppedFilesAsync(paths);
        }
        catch (Exception error)
        {
            ShowError(error);
        }
        finally
        {
            deferral.Complete();
        }
    }

    private void InitializeElevatedFileDrop()
    {
        if (elevatedFileDropTarget is not null)
        {
            return;
        }

        try
        {
            nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            elevatedFileDropTarget = new ElevatedFileDropTarget(
                hwnd,
                IsSourcePageDropPoint,
                paths => _ = ObserveDetachedAsync(ProcessDroppedFilesAsync(paths)));
            UpdateFileDropAvailability();
        }
        catch (Exception error)
        {
            // The regular WinUI drag-and-drop path remains available for equal-integrity sources.
            AppLog.Error(error);
        }
    }


    private bool IsSourcePageDropPoint(int x, int y)
    {
        if (currentPage != WorkspacePage.Source || SourcePage.Visibility != Visibility.Visible || !SourcePage.AllowDrop)
        {
            return false;
        }

        double scale = Root.XamlRoot?.RasterizationScale ?? 0d;
        if (!double.IsFinite(scale) || scale <= 0)
        {
            return false;
        }

        Windows.Foundation.Point sourceOrigin = SourcePage.TransformToVisual(Root)
            .TransformPoint(new Windows.Foundation.Point());
        Windows.Foundation.Point viewportOrigin = ContentScroller.TransformToVisual(Root)
            .TransformPoint(new Windows.Foundation.Point());

        double leftDip = Math.Max(sourceOrigin.X, viewportOrigin.X);
        double topDip = Math.Max(sourceOrigin.Y, viewportOrigin.Y);
        double rightDip = Math.Min(sourceOrigin.X + SourcePage.ActualWidth,
            viewportOrigin.X + ContentScroller.ActualWidth);
        double bottomDip = Math.Min(sourceOrigin.Y + SourcePage.ActualHeight,
            viewportOrigin.Y + ContentScroller.ActualHeight);
        if (rightDip <= leftDip || bottomDip <= topDip)
        {
            return false;
        }

        double left = leftDip * scale;
        double top = topDip * scale;
        double right = rightDip * scale;
        double bottom = bottomDip * scale;
        return x >= left && y >= top && x < right && y < bottom;
    }

    private static async Task ObserveDetachedAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (Exception error)
        {
            AppLog.Error(error);
        }
    }

    private async Task ProcessDroppedFilesAsync(IReadOnlyList<string> paths)
    {
        await EnqueueOnUiThreadAsync(async () =>
        {
            if (operation is not null || currentPage != WorkspacePage.Source)
            {
                return;
            }

            try
            {
                if (paths.Count != 1 || string.IsNullOrWhiteSpace(paths[0]))
                {
                    throw new InvalidDataException(OperationError.DropSingleFile);
                }

                await LoadFileAsync(paths[0]);
            }
            catch (Exception error)
            {
                ShowError(error);
            }
        });
    }

    private async Task LoadFileAsync(string path)
    {
        if (operation is not null)
        {
            return;
        }
        await RunOperation(async token =>
        {
            if (!FirmwarePackageLoader.HasSupportedInputExtension(path))
            {
                throw new InvalidDataException(OperationError.UnsupportedFileType);
            }

            try
            {
                if (FirmwarePackageLoader.IsPackagePath(path))
                {
                    FirmwarePackageInspection package = await FirmwarePackageLoader.InspectAsync(path, token);
                    if (package.Candidates.Count == 0)
                    {
                        throw new InvalidDataException(OperationError.PackageNoBiosImage);
                    }

                    FirmwarePackageCandidate? selected = await SelectPackageCandidateAsync(package.Candidates);
                    if (selected is null)
                    {
                        return;
                    }

                    BiosImage image = await MaterializePackageCandidateAsync(selected, token);
                    ShowImage(
                        image,
                        ImageSourceKind.File,
                        displayPath: Path.GetFullPath(path),
                        packageEntry: selected.LogicalPath);
                    return;
                }

                BiosImage rawImage = await BiosImageLoader.LoadValidatedAsync(path, token);
                ShowImage(rawImage, ImageSourceKind.File, displayPath: Path.GetFullPath(path));
            }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
            {
                throw new IOException(OperationError.ImageUnavailable, error);
            }
        }, UiOperationKind.Loading);
    }

    private async Task<FirmwarePackageCandidate?> SelectPackageCandidateAsync(
        IReadOnlyList<FirmwarePackageCandidate> candidates)
    {
        if (candidates.Count == 1)
        {
            return candidates[0];
        }

        string[] labels = candidates.Select(candidate => string.Format(
            text.Culture,
            text["PackageCandidateFormat"],
            candidate.LogicalPath,
            candidate.Data.Length / (double)UiDesign.BytesPerMebibyte,
            text[candidate.Image.Kind.ToString()])).ToArray();
        var selector = new ComboBox
        {
            ItemsSource = labels,
            SelectedIndex = 0,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var content = new StackPanel
        {
            Spacing = UiDesign.DialogContentSpacing
        };
        content.Children.Add(new TextBlock
        {
            Text = text["PackageSelectionHint"],
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true
        });
        content.Children.Add(selector);

        var dialog = new ContentDialog
        {
            Title = text["PackageSelectionTitle"],
            Content = content,
            PrimaryButtonText = text["Open"],
            CloseButtonText = text["Cancel"],
            DefaultButton = ContentDialogButton.Primary
        };
        ContentDialogResult result = await ShowDialogAsync(dialog);
        return result == ContentDialogResult.Primary && selector.SelectedIndex >= 0
            ? candidates[selector.SelectedIndex]
            : null;
    }

    private async Task<BiosImage> MaterializePackageCandidateAsync(
        FirmwarePackageCandidate candidate,
        CancellationToken cancellationToken)
    {
        string target = temporary.NewBiosPath(TemporaryBiosArtifact.PackageImport);
        try
        {
            await using (var output = new FileStream(target, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.WriteThrough
            }))
            {
                await output.WriteAsync(candidate.Data, cancellationToken);
                await output.FlushAsync(cancellationToken);
            }

            BiosImage image = await BiosImageLoader.LoadValidatedAsync(target, cancellationToken);
            if (!string.Equals(image.Sha256, candidate.Image.Sha256, StringComparison.Ordinal))
            {
                throw new IOException(OperationError.OutputVerification);
            }
            return image;
        }
        catch
        {
            try
            {
                File.Delete(target);
            }
            catch (Exception cleanupError) when (cleanupError is IOException or UnauthorizedAccessException)
            {
                AppLog.Error(cleanupError);
            }
            throw;
        }
    }

    private async void ReadSystem(object sender, RoutedEventArgs e)
    {
        if (operation is not null)
        {
            return;
        }
        try
        {
            ResetActiveImageState();
            await RunOperation(async token =>
            {
                string destination = temporary.NewBiosPath(TemporaryBiosArtifact.SystemDump);
                var reporter = new Progress<double>(value => Progress.Value = value * UiDesign.ProgressPercentageScale);
                VerifiedFirmwareDump dump = await Task.Run(async () =>
                {
                    using var gate = new Semaphore(1, 1, ApplicationIdentity.SpiReadSemaphoreName);
                    if (!gate.WaitOne(0))
                    {
                        throw new IOException(OperationError.SpiBusy);
                    }
                    try
                    {
                        using var driver = ThrottleStopDriver.Open(cancellationToken: token);
                        return await VerifiedDump.CreateAsync(new X99SpiReader(driver), destination, reporter, token);
                    }
                    finally
                    {
                        gate.Release();
                    }
                }, token);
                ImageSourceKind source = dump.Scope switch
                {
                    FirmwareReadScope.FullSpi => ImageSourceKind.FullSpi,
                    FirmwareReadScope.PartialSpi => ImageSourceKind.PartialSpi,
                    _ => ImageSourceKind.BiosRegion
                };
                ShowImage(dump.Image, source, dumpRegions: dump.Regions);
            }, UiOperationKind.Dumping);
        }
        catch (Exception error)
        {
            ShowError(error);
        }
    }

    private async Task RunOperation(Func<CancellationToken, Task> action, UiOperationKind operationKind)
    {
        if (operation is not null)
        {
            return;
        }

        using var currentOperation = new CancellationTokenSource();
        operation = currentOperation;
        currentOperationKind = operationKind;
        UpdateInteractionState();
        UpdateFileDropAvailability();
        StatusHost.Visibility = Visibility.Visible;
        BusyPanel.Visibility = Visibility.Visible;
        Progress.IsIndeterminate = operationKind is not (UiOperationKind.Dumping or UiOperationKind.FlashingImage);
        Progress.Value = 0;
        BusyLabel.Text = text[operationKind.ToString()];
        StatusBar.IsOpen = false;

        try
        {
            // Return control to the dispatcher once so the busy indicator can be composed
            // before any operation-specific work begins. CPU-heavy mutation paths then run off the UI thread.
            await Task.Yield();
            currentOperation.Token.ThrowIfCancellationRequested();
            await action(currentOperation.Token);
        }
        catch (OperationCanceledException) when (currentOperation.IsCancellationRequested)
        {
            ShowOperationNotice(operationKind, string.Empty, text["Cancelled"], InfoBarSeverity.Informational);
        }
        catch (Exception error)
        {
            ShowOperationError(operationKind, error);
        }
        finally
        {
            if (ReferenceEquals(operation, currentOperation))
            {
                operation = null;
            }
            currentOperationKind = null;
            UpdateInteractionState();
            UpdateFileDropAvailability();
            BusyPanel.Visibility = Visibility.Collapsed;
            if (!StatusBar.IsOpen)
            {
                StatusHost.Visibility = Visibility.Collapsed;
            }
            if (closing)
            {
                Close();
            }
        }
    }

    private void CancelOperation(object sender, RoutedEventArgs e) => operation?.Cancel();

    private void StatusBarClosed(InfoBar sender, InfoBarClosedEventArgs args)
    {
        _ = sender;
        _ = args;
        if (operation is null)
        {
            StatusHost.Visibility = Visibility.Collapsed;
        }
    }

    private void ShowError(Exception error)
    {
        AppLog.ReportError(error, "UI error");
        ShowStatus(text["Error"], LocalizedErrorMessage(error), InfoBarSeverity.Error);
    }

    private void ShowOperationError(UiOperationKind operationKind, Exception error)
    {
        AppLog.ReportError(error, "Operation: " + operationKind);
        ShowOperationNotice(operationKind, text["Error"], LocalizedErrorMessage(error), InfoBarSeverity.Error);
    }

    private void ShowOperationNotice(
        UiOperationKind operationKind,
        string title,
        string message,
        InfoBarSeverity severity)
    {
        if (operationKind == UiOperationKind.UpdatingCertificates)
        {
            SetNotice(SecureBootNoticeBar, title, message, severity);
            return;
        }
        if (operationKind is UiOperationKind.RemovingCpuPatch or
            UiOperationKind.RemovingForeignUnlock)
        {
            SetNotice(TurboBoostNoticeBar, title, message, severity);
            return;
        }
        if (operationKind is UiOperationKind.UpdatingBootLogo or UiOperationKind.UpdatingBeeper)
        {
            SetNotice(PersonalizationNoticeBar, title, message, severity);
            return;
        }
        if (operationKind == UiOperationKind.UpdatingTpmDebugDriver)
        {
            SetNotice(TpmNoticeBar, title, message, severity);
            return;
        }
        if (operationKind is UiOperationKind.SavingImage or UiOperationKind.FlashingImage)
        {
            SetNotice(SaveNoticeBar, title, message, severity);
            return;
        }

        ShowStatus(title, message, severity);
    }

    private string LocalizedErrorMessage(Exception error) =>
        error is Win32Exception win32 && WindowsErrorCodes.IsDriverLoadBlocked(win32.NativeErrorCode)
            ? text["DriverBlocked"]
            : text.Keys.Contains(error.Message)
                ? text[error.Message]
                : error is Win32Exception
                    ? error.Message
                    : text["UnexpectedError"];

    private void ShowStatus(string title, string message, InfoBarSeverity severity)
    {
        SetNotice(StatusBar, title, message, severity);
        StatusHost.Visibility = Visibility.Visible;
    }

    private void ShowImage(
        BiosImage image,
        ImageSourceKind source,
        WorkspacePage destination = WorkspacePage.Analysis,
        IReadOnlyList<FirmwareRegionReadStatus>? dumpRegions = null,
        string? displayPath = null,
        string? packageEntry = null)
    {
        IReadOnlyList<FirmwareRegionReadStatus> previousDumpRegions = activeDumpRegions;
        string? previousInputPath = activeInputPath;
        string? previousPackageEntry = activePackageEntry;

        activeImage = image;
        activeSource = source;
        activeDumpRegions = source == ImageSourceKind.UpdatedImage
            ? previousDumpRegions
            : dumpRegions?.ToArray() ?? [];
        activeInputPath = source switch
        {
            ImageSourceKind.File => displayPath ?? image.FilePath,
            ImageSourceKind.UpdatedImage => previousInputPath,
            _ => null
        };
        activePackageEntry = source switch
        {
            ImageSourceKind.File => packageEntry,
            ImageSourceKind.UpdatedImage => previousPackageEntry,
            _ => null
        };
        pageScrollOffsets.Clear();
        ContentScroller.ChangeView(null, 0d, null, true);
        RenderActiveImageViews();
        ApplyImageAvailabilityState();
        NavigateTo(destination);
        if (destination == WorkspacePage.Analysis)
        {
            AnimateResults();
        }
        StatusBar.IsOpen = false;
        StatusHost.Visibility = Visibility.Collapsed;
    }

    private void AddFirmwareVolumePager(StackPanel host, IReadOnlyList<FirmwareVolume> volumes)
    {
        int shown = Math.Min(UiDesign.MaximumDisplayedFirmwareVolumes, volumes.Count);
        AddFirmwareVolumeRows(host, volumes, 0, shown);
        if (shown >= volumes.Count)
        {
            return;
        }

        int nextInsertionIndex = host.Children.Count;
        var progress = Label(string.Format(
            text.Culture,
            text["FirmwareVolumeDisplayProgress"],
            shown,
            volumes.Count));
        progress.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutSecondaryTextOpacity);
        host.Children.Add(progress);

        var more = new Button
        {
            Content = text["ShowMore"],
            HorizontalAlignment = HorizontalAlignment.Left
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(more, text["ShowMoreFirmwareVolumes"]);
        more.Click += (_, _) =>
        {
            int remaining = volumes.Count - shown;
            int pageSize = Math.Min(UiDesign.MaximumDisplayedFirmwareVolumes, remaining);
            AddFirmwareVolumeRows(host, volumes, shown, pageSize, insertionIndex: nextInsertionIndex);
            shown += pageSize;
            nextInsertionIndex += pageSize;
            progress.Text = string.Format(
                text.Culture,
                text["FirmwareVolumeDisplayProgress"],
                shown,
                volumes.Count);
            if (shown >= volumes.Count)
            {
                more.Visibility = Visibility.Collapsed;
            }
        };
        host.Children.Add(more);
    }

    private void AddFirmwareVolumeRows(
        StackPanel host,
        IReadOnlyList<FirmwareVolume> volumes,
        int start,
        int count,
        int? insertionIndex = null)
    {
        if (start < 0 || count < 0 || start > volumes.Count || count > volumes.Count - start)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        int end = start + count;
        int insertAt = insertionIndex ?? host.Children.Count;
        if (insertAt < 0 || insertAt > host.Children.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(insertionIndex));
        }
        for (int index = start; index < end; index++)
        {
            FirmwareVolume volume = volumes[index];
            Grid row = CreateRow(
                string.Format(text.Culture, text["OffsetHexFormat"], text["Offset"], volume.Offset),
                string.Format(text.Culture, text["VolumeValueFormat"],
                    volume.Length / (double)UiDesign.BytesPerKibibyte, text["Checksum"],
                    text[volume.HeaderChecksumValid ? "Valid" : "Invalid"], volume.FileSystem));
            host.Children.Insert(insertAt++, row);
        }
    }

    private string ImageDisplayName(BiosImage image, ImageSourceKind source) =>
        source == ImageSourceKind.File
            ? Path.GetFileName(activeInputPath ?? image.FilePath)
            : ImageSourceDisplayName(source);

    private string ActiveFileTooltip(BiosImage image)
    {
        string path = activeInputPath ?? image.FilePath;
        return string.IsNullOrWhiteSpace(activePackageEntry)
            ? path
            : string.Join(Environment.NewLine, path, activePackageEntry);
    }

    private string ImageSourceDisplayName(ImageSourceKind source) => source switch
    {
        ImageSourceKind.File => text["SourceFileName"],
        ImageSourceKind.UpdatedImage => text["SourceModifiedName"],
        ImageSourceKind.FullSpi or ImageSourceKind.PartialSpi or ImageSourceKind.BiosRegion => text["SourceSystemName"],
        _ => throw new ArgumentOutOfRangeException(nameof(source))
    };

    private void RenderActiveImageViews()
    {
        if (activeImage is null || activeSource is null)
        {
            return;
        }

        BiosImage image = activeImage;
        Results.Children.Clear();
        SecureBootResults.Children.Clear();
        DriversResults.Children.Clear();
        TurboBoostResults.Children.Clear();
        PersonalizationResults.Children.Clear();
        TpmResults.Children.Clear();
        SaveResults.Children.Clear();
        SecureBootIssueHost.Children.Clear();
        SecureBootNoticeBar.IsOpen = false;
        TurboBoostNoticeBar.IsOpen = false;
        PersonalizationNoticeBar.IsOpen = false;
        TpmNoticeBar.IsOpen = false;
        SaveNoticeBar.IsOpen = false;

        var summary = Card(Results, text["Summary"]);
        AddRow(summary, text["Source"], ImageSourceDisplayName(activeSource.Value));
        if (activeSource == ImageSourceKind.File ||
            (activeSource == ImageSourceKind.UpdatedImage && !string.IsNullOrWhiteSpace(activeInputPath)))
        {
            AddRow(summary, text["Path"], activeInputPath ?? image.FilePath);
            if (!string.IsNullOrWhiteSpace(activePackageEntry))
            {
                AddRow(summary, text["PackageEntry"], activePackageEntry);
            }
        }
        AddRow(summary, text["Size"], string.Format(text.Culture, text["ByteSizeFormat"],
            image.Size, image.Size / (double)UiDesign.BytesPerMebibyte));
        AddRow(summary, text["Format"], text[image.Kind.ToString()]);
        AddRow(summary, text["Sha256"], image.Sha256);

        ShowFirmwareImageIdentity();

        if (activeSource == ImageSourceKind.PartialSpi)
        {
            FirmwareRegionReadStatus[] unreadableRegions = activeDumpRegions
                .Where(region => !region.Readable)
                .ToArray();
            FirmwareRegionReadStatus[] relevantUnreadableRegions = unreadableRegions
                .Where(region => region.Kind != FlashRegionKind.ME)
                .ToArray();

            // Intel ME is intentionally outside the application's modification scope.
            // Keep the internal PartialSpi metadata truthful, but do not surface ME-only
            // read restrictions as a user-facing problem.
            bool managementEngineIsTheOnlyUnreadableRegion =
                unreadableRegions.Length > 0 && relevantUnreadableRegions.Length == 0;
            if (!managementEngineIsTheOnlyUnreadableRegion)
            {
                string unavailable = string.Join(
                    text["InlineListSeparator"],
                    relevantUnreadableRegions.Select(region => text["Region" + region.Kind]));
                string details = string.IsNullOrWhiteSpace(unavailable)
                    ? text["PartialSpiWarning"]
                    : string.Format(text.Culture, text["PartialSpiWarningWithRegions"], unavailable);
                Results.Children.Add(Notice(text["PartialSpiTitle"], details, InfoBarSeverity.Warning));
            }
        }

        SecureBootReport secureBootReport = image.ManagedSecureBoot ?? image.SecureBoot;
        ShowSecureBootOverview(secureBootReport);
        ShowDriverOverview(image.UefiDrivers);
        ShowTurboBoostOverview(image.TurboBoostUnlock);
        ShowPersonalizationOverview(image.Personalization);
        ShowPersonalizationDetails(image.Personalization);
        if (TpmUiEnabled)
        {
            ShowTpmOverview(image.TpmFirmware);
            ShowTpmDetails(image.TpmFirmware);
        }
        ShowSaveDetails(image);

        Results.Children.Add(Notice(text["Checks"],
            image.Issues.Count == 0 ? text["ChecksOk"] : string.Join(Environment.NewLine, image.Issues.Select(key => text[key])),
            image.Issues.Count == 0 ? InfoBarSeverity.Success : InfoBarSeverity.Warning));

        var volumes = Card(Results, string.Format(text.Culture, text["CountTitleFormat"],
            text["Volumes"], image.Volumes.Count));
        if (image.Volumes.Count == 0)
        {
            volumes.Children.Add(Label(text["NoVolumes"]));
        }
        else
        {
            AddFirmwareVolumePager(volumes, image.Volumes);
        }

        var regions = Card(Results, text["Regions"]);
        foreach (var region in image.Regions)
        {
            string formatKey = region.WithinImage ? "RegionValueFormat" : "RegionInvalidValueFormat";
            AddRow(regions, text["Region" + region.Kind], string.Format(text.Culture, text[formatKey],
                region.Offset, region.Length / (double)UiDesign.BytesPerKibibyte, text["Invalid"]));
        }
        if (image.Regions.Count == 0)
        {
            string noRegionsKey = activeSource == ImageSourceKind.BiosRegion
                ? "NoRegionsBiosRegion"
                : "NoRegions";
            regions.Children.Add(Label(text[noRegionsKey]));
        }

        var markers = Card(Results, text["Markers"]);
        markers.Children.Add(Label(image.Markers.Count == 0 ? text["NoMarkers"] : string.Join(text["InlineListSeparator"], image.Markers)));
        var hint = Label(text["MarkerHint"]);
        hint.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutSecondaryTextOpacity);
        markers.Children.Add(hint);

        ShowSecureBootDetails(secureBootReport, image.ManagedSecureBoot is not null);
        ShowDriverDetails(image.UefiDrivers);
        ShowTurboBoostDetails(image.TurboBoostUnlock);
    }

    private void ShowFirmwareImageIdentity()
    {
        FirmwareImageIdentity identity = activeImage?.FirmwareIdentity ?? FirmwareImageIdentity.Empty;

        var bios = Card(Results, text["BiosInformation"]);
        AddRow(bios, text["Manufacturer"], IdentityValue(identity.BiosManufacturer));
        AddRow(bios, text["Version"], IdentityValue(identity.BiosVersion));
        AddRow(bios, text["ReleaseDate"], IdentityValue(identity.BiosReleaseDate));

        var board = Card(Results, text["SystemBoard"]);
        AddRow(board, text["Manufacturer"], IdentityValue(identity.BoardManufacturer));
        AddRow(board, text["Name"], IdentityValue(identity.BoardName));
        AddRow(board, text["Version"], IdentityValue(identity.BoardVersion));
        AddRow(board, text["SerialNumber"], IdentityValue(identity.BoardSerialNumber));
    }

    private string IdentityValue(string? value) =>
        string.IsNullOrWhiteSpace(value) ? text["NotAvailable"] : value;

    private static StackPanel Card(StackPanel host, string title)
    {
        var panel = new StackPanel { Spacing = UiResources.Get<double>(UiResourceKeys.LayoutDynamicCardSpacing) };
        panel.Children.Add(new TextBlock
        {
            Text = title,
            Style = UiResources.Get<Style>(UiResourceKeys.SectionTitleTextStyle),
            TextWrapping = TextWrapping.Wrap
        });

        var border = new Border
        {
            Style = UiResources.Get<Style>(UiResourceKeys.CardBorderStyle),
            Child = panel
        };
        host.Children.Add(border);
        return panel;
    }

    private static TextBlock Label(string value) => new()
    {
        Text = value,
        TextWrapping = TextWrapping.Wrap,
        IsTextSelectionEnabled = true
    };

    private static FrameworkElement NoticeContent(string title, string message)
    {
        var content = new StackPanel { Spacing = UiResources.Get<double>(UiResourceKeys.LayoutNoticeSpacing) };
        if (!string.IsNullOrWhiteSpace(title))
        {
            content.Children.Add(new TextBlock
            {
                Text = title,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true
            });
        }

        content.Children.Add(Label(message));
        return content;
    }

    private InfoBar Notice(string title, string message, InfoBarSeverity severity, bool isClosable = false)
    {
        var bar = new InfoBar
        {
            IsOpen = true,
            IsClosable = isClosable,
            Content = NoticeContent(title, message),
            Severity = severity,
            Tag = message
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(bar, AccessibleNoticeName(title, message));
        return bar;
    }

    private void SetNotice(InfoBar bar, string title, string message, InfoBarSeverity severity)
    {
        bar.Title = string.Empty;
        bar.Message = string.Empty;
        bar.Content = NoticeContent(title, message);
        bar.Tag = message;
        bar.Severity = severity;
        bar.IsOpen = true;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(bar, AccessibleNoticeName(title, message));
    }

    private string AccessibleNoticeName(string title, string message) =>
        string.IsNullOrWhiteSpace(title)
            ? message
            : string.Format(text.Culture, text["NoticeAutomationNameFormat"], title, message);

    private static string NoticeMessage(InfoBar bar) => bar.Tag as string ?? string.Empty;

    private static void AddRow(StackPanel panel, string name, string value) =>
        panel.Children.Add(CreateRow(name, value));

    private static Grid CreateRow(string name, string value)
    {
        var row = new Grid { ColumnSpacing = UiResources.Get<double>(UiResourceKeys.LayoutRowColumnSpacing) };
        row.ColumnDefinitions.Add(new ColumnDefinition
        {
            Width = GridLength.Auto,
            MaxWidth = UiResources.Get<double>(UiResourceKeys.LayoutRowLabelMaxWidth)
        });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var title = Label(name);
        title.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutSecondaryTextOpacity);
        var body = Label(value);
        Grid.SetColumn(body, 1);
        row.Children.Add(title);
        row.Children.Add(body);
        return row;
    }

}
