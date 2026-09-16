namespace XeonV3Control.Tests;

[TestClass]
public sealed class UiSourceContractTests
{
    [TestMethod]
    public void LoadedBoundaryIsOneShotAndHandlesUnexpectedErrors()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "Root.Loaded += RootLoaded;");
        StringAssert.Contains(source, "Root.Loaded -= RootLoaded;");
        StringAssert.Contains(source, "private async void RootLoaded");
        StringAssert.Contains(source, "catch (Exception error)");
        StringAssert.Contains(source, "ShowError(error);");
        Assert.IsFalse(source.Contains("Root.Loaded += async", StringComparison.Ordinal));
    }

    [TestMethod]
    public void CaptionButtonsUseSystemForegroundAndGuardCustomization()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "AppWindowTitleBar.IsCustomizationSupported()");
        StringAssert.Contains(source, "ButtonBackgroundColor = Colors.Transparent");
        StringAssert.Contains(source, "ButtonForegroundColor = null");
        StringAssert.Contains(source, "ButtonInactiveForegroundColor = null");
        Assert.IsFalse(source.Contains("Colors.White", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("Colors.Black", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("ActualThemeChanged +=", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("UpdateTitleBar", StringComparison.Ordinal));
    }

    [TestMethod]
    public void NavigationItemsReceiveLocalizedAccessibilityMetadata()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "SetNavigationItemText(SourceNavigationItem, text[\"NavSource\"])");
        StringAssert.Contains(source, "SetNavigationItemText(AnalysisNavigationItem, text[\"NavAnalysis\"])");
        StringAssert.Contains(source, "SetNavigationItemText(SecureBootNavigationItem, text[\"NavSecureBoot\"])");
        StringAssert.Contains(source, "SetNavigationItemText(DriversNavigationItem, text[\"NavDrivers\"])");
        StringAssert.Contains(source, "SetNavigationItemText(TurboBoostNavigationItem, text[\"NavTurboBoostUnlock\"])");
        StringAssert.Contains(source, "SetNavigationItemText(PersonalizationNavigationItem, text[\"NavPersonalization\"])");
        StringAssert.Contains(source, "SetNavigationItemText(TpmNavigationItem, text[\"NavTpm\"])");
        StringAssert.Contains(source, "SetNavigationItemText(SaveNavigationItem, text[\"NavSave\"])");
        StringAssert.Contains(source, "ToolTipService.SetToolTip(item, value)");
        StringAssert.Contains(source, "AutomationProperties.SetName(item, value)");
    }

    [TestMethod]
    public void UefiDriversExposeOnlyCatalogAuthorizedUpdatesAndHaveLocalizedNavigation()
    {
        string mainPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string main = File.ReadAllText(mainPath);
        StringAssert.Contains(main, "SetNavigationItemText(DriversNavigationItem, text[\"NavDrivers\"])");
        StringAssert.Contains(main, "ShowDriverOverview(image.UefiDrivers);");
        StringAssert.Contains(main, "ShowDriverDetails(image.UefiDrivers);");

        string biosPath = RepositoryTestFiles.Find("src", "XeonV3Control.Core", "BiosImage.cs");
        string bios = File.ReadAllText(biosPath);
        StringAssert.Contains(bios, "public IReadOnlyList<X99UefiDriverUpdatePlan> X99UefiDriverUpdates");
        StringAssert.Contains(bios, "X99UefiDriverUpdatePlanner.Plan(data, image, cancellationToken)");

        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        StringAssert.Contains(xaml, "x:Name=\"DriversNavigationItem\"");
        StringAssert.Contains(xaml, "x:Name=\"DriversPage\"");

        string viewPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "DriversView.cs");
        string view = File.ReadAllText(viewPath);
        StringAssert.Contains(view, "new AutoSuggestBox");
        StringAssert.Contains(view, "DriverMatchesSearch");
        StringAssert.Contains(view, "UefiDriverSearchPlaceholder");
        StringAssert.Contains(view, "ShowX99DriverUpdates(image.X99UefiDriverUpdates, report.Drivers.Count)");
        StringAssert.Contains(view, "UefiDriverUpdatesInventorySummary");
        StringAssert.Contains(view, ".OrderBy(X99DriverUpdateDisplayRank)");
        StringAssert.Contains(view, "X99UefiDriverUpdateDisposition.Ready => 0");
        StringAssert.Contains(view, "text[\"UefiDriverUpdateDisposition\" + plan.Disposition]");
        Assert.IsFalse(view.Contains("UefiDriverMutationPlanner", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("UefiDriverUpdatePlanner", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("X99UefiDriverUpdatePlanner", StringComparison.Ordinal));
        StringAssert.Contains(view, "plan.CanApply");
        StringAssert.Contains(view, "X99UefiDriverImageUpdater.ApplyFileAsync");
        StringAssert.Contains(view, "TemporaryBiosArtifact.UefiDriverUpdate");
        StringAssert.Contains(view, "UiOperationKind.UpdatingUefiDriver");
        Assert.IsFalse(view.Contains("ContentDialog", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("PlanAdd", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("PlanReplace", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("PlanRemove", StringComparison.Ordinal));
        Assert.IsFalse(xaml.Contains("PlanAdd", StringComparison.Ordinal));
        Assert.IsFalse(xaml.Contains("PlanReplace", StringComparison.Ordinal));
        Assert.IsFalse(xaml.Contains("PlanRemove", StringComparison.Ordinal));
    }

    [TestMethod]
    public void UefiDriverCardsDoNotSnapshotThemeBrushesInCode()
    {
        string viewPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "DriversView.cs");
        string view = File.ReadAllText(viewPath);

        Assert.IsFalse(view.Contains("SemanticBackgroundBrush", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("SemanticBrush(", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("UiResources.Get<Brush>", StringComparison.Ordinal));
        StringAssert.Contains(view, "DriverBorderStyleKey");
        StringAssert.Contains(view, "DriverStatusStyleKey");
    }

    [TestMethod]
    public void UiSmokeExercisesTheUefiDriverPageInDarkTheme()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "SelectTaggedItem(ThemeComboBox, ThemePreference.Dark.ToString())");
        StringAssert.Contains(source, "Root.ActualTheme != ElementTheme.Dark");
        StringAssert.Contains(source, "drivers-dark.png");
        StringAssert.Contains(source, "UEFI drivers page did not preserve the dark theme.");
    }


    [TestMethod]
    public void WindowSizingConvertsLogicalPixelsAtTheCurrentDpi()
    {
        string designPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "UiDesign.cs");
        string design = File.ReadAllText(designPath);
        StringAssert.Contains(design, "ScaleDimension(logicalSize.Width, scale)");
        StringAssert.Contains(design, "ScaleDimension(logicalSize.Height, scale)");
        StringAssert.Contains(design, "Native.GetDpiForWindow(windowHandle)");
        StringAssert.Contains(design, "Math.Min(physicalSize.Width, workArea.Width)");

        string windowPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string window = File.ReadAllText(windowPath);
        StringAssert.Contains(window, "Root.XamlRoot?.RasterizationScale");
        StringAssert.Contains(window, "ResizeWindow(UiDesign.SmokeNarrowWindowSize)");
        StringAssert.Contains(window, "ResizeWindow(UiDesign.SmokeMediumWindowSize)");
        Assert.AreEqual(1, window.Split("AppWindow.Resize", StringSplitOptions.None).Length - 1);
    }

    [TestMethod]
    public void PersonalizationPageExposesTwoBootLogosAndBeeperMutation()
    {
        string mainPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string main = File.ReadAllText(mainPath);
        StringAssert.Contains(main, "WorkspacePage.Personalization");
        StringAssert.Contains(main, "PersonalizationNavigationItem.Visibility = imageNavigationVisibility;");
        StringAssert.Contains(main, "ShowPersonalizationDetails(image.Personalization);");

        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        StringAssert.Contains(xaml, "x:Name=\"PersonalizationNavigationItem\"");
        StringAssert.Contains(xaml, "x:Name=\"PersonalizationPage\"");
        StringAssert.Contains(xaml, "x:Name=\"PersonalizationResults\"");

        string viewPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "PersonalizationView.cs");
        string view = File.ReadAllText(viewPath);
        StringAssert.Contains(view, "BootLogoKind.LargeBoot");
        StringAssert.Contains(view, "BootLogoKind.SmallAmi");
        StringAssert.Contains(view, "PersonalizationImageUpdater.ReplaceBootLogoAsync");
        StringAssert.Contains(view, "BootLogoImageDecoder.DecodeFittedBgraAsync");
        StringAssert.Contains(view, "BootLogoBitmapConverter.CreateBlackTemplate");
        StringAssert.Contains(view, "PersonalizationPreviewCurrent");
        StringAssert.Contains(view, "SetBootLogoPreview(state, state.CurrentBmp)");
        StringAssert.Contains(view, "PersonalizationImageUpdater.SetStartupBeeperDisabledAsync");
        StringAssert.Contains(view, "TemporaryBiosArtifact.LargeBootLogo");
        StringAssert.Contains(view, "TemporaryBiosArtifact.SmallAmiLogo");
        StringAssert.Contains(view, "UiOperationKind.UpdatingBeeper");
    }

    [TestMethod]
    public void TpmUiRemainsHiddenUntilHardwareValidationResumes()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "private static readonly bool TpmUiEnabled = false;");
        StringAssert.Contains(source, "TpmNavigationItem.Visibility = TpmUiEnabled ? imageNavigationVisibility : Visibility.Collapsed;");
        StringAssert.Contains(source, "TpmNavigationItem.IsEnabled = TpmUiEnabled && idle && imageAvailable;");
        StringAssert.Contains(source, "if (page == WorkspacePage.Tpm && !TpmUiEnabled)");
        StringAssert.Contains(source, "if (TpmUiEnabled)");
        StringAssert.Contains(source, "ShowTpmOverview(image.TpmFirmware);");
        StringAssert.Contains(source, "ShowTpmDetails(image.TpmFirmware);");
    }

    [TestMethod]
    public void TurboBoostCpuPatchRemovalIsExplicitlyGatedAndTpmPageExposesDiagnostics()
    {
        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        StringAssert.Contains(xaml, "x:Name=\"TpmPage\"");
        StringAssert.Contains(xaml, "x:Name=\"TpmNoticeBar\"");
        StringAssert.Contains(xaml, "x:Name=\"TpmResults\"");
        StringAssert.Contains(xaml, "x:Name=\"SaveNavigationItem\"");
        StringAssert.Contains(xaml, "x:Name=\"SavePage\"");

        string tpmViewPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "TpmView.cs");
        string tpmView = File.ReadAllText(tpmViewPath);
        StringAssert.Contains(tpmView, "TpmDebugDriverImageUpdater.Plan");
        StringAssert.Contains(tpmView, "TpmDebugDriverImageUpdater.ApplyFileAsync");
        StringAssert.Contains(tpmView, "UefiTpmDebugReportReader.TryRead()");
        StringAssert.Contains(tpmView, "TemporaryBiosArtifact.TpmDebugInstall");
        StringAssert.Contains(tpmView, "TemporaryBiosArtifact.TpmDebugRemoval");

        string viewPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "TurboBoostView.cs");
        string view = File.ReadAllText(viewPath);
        StringAssert.Contains(view, "AddRow(card, text[\"TurboBoostCpuPatchRemovalStatus\"], TurboBoostCpuPatchRemovalStatusText(report));");
        StringAssert.Contains(view, "AddRow(summary, text[\"TurboBoostCpuPatchRemovalStatus\"], TurboBoostCpuPatchRemovalStatusText(report));");
        int overviewStatus = view.IndexOf("AddRow(card, text[\"TurboBoostStatus\"]", StringComparison.Ordinal);
        int overviewRemoval = view.IndexOf("AddRow(card, text[\"TurboBoostCpuPatchRemovalStatus\"]", StringComparison.Ordinal);
        int overviewFindings = view.IndexOf("AddRow(card, text[\"TurboBoostFindings\"]", StringComparison.Ordinal);
        Assert.IsTrue(overviewStatus >= 0 && overviewRemoval > overviewStatus && overviewFindings > overviewRemoval);
        int detailStatus = view.IndexOf("AddRow(summary, text[\"TurboBoostStatus\"]", StringComparison.Ordinal);
        int detailRemoval = view.IndexOf("AddRow(summary, text[\"TurboBoostCpuPatchRemovalStatus\"]", StringComparison.Ordinal);
        int detailFindings = view.IndexOf("AddRow(summary, text[\"TurboBoostFindings\"]", StringComparison.Ordinal);
        Assert.IsTrue(detailStatus >= 0 && detailRemoval > detailStatus && detailFindings > detailRemoval);
        Assert.IsFalse(view.Contains("TurboBoostScope", StringComparison.Ordinal));
        StringAssert.Contains(view, "card.Children.Add(CreateCpuPatchRemovalButton(report));");
        StringAssert.Contains(view, "IsEnabled = plan is not null");
        StringAssert.Contains(view, "button.Click += RemoveCpuPatch;");
        StringAssert.Contains(view, "CpuPatchImageUpdater.RemoveFileAsync(");
        StringAssert.Contains(view, "TurboBoostNoticeBar");
        Assert.IsFalse(view.Contains("TurboBoostRemoveConfirmTitle", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("ShowDialogAsync", StringComparison.Ordinal));
        StringAssert.Contains(view, "Task.Run(");
    }

    [TestMethod]
    public void ForeignUnlockCleanupUiExecutesOnlySingleVerifiedForeignFfsWithoutBaseline()
    {
        string viewPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "TurboBoostView.cs");
        string view = File.ReadAllText(viewPath);

        StringAssert.Contains(view, "TurboBoostForeignUnlockModules");
        StringAssert.Contains(view, "TurboBoostUnlockDisposition");
        StringAssert.Contains(view, "TurboBoostForeignRemovalStatus");
        StringAssert.Contains(view, "TurboBoostForeignProposedAction");
        StringAssert.Contains(view, "TurboBoostUnlockConfidence");
        StringAssert.Contains(view, "plan.Operation == TurboBoostForeignRemovalOperation.RemoveInjectedFfs");
        StringAssert.Contains(view, "TurboBoostForeignUnlockImageUpdater.RemoveInjectedFfsFileAsync(");
        Assert.IsFalse(view.Contains("TurboBoostForeignRemoveConfirmTitle", StringComparison.Ordinal));
        StringAssert.Contains(view, "TurboBoostEmbeddedDiagnosticsTitle");
        StringAssert.Contains(view, "TurboBoostEmbeddedDiagnosticsExplanation");
        StringAssert.Contains(view, "Where(IsEmbeddedTurboBoostDiagnostic)");
        StringAssert.Contains(view, "IsExpanded = false");
        Assert.IsFalse(view.Contains("TurboBoostForeignSelectBaseline", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("TurboBoostForeignUnlockRemovalPlanner.PlanFilesAsync(", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("CurrentTurboBoostForeignPlanning", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("SameFirmwarePath", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("string.Join(text[\"InlineListSeparator\"], finding.MarkerHits)", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("RemoveAllForeign", StringComparison.Ordinal));
        Assert.IsFalse(view.Contains("RestoreBaselineFfsFileAsync", StringComparison.Ordinal));
    }

    [TestMethod]
    public void TurboBoostOperationNoticesStayOnTheTurboBoostPage()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "UiOperationKind.RemovingCpuPatch or");
        StringAssert.Contains(source, "UiOperationKind.RemovingForeignUnlock");
        StringAssert.Contains(source, "SetNotice(TurboBoostNoticeBar, title, message, severity);");
        StringAssert.Contains(source, "TurboBoostNoticeBar.IsOpen = false;");
        StringAssert.Contains(source, "await Task.Yield();");
        Assert.IsFalse(source.Contains("PlanningForeignUnlock", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("turboBoostForeignPlanning", StringComparison.Ordinal));
    }

    [TestMethod]
    public void SecureBootNoticesAreStructuredAndMutationRequiresASafeLayout()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "SecureBootView.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "AddSecureBootNotices(");
        StringAssert.Contains(source, "SecureBootIssueHost");
        StringAssert.Contains(source, "IsClosable = false");
        StringAssert.Contains(source, "Title = notice.Title");
        StringAssert.Contains(source, "Message = notice.Message");
        StringAssert.Contains(source, "BiosImage updatedImage = await Task.Run(async () =>");
        StringAssert.Contains(source, "SecureBootImageUpdater.UpdateFileAsync(sourceImage.FilePath, target, token)");
        StringAssert.Contains(source, "if (managedLayoutAvailable && maintenanceRequired && !mutationBlocked)");
        StringAssert.Contains(source, "Content = IconText(UiGlyphs.UpdateCertificate, text[\"CertUpdate\"])");
        StringAssert.Contains(source, "repairButton.Click += RepairSecureBoot;");
        Assert.IsFalse(source.Contains("UpdateCertificates", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("SecureBootNoticeText", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("CompactStatus", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("IsEnabled = maintenanceRequired", StringComparison.Ordinal));
    }

    [TestMethod]
    public void SecureBootOperationNoticesStayOnTheSecureBootPage()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "ShowOperationNotice(operationKind, string.Empty, text[\"Cancelled\"]");
        StringAssert.Contains(source, "ShowOperationError(operationKind, error);");
        StringAssert.Contains(source, "operationKind == UiOperationKind.UpdatingCertificates");
        StringAssert.Contains(source, "SetNotice(SecureBootNoticeBar, title, message, severity);");
    }

    [TestMethod]
    public void TemporaryFirmwareUsesFriendlyUiNamesAndDoesNotExposeInternalPaths()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "ImageSourceKind.UpdatedImage => text[\"SourceModifiedName\"]");
        StringAssert.Contains(source, "ImageSourceKind.FullSpi or ImageSourceKind.PartialSpi or ImageSourceKind.BiosRegion => text[\"SourceSystemName\"]");
        StringAssert.Contains(source, "activeSource == ImageSourceKind.UpdatedImage && !string.IsNullOrWhiteSpace(activeInputPath)");
        StringAssert.Contains(source, "source == ImageSourceKind.File ? ActiveFileTooltip(image) : displayName");
        StringAssert.Contains(source, "ImageSourceKind.UpdatedImage => previousInputPath");
        StringAssert.Contains(source, "ImageSourceKind.UpdatedImage => previousPackageEntry");
        StringAssert.Contains(source, "? previousDumpRegions");
        StringAssert.Contains(source, "AddRow(summary, text[\"Path\"], activeInputPath ?? image.FilePath);");
    }

    [TestMethod]
    public void SecureBootSummaryUsesRequestedCompactTitle()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.Core", "Localization", "ru-RU.json");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "\"SecureBootSummary\": \"SecureBoot\"");
    }

    [TestMethod]
    public void SecureBootRepairCopyDoesNotRequireManualPlatformKeyEnrollment()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.Core", "Localization", "ru-RU.json");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "\"CertUpdate\": \"Исправить Secure Boot\"");
        Assert.IsFalse(source.Contains("зарегистрировать доверенный PK", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("регистрирует Platform Key", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(source.Contains("Регистрация доверенного Platform Key", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void PartialSpiWarningDoesNotContainProgrammingDisclaimer()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.Core", "Localization", "ru-RU.json");
        string source = File.ReadAllText(path);

        Assert.IsFalse(source.Contains("Этот файл нельзя считать полным резервным образом для программирования", StringComparison.Ordinal));
    }

    [TestMethod]
    public void ManagementEngineOnlyReadRestrictionIsNotPresentedAsAUserFacingProblem()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, ".Where(region => region.Kind != FlashRegionKind.ME)");
        StringAssert.Contains(source, "managementEngineIsTheOnlyUnreadableRegion");
        StringAssert.Contains(source, "if (!managementEngineIsTheOnlyUnreadableRegion)");
    }

    [TestMethod]
    public void LegacyPreferencesAreMigratedIntoCombinedSchemaOnRead()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "UserPreferences.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "LegacyLanguageValueName");
        StringAssert.Contains(source, "LegacyThemeValueName");
        StringAssert.Contains(source, "_ = TryPersist(preferences.Culture, preferences.Theme, out _);");
        StringAssert.Contains(source, "TryDeleteLegacyValue(key, LegacyLanguageValueName)");
        StringAssert.Contains(source, "TryDeleteLegacyValue(key, LegacyThemeValueName)");
    }

    [TestMethod]
    public void SettingsItemCanRestoreThePreviousWorkspacePage()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "private WorkspacePage pageBeforeSettings = WorkspacePage.Source;");
        StringAssert.Contains(source, "args.IsSettingsInvoked");
        StringAssert.Contains(source, "currentPage != WorkspacePage.Settings");
        StringAssert.Contains(source, "CloseSettings();");
        StringAssert.Contains(source, "pageBeforeSettings = currentPage;");
        StringAssert.Contains(source, "private void CloseSettings() => NavigateTo(pageBeforeSettings);");
    }

    [TestMethod]
    public void ResponsiveLayoutIsCalculatedFromTheContentViewport()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "private void ContentScrollerSizeChanged");
        StringAssert.Contains(source, "ResponsiveLayout.Calculate(");
        StringAssert.Contains(source, "UiResourceKeys.LayoutActionCardsTwoColumnMinWidth");
        StringAssert.Contains(source, "ContentPanel.Width = layout.ContentWidth;");
        StringAssert.Contains(source, "Grid.SetRow(SystemCard, layout.UseTwoColumnActions ? 0 : 1);");
        StringAssert.Contains(source, "Grid.SetColumn(SystemCard, layout.UseTwoColumnActions ? 1 : 0);");
    }

    [TestMethod]
    public void SystemDumpDistinguishesFullPartialAndBiosFallbackSources()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "FirmwareReadScope.FullSpi => ImageSourceKind.FullSpi");
        StringAssert.Contains(source, "FirmwareReadScope.PartialSpi => ImageSourceKind.PartialSpi");
        StringAssert.Contains(source, "_ => ImageSourceKind.BiosRegion");
        StringAssert.Contains(source, "activeSource == ImageSourceKind.BiosRegion");
        StringAssert.Contains(source, "? \"NoRegionsBiosRegion\"");
    }

    [TestMethod]
    public void BiosInformationUsesOnlyTheAnalyzedFirmwareImageIdentity()
    {
        string mainPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string main = File.ReadAllText(mainPath);
        StringAssert.Contains(main, "ShowFirmwareImageIdentity();");
        StringAssert.Contains(main, "FirmwareImageIdentity identity = activeImage?.FirmwareIdentity ?? FirmwareImageIdentity.Empty;");
        StringAssert.Contains(main, "Card(Results, text[\"BiosInformation\"])");
        StringAssert.Contains(main, "IdentityValue(identity.BiosManufacturer)");
        StringAssert.Contains(main, "IdentityValue(identity.BiosVersion)");
        StringAssert.Contains(main, "IdentityValue(identity.BiosReleaseDate)");
        StringAssert.Contains(main, "Card(Results, text[\"SystemBoard\"])");
        StringAssert.Contains(main, "IdentityValue(identity.BoardManufacturer)");
        StringAssert.Contains(main, "IdentityValue(identity.BoardName)");
        StringAssert.Contains(main, "IdentityValue(identity.BoardVersion)");
        StringAssert.Contains(main, "IdentityValue(identity.BoardSerialNumber)");
        Assert.IsFalse(main.Contains("SystemFirmwareIdentity", StringComparison.Ordinal));
        Assert.IsFalse(main.Contains("SystemFirmwareIdentityReader", StringComparison.Ordinal));
        Assert.IsFalse(main.Contains("PreferSystemIdentity", StringComparison.Ordinal));
        string appDirectory = Path.GetDirectoryName(mainPath)!;
        Assert.IsFalse(File.Exists(Path.Combine(appDirectory, "SystemFirmwareIdentity.cs")));

        string imageReaderPath = RepositoryTestFiles.Find("src", "XeonV3Control.Core", "FirmwareImageIdentity.cs");
        string imageReader = File.ReadAllText(imageReaderPath);
        StringAssert.Contains(imageReader, "BIOS Message:");
        StringAssert.Contains(imageReader, "$FID");
        StringAssert.Contains(imageReader, "firmware-board-identities.json");
        Assert.IsFalse(imageReader.Contains("DllImport", StringComparison.Ordinal));
    }

    [TestMethod]
    public void MainContentAndStatusAreCenteredWithinTheNavigationViewport()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string source = File.ReadAllText(path);

        int contentPanel = source.IndexOf("x:Name=\"ContentPanel\"", StringComparison.Ordinal);
        int statusHost = source.IndexOf("x:Name=\"StatusHost\"", StringComparison.Ordinal);
        Assert.IsTrue(contentPanel >= 0);
        Assert.IsTrue(statusHost >= 0);
        StringAssert.Contains(source[contentPanel..], "HorizontalAlignment=\"Center\"");
        string statusMarkup = source[statusHost..Math.Min(source.Length, statusHost + 700)];
        StringAssert.Contains(statusMarkup, "HorizontalAlignment=\"Center\"");
        StringAssert.Contains(statusMarkup, "VerticalAlignment=\"Bottom\"");
        StringAssert.Contains(statusMarkup, "Canvas.ZIndex=\"1\"");
        Assert.IsFalse(statusMarkup.Contains("Grid.Row=\"1\"", StringComparison.Ordinal));
    }

    [TestMethod]
    public void SecureBootUiUsesManagedStoresAndCentersCurrentImageStatus()
    {
        string codePath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string code = File.ReadAllText(codePath);
        StringAssert.Contains(code, "SecureBootReport secureBootReport = image.ManagedSecureBoot ?? image.SecureBoot;");
        StringAssert.Contains(code, "ShowSecureBootDetails(secureBootReport, image.ManagedSecureBoot is not null);");

        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        int label = xaml.IndexOf("x:Name=\"CurrentFileLabel\"", StringComparison.Ordinal);
        Assert.IsTrue(label >= 0);
        string labelMarkup = xaml[label..Math.Min(xaml.Length, label + 700)];
        StringAssert.Contains(labelMarkup, "HorizontalAlignment=\"Stretch\"");
        StringAssert.Contains(labelMarkup, "TextAlignment=\"Center\"");
    }

    [TestMethod]
    public void FilePickerAndDropUseUnifiedImageOrPackagePipeline()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "FirmwarePackageLoader.SupportedInputExtensions");
        StringAssert.Contains(source, "FirmwarePackageLoader.HasSupportedInputExtension(path)");
        StringAssert.Contains(source, "FirmwarePackageLoader.IsPackagePath(path)");
        StringAssert.Contains(source, "FirmwarePackageLoader.InspectAsync(path, token)");
        StringAssert.Contains(source, "SelectPackageCandidateAsync(package.Candidates)");
        StringAssert.Contains(source, "MaterializePackageCandidateAsync(selected, token)");
        StringAssert.Contains(source, "packageEntry: selected.LogicalPath");

        string packagePath = RepositoryTestFiles.Find("src", "XeonV3Control.Core", "FirmwarePackage.cs");
        string packageSource = File.ReadAllText(packagePath);
        Assert.IsFalse(packageSource.Contains("Process.Start", StringComparison.Ordinal));
        Assert.IsFalse(packageSource.Contains("ProcessStartInfo", StringComparison.Ordinal));
        Assert.IsFalse(packageSource.Contains("tar.exe", StringComparison.OrdinalIgnoreCase));
    }
    [TestMethod]
    public void SourcePickerOffersExplicitCategoriesAndKeepsDropHintSeparate()
    {
        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        Assert.IsFalse(xaml.Contains("FileTypeFilterComboBox", StringComparison.Ordinal));
        StringAssert.Contains(xaml, "x:Name=\"DropHint\"");

        string codePath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string code = File.ReadAllText(codePath);
        StringAssert.Contains(code, "IReadOnlyList<SystemFileOpenDialog.Filter> OpenFileFilters()");
        StringAssert.Contains(code, "text[\"FileTypeAllSupported\"]");
        StringAssert.Contains(code, "text[\"FileTypeBiosImages\"]");
        StringAssert.Contains(code, "text[\"FileTypeArchives\"]");
        StringAssert.Contains(code, "text[\"FileTypeManufacturerPackages\"]");
        StringAssert.Contains(code, "SystemFileOpenDialog.PickSingleFile(hwnd, OpenFileFilters())");
        Assert.IsFalse(code.Contains("FileTypeChoices", StringComparison.Ordinal));
        Assert.IsFalse(code.Contains("FileOpenPicker", StringComparison.Ordinal));
        StringAssert.Contains(code, "FileHint.Text = text[\"FileHint\"];");
        StringAssert.Contains(code, "DropHint.Text = text[\"DropBiosHere\"];");

        string dialogPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "SystemFileOpenDialog.cs");
        string dialog = File.ReadAllText(dialogPath);
        StringAssert.Contains(dialog, "Guid(\"42F85136-DB7E-439C-85F1-E4075D135FC8\")");
        StringAssert.Contains(dialog, "void SetFileTypes(uint count");
        StringAssert.Contains(dialog, "dialog.SetFileTypes(");
        StringAssert.Contains(dialog, "string.Join(';', patterns)");
        Assert.IsFalse(dialog.Contains("DllImport", StringComparison.Ordinal));
        Assert.IsFalse(dialog.Contains("LibraryImport", StringComparison.Ordinal));
    }

    [TestMethod]
    public void LongOperationsDisableWorkspaceNavigationAndContentUntilCompletion()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "private void UpdateInteractionState()");
        StringAssert.Contains(source, "bool idle = operation is null;");
        StringAssert.Contains(source, "ContentPanel.IsEnabled = idle;");
        StringAssert.Contains(source, "SourceNavigationItem.IsEnabled = idle;");
        StringAssert.Contains(source, "AnalysisNavigationItem.IsEnabled = idle && imageAvailable;");
        StringAssert.Contains(source, "settingsItem.IsEnabled = idle;");
        StringAssert.Contains(source, "OpenButton.IsEnabled = idle;");
        StringAssert.Contains(source, "ReadButton.IsEnabled = idle;");
        StringAssert.Contains(source, "CancelButton.IsEnabled = !idle;");
        StringAssert.Contains(source, "if (operation is not null)\n        {\n            SynchronizeNavigationSelection();");
        StringAssert.Contains(source, "if (operation is not null || navigationSync || !args.IsSettingsInvoked");
        StringAssert.Contains(source, "UpdateInteractionState();\n        UpdateFileDropAvailability();");
    }

    [TestMethod]
    public void DragAndDropIsScopedToTheSourcePage()
    {
        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        int root = xaml.IndexOf("x:Name=\"Root\"", StringComparison.Ordinal);
        int sourcePage = xaml.IndexOf("x:Name=\"SourcePage\"", StringComparison.Ordinal);
        Assert.IsTrue(root >= 0 && sourcePage > root);
        string rootMarkup = xaml[root..sourcePage];
        Assert.IsFalse(rootMarkup.Contains("DragOver=\"SourceDragOver\"", StringComparison.Ordinal));
        Assert.IsFalse(rootMarkup.Contains("Drop=\"SourceDrop\"", StringComparison.Ordinal));

        string sourceMarkup = xaml[sourcePage..Math.Min(xaml.Length, sourcePage + 500)];
        StringAssert.Contains(sourceMarkup, "DragOver=\"SourceDragOver\"");
        StringAssert.Contains(sourceMarkup, "Drop=\"SourceDrop\"");

        string codePath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string code = File.ReadAllText(codePath);
        StringAssert.Contains(code, "bool enabled = currentPage == WorkspacePage.Source && operation is null;");
        StringAssert.Contains(code, "SourcePage.AllowDrop = enabled;");
        StringAssert.Contains(code, "IsSourcePageDropPoint");
        StringAssert.Contains(code, "SourcePage.TransformToVisual(Root)");
        StringAssert.Contains(code, "Root.XamlRoot?.RasterizationScale");
        StringAssert.Contains(code, "ContentScroller.TransformToVisual(Root)");
        Assert.IsFalse(code.Contains("Root.AllowDrop", StringComparison.Ordinal));

        string elevatedPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "ElevatedFileDropTarget.cs");
        string elevated = File.ReadAllText(elevatedPath);
        StringAssert.Contains(elevated, "Func<int, int, bool> acceptsPoint");
        StringAssert.Contains(elevated, "DragQueryPoint(dropHandle, out Native.Point point)");
        StringAssert.Contains(elevated, "return acceptsPoint(point.X, point.Y);");
    }

    [TestMethod]
    public void FailedFileImportPreservesActiveSessionUntilSuccessfulReplacement()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);
        int start = source.IndexOf("private async Task LoadFileAsync", StringComparison.Ordinal);
        int end = source.IndexOf("private async Task<FirmwarePackageCandidate?>", start, StringComparison.Ordinal);
        Assert.IsTrue(start >= 0 && end > start);
        Assert.IsFalse(source[start..end].Contains("ResetActiveImageState();", StringComparison.Ordinal));
        StringAssert.Contains(source[start..end], "ShowImage(rawImage, ImageSourceKind.File");
        StringAssert.Contains(source, "private async void ReadSystem");
        int readSystem = source.IndexOf("private async void ReadSystem", StringComparison.Ordinal);
        int runOperation = source.IndexOf("await RunOperation", readSystem, StringComparison.Ordinal);
        Assert.IsTrue(source[readSystem..runOperation].Contains("ResetActiveImageState();", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AnalysisResultsArePersistentAndTurboBoostStatusesUseWarningSeverity()
    {
        string mainPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string main = File.ReadAllText(mainPath);
        StringAssert.Contains(main, "private InfoBar Notice(string title, string message, InfoBarSeverity severity, bool isClosable = false)");
        StringAssert.Contains(main, "IsClosable = isClosable");

        string turboPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "TurboBoostView.cs");
        string turbo = File.ReadAllText(turboPath);
        int detectedStart = turbo.IndexOf("TurboBoostUnlockStatus.Detected => Notice(", StringComparison.Ordinal);
        int possibleStart = turbo.IndexOf("TurboBoostUnlockStatus.Possible => Notice(", detectedStart, StringComparison.Ordinal);
        Assert.IsTrue(detectedStart >= 0 && possibleStart > detectedStart);
        StringAssert.Contains(turbo[detectedStart..possibleStart], "InfoBarSeverity.Warning");

        int notDetectedStart = turbo.IndexOf("TurboBoostUnlockStatus.NotDetected => Notice(", StringComparison.Ordinal);
        int fallbackStart = turbo.IndexOf("_ => Notice(", notDetectedStart, StringComparison.Ordinal);
        Assert.IsTrue(notDetectedStart >= 0 && fallbackStart > notDetectedStart);
        StringAssert.Contains(turbo[notDetectedStart..fallbackStart], "InfoBarSeverity.Warning");
    }

    [TestMethod]
    public void ThemeChangesReapplyWindowIconAndSettingsControlsAreNamedForAutomation()
    {
        string mainPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string main = File.ReadAllText(mainPath);
        StringAssert.Contains(main, "AppWindow.SetIcon(MaterializeWindowIcon())");
        StringAssert.Contains(main, "GetManifestResourceStream(\"XeonV3Control.window-icon\")");
        StringAssert.Contains(main, "temporary.WindowIconPath");

        string settingsPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "SettingsView.cs");
        string settings = File.ReadAllText(settingsPath);
        StringAssert.Contains(settings, "AutomationProperties.SetName(LanguageComboBox, text[\"LanguageSetting\"])");
        StringAssert.Contains(settings, "AutomationProperties.SetName(ThemeComboBox, text[\"ThemeSetting\"])");
        StringAssert.Contains(settings, "Root.RequestedTheme = ElementThemeFor(theme);");
        StringAssert.Contains(settings, "ApplyWindowIcon();");

        string projectPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "XeonV3Control.App.csproj");
        string project = File.ReadAllText(projectPath);
        StringAssert.Contains(project, "EmbeddedResource Include=\"Assets/XeonV3Control.ico\" LogicalName=\"XeonV3Control.window-icon\"");
    }

    [TestMethod]
    public void NavigationRestoresPageScrollAndShowsCompactImageContext()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string source = File.ReadAllText(path);
        StringAssert.Contains(source, "pageScrollOffsets[currentPage] = ContentScroller.VerticalOffset;");
        StringAssert.Contains(source, "pageScrollOffsets.TryGetValue(page, out double savedOffset)");
        StringAssert.Contains(source, "CurrentImageContextLabel.Visibility = hasImage && !expanded");
        StringAssert.Contains(source, "pageScrollOffsets.Clear();");

        string xamlPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml");
        string xaml = File.ReadAllText(xamlPath);
        StringAssert.Contains(xaml, "x:Name=\"CurrentImageContextLabel\"");
        StringAssert.Contains(xaml, "TextTrimming=\"CharacterEllipsis\"");
    }

    [TestMethod]
    public void DriverDetailsAndFirmwareVolumesAreProgressivelyDiscoverable()
    {
        string driversPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "DriversView.cs");
        string drivers = File.ReadAllText(driversPath);
        StringAssert.Contains(drivers, "Content = text[\"ShowDetails\"]");
        StringAssert.Contains(drivers, "details.Visibility = expand ? Visibility.Visible : Visibility.Collapsed;");
        StringAssert.Contains(drivers, "AddDriverExtendedDetails(details, driver);");

        string mainPath = RepositoryTestFiles.Find("src", "XeonV3Control.App", "MainWindow.xaml.cs");
        string main = File.ReadAllText(mainPath);
        StringAssert.Contains(main, "AddFirmwareVolumePager(volumes, image.Volumes);");
        StringAssert.Contains(main, "FirmwareVolumeDisplayProgress");
        StringAssert.Contains(main, "ShowMoreFirmwareVolumes");
    }

}

