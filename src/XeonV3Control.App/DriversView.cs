using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private static readonly char[] DriverSearchSeparators = [' ', '\t', '\r', '\n', ',', ';'];
    private UefiDriverReport? renderedDriverReport;
    private string driverSearchQuery = string.Empty;

    private void ShowDriverOverview(UefiDriverReport report)
    {
        StackPanel card = Card(Results, text["UefiDriversSummary"]);
        var notices = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutNoticeStackSpacing)
        };
        AddDriverNotices(notices, report);
        card.Children.Add(notices);
        card.Children.Add(DriverMetrics(report));

        var detailsButton = new Button
        {
            Content = IconText(UiGlyphs.Navigate, text["OpenUefiDrivers"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        detailsButton.Click += ShowDriversPage;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(detailsButton, text["OpenUefiDrivers"]);
        card.Children.Add(detailsButton);
    }

    private void ShowDriverDetails(UefiDriverReport report)
    {
        if (!ReferenceEquals(renderedDriverReport, report))
        {
            renderedDriverReport = report;
            driverSearchQuery = string.Empty;
        }

        StackPanel summary = Card(DriversResults, text["UefiDriversSummary"]);
        AddDriverNotices(summary, report);
        summary.Children.Add(DriverMetrics(report));
        summary.Children.Add(Notice(string.Empty, text["UefiDriverScope"], InfoBarSeverity.Informational));

        if (activeImage is BiosImage image)
        {
            ShowX99DriverUpdates(image.X99UefiDriverUpdates, report.Drivers.Count);
        }

        UefiDriverInfo[] attention = report.Drivers
            .Where(driver => driver.SecurityStatus != UefiDriverSecurityStatus.NoKnownIssues)
            .OrderBy(driver => DriverStatusRank(driver.SecurityStatus))
            .ThenBy(driver => DriverDisplayName(driver), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (attention.Length > 0)
        {
            StackPanel attentionCard = Card(DriversResults, string.Format(
                text.Culture,
                text["CountTitleFormat"],
                text["UefiDriverAttention"],
                attention.Length));
            foreach (UefiDriverInfo driver in attention)
            {
                attentionCard.Children.Add(DriverItem(driver, compact: false));
            }
        }

        StackPanel inventory = Card(DriversResults, text["UefiDriverInventory"]);
        if (report.Drivers.Count == 0)
        {
            inventory.Children.Add(Label(text["UefiDriverNoDrivers"]));
            return;
        }

        var search = new AutoSuggestBox
        {
            PlaceholderText = text["UefiDriverSearchPlaceholder"],
            QueryIcon = new FontIcon { Glyph = UiGlyphs.Search },
            Text = driverSearchQuery,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(search, text["UefiDriverSearchPlaceholder"]);
        inventory.Children.Add(search);

        TextBlock resultCount = Label(string.Empty);
        resultCount.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutSecondaryTextOpacity);
        inventory.Children.Add(resultCount);

        var items = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateListSpacing)
        };
        inventory.Children.Add(items);

        RenderDriverInventory(report, driverSearchQuery, resultCount, items);
        search.TextChanged += (_, _) =>
        {
            driverSearchQuery = search.Text?.Trim() ?? string.Empty;
            RenderDriverInventory(report, driverSearchQuery, resultCount, items);
        };
    }

    private void ShowX99DriverUpdates(IReadOnlyList<X99UefiDriverUpdatePlan> plans, int detectedDriverCount)
    {
        StackPanel card = Card(DriversResults, text["UefiDriverUpdatesTitle"]);
        int ready = plans.Count(plan => plan.Disposition == X99UefiDriverUpdateDisposition.Ready);
        int current = plans.Count(plan => plan.Disposition == X99UefiDriverUpdateDisposition.UpToDate);
        int review = plans.Count(plan => plan.Disposition == X99UefiDriverUpdateDisposition.RequiresReview);
        int blocked = plans.Count - ready - current - review;
        card.Children.Add(Label(string.Format(
            text.Culture,
            text["UefiDriverUpdatesInventorySummary"],
            detectedDriverCount,
            plans.Count)));
        card.Children.Add(Label(string.Format(
            text.Culture,
            text["UefiDriverUpdatesSummary"],
            ready,
            current,
            review,
            blocked)));

        foreach (X99UefiDriverUpdatePlan plan in plans
            .OrderBy(X99DriverUpdateDisplayRank)
            .ThenBy(plan => plan.Component, StringComparer.OrdinalIgnoreCase)
            .ThenBy(plan => plan.Target.FileOffset))
        {
            var item = new StackPanel
            {
                Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
            };
            item.Children.Add(new TextBlock
            {
                Text = plan.Component,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true
            });
            AddRow(item, text["Status"], text["UefiDriverUpdateDisposition" + plan.Disposition]);
            if (!string.IsNullOrWhiteSpace(plan.Branch))
            {
                AddRow(item, text["UefiDriverUpdateBranch"], plan.Branch);
            }
            if (!string.IsNullOrWhiteSpace(plan.CurrentVersion))
            {
                AddRow(item, text["UefiDriverUpdateCurrentVersion"], plan.CurrentVersion);
            }
            if (!string.IsNullOrWhiteSpace(plan.CandidateVersion))
            {
                AddRow(item, text["UefiDriverUpdateCandidateVersion"], plan.CandidateVersion);
            }
            if (plan.Disposition == X99UefiDriverUpdateDisposition.Ready ||
                plan.MutationStrategy != UefiFirmwareVolumeMutationStrategy.Unsupported)
            {
                AddRow(item, text["UefiDriverUpdateMutation"],
                    text["UefiDriverUpdateMutation" + plan.MutationStrategy]);
            }
            string reasons = string.Join(text["InlineListSeparator"], plan.Reasons
                .Where(reason => reason != X99UefiDriverUpdateReason.None)
                .Select(X99DriverUpdateReasonText));
            if (!string.IsNullOrWhiteSpace(reasons))
            {
                AddRow(item, text["UefiDriverUpdateReason"], reasons);
            }
            item.Children.Add(CreateX99DriverUpdateButton(plan));

            card.Children.Add(new Border
            {
                Child = item,
                Style = UiResources.Get<Style>(UiResourceKeys.UefiDriverBorderStyle)
            });
        }
    }


    private static int X99DriverUpdateDisplayRank(X99UefiDriverUpdatePlan plan) => plan.Disposition switch
    {
        X99UefiDriverUpdateDisposition.Ready => 0,
        X99UefiDriverUpdateDisposition.UpToDate => 1,
        X99UefiDriverUpdateDisposition.RequiresReview => 2,
        X99UefiDriverUpdateDisposition.Blocked => 3,
        _ => 4
    };

    private Button CreateX99DriverUpdateButton(X99UefiDriverUpdatePlan plan)
    {
        string label = plan.Disposition switch
        {
            X99UefiDriverUpdateDisposition.Ready => text["UefiDriverUpdateButton"],
            X99UefiDriverUpdateDisposition.UpToDate => text["UefiDriverUpdateCurrentButton"],
            _ => text["UefiDriverUpdateUnavailableButton"]
        };
        var button = new Button
        {
            Content = label,
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = plan.CanApply,
            Tag = plan
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, label);
        if (plan.CanApply)
        {
            button.Click += UpdateX99UefiDriver;
        }
        return button;
    }

    private async void UpdateX99UefiDriver(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: X99UefiDriverUpdatePlan plan } ||
            !plan.CanApply ||
            operation is not null ||
            activeImage is not BiosImage sourceImage)
        {
            return;
        }

        string destination = temporary.NewBiosPath(TemporaryBiosArtifact.UefiDriverUpdate);
        await RunOperation(async token =>
        {
            BiosImage updated = await Task.Run(
                () => X99UefiDriverImageUpdater.ApplyFileAsync(
                    sourceImage.FilePath,
                    destination,
                    plan,
                    token),
                token);
            ShowImage(updated, ImageSourceKind.UpdatedImage, WorkspacePage.Drivers);
            ShowOperationNotice(
                UiOperationKind.UpdatingUefiDriver,
                text["UefiDriverUpdateCompletedTitle"],
                string.Format(
                    text.Culture,
                    text["UefiDriverUpdateCompletedMessage"],
                    plan.Component,
                    plan.CandidateVersion ?? text["NotAvailable"],
                    updated.Sha256),
                InfoBarSeverity.Success);
        }, UiOperationKind.UpdatingUefiDriver);
    }

    private string X99DriverUpdateReasonText(string reason)
    {
        string key = "UefiDriverUpdateReason" + reason;
        return text.Keys.Contains(key) ? text[key] : reason;
    }

    private void RenderDriverInventory(
        UefiDriverReport report,
        string query,
        TextBlock resultCount,
        StackPanel items)
    {
        items.Children.Clear();
        UefiDriverInfo[] matches = report.Drivers
            .Where(driver => DriverMatchesSearch(driver, query))
            .OrderBy(driver => DriverDisplayName(driver), StringComparer.OrdinalIgnoreCase)
            .ThenBy(driver => driver.FileGuid)
            .ThenBy(driver => driver.FileOffset)
            .ToArray();

        resultCount.Text = string.Format(
            text.Culture,
            text["UefiDriverSearchResults"],
            matches.Length,
            report.Drivers.Count);
        if (matches.Length == 0)
        {
            items.Children.Add(Label(text["UefiDriverSearchNoResults"]));
            return;
        }

        bool showFullDetails = !string.IsNullOrWhiteSpace(query) &&
            matches.Length <= UiDesign.MaximumExpandedUefiDriverSearchResults;
        int count = Math.Min(matches.Length, UiDesign.MaximumDisplayedUefiDrivers);
        for (int index = 0; index < count; index++)
        {
            items.Children.Add(DriverItem(matches[index], compact: !showFullDetails));
        }
        if (matches.Length > count)
        {
            items.Children.Add(Label(string.Format(
                text.Culture,
                text["UefiDriverDisplayLimit"],
                count,
                matches.Length)));
        }
    }

    private bool DriverMatchesSearch(UefiDriverInfo driver, string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return true;
        }

        string document = DriverSearchDocument(driver);
        string[] terms = query.Split(
            DriverSearchSeparators,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return terms.Length == 0 || terms.All(term =>
            document.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    private string DriverSearchDocument(UefiDriverInfo driver)
    {
        IEnumerable<string> executableFields = driver.Executables.SelectMany(executable => new[]
        {
            executable.Format.ToString(),
            text["UefiExecutableFormat" + executable.Format],
            executable.Machine.ToString(),
            text["UefiMachine" + executable.Machine],
            executable.Subsystem.ToString(),
            text["UefiSubsystem" + executable.Subsystem],
            executable.Sha256,
            executable.ImageSize.ToString(CultureInfo.InvariantCulture),
            executable.SectionCount.ToString(CultureInfo.InvariantCulture)
        });

        IEnumerable<string> fields = new[]
        {
            DriverDisplayName(driver),
            driver.FileGuid.ToString(),
            driver.Sha256,
            driver.Kind.ToString(),
            DriverKindText(driver.Kind),
            driver.SecurityStatus.ToString(),
            DriverStatusText(driver.SecurityStatus),
            driver.Version ?? string.Empty,
            driver.BuildNumber?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            driver.VolumeOffset.ToString("X", CultureInfo.InvariantCulture),
            driver.VolumeFileSystem.ToString(),
            driver.FileOffset.ToString("X", CultureInfo.InvariantCulture),
            driver.FileSize.ToString(CultureInfo.InvariantCulture),
            driver.FfsType.ToString("X2", CultureInfo.InvariantCulture),
            driver.FfsAttributes.ToString("X2", CultureInfo.InvariantCulture),
            driver.RequiredDataAlignment.ToString(CultureInfo.InvariantCulture),
            driver.FixedLocation.ToString(),
            driver.SectionCount.ToString(CultureInfo.InvariantCulture),
            driver.CompressionSectionCount.ToString(CultureInfo.InvariantCulture),
            driver.GuidedSectionCount.ToString(CultureInfo.InvariantCulture),
            driver.DependencySectionCount.ToString(CultureInfo.InvariantCulture)
        }
        .Concat(driver.DependencySha256)
        .Concat(driver.VulnerabilityIds)
        .Concat(driver.Issues)
        .Concat(driver.Issues.Select(DriverIssueText))
        .Concat(executableFields);
        return string.Join("\n", fields);
    }

    private void AddDriverNotices(StackPanel host, UefiDriverReport report)
    {
        int vulnerable = report.Drivers.Count(driver => driver.SecurityStatus == UefiDriverSecurityStatus.KnownVulnerable);
        int review = report.Drivers.Count(driver => driver.SecurityStatus == UefiDriverSecurityStatus.ReviewRecommended);
        int unknown = report.Drivers.Count(driver => driver.SecurityStatus == UefiDriverSecurityStatus.Unknown);

        if (report.Drivers.Count == 0)
        {
            host.Children.Add(Notice(text["UefiDriverNoDriversTitle"], text["UefiDriverNoDrivers"],
                InfoBarSeverity.Informational));
            return;
        }
        if (vulnerable > 0)
        {
            host.Children.Add(Notice(
                text["UefiDriverKnownVulnerableNoticeTitle"],
                string.Format(text.Culture, text["UefiDriverKnownVulnerableNotice"], vulnerable),
                InfoBarSeverity.Error));
        }
        if (review > 0)
        {
            host.Children.Add(Notice(
                text["UefiDriverReviewNoticeTitle"],
                string.Format(text.Culture, text["UefiDriverReviewNotice"], review),
                InfoBarSeverity.Warning));
        }
        if (unknown > 0 || report.Incomplete)
        {
            host.Children.Add(Notice(
                text["UefiDriverUnknownNoticeTitle"],
                string.Format(text.Culture, text["UefiDriverUnknownNotice"], unknown),
                InfoBarSeverity.Warning));
        }
        if (vulnerable == 0 && review == 0 && unknown == 0 && !report.Incomplete)
        {
            host.Children.Add(Notice(
                text["UefiDriverNoKnownIssuesNoticeTitle"],
                text["UefiDriverNoKnownIssuesNotice"],
                InfoBarSeverity.Success));
        }
    }

    private Grid DriverMetrics(UefiDriverReport report)
    {
        int noKnownIssues = report.Drivers.Count(driver => driver.SecurityStatus == UefiDriverSecurityStatus.NoKnownIssues);
        int attention = report.Drivers.Count - noKnownIssues;
        var grid = new Grid
        {
            ColumnSpacing = UiResources.Get<double>(UiResourceKeys.LayoutSecureBootMetricsColumnSpacing),
            RowSpacing = UiResources.Get<double>(UiResourceKeys.LayoutSecureBootMetricsColumnSpacing)
        };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        FrameworkElement total = Metric(text["UefiDrivers"], report.Drivers.Count.ToString(text.Culture));
        FrameworkElement clean = Metric(text["UefiDriverStatusNoKnownIssues"], noKnownIssues.ToString(text.Culture));
        FrameworkElement attentionMetric = Metric(text["UefiDriverAttention"], attention.ToString(text.Culture));
        FrameworkElement unknown = Metric(text["UefiDriverStatusUnknown"],
            report.Drivers.Count(driver => driver.SecurityStatus == UefiDriverSecurityStatus.Unknown).ToString(text.Culture));
        Grid.SetColumn(clean, 1);
        Grid.SetRow(attentionMetric, 1);
        Grid.SetRow(unknown, 1);
        Grid.SetColumn(unknown, 1);
        grid.Children.Add(total);
        grid.Children.Add(clean);
        grid.Children.Add(attentionMetric);
        grid.Children.Add(unknown);
        return grid;
    }

    private FrameworkElement DriverItem(UefiDriverInfo driver, bool compact)
    {
        var content = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
        };
        content.Children.Add(new TextBlock
        {
            Text = DriverDisplayName(driver),
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true
        });

        var status = new TextBlock
        {
            Text = string.Format(
                text.Culture,
                text["UefiDriverHeaderFormat"],
                DriverKindText(driver.Kind),
                DriverStatusText(driver.SecurityStatus),
                driver.FileSize),
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            Style = UiResources.Get<Style>(DriverStatusStyleKey(driver.SecurityStatus))
        };
        content.Children.Add(status);
        content.Children.Add(Label(string.Format(
            text.Culture,
            text["UefiDriverIdentityFormat"],
            driver.FileGuid,
            driver.VolumeOffset,
            driver.FileOffset,
            driver.Sha256)));

        if (!string.IsNullOrWhiteSpace(driver.Version) || driver.BuildNumber.HasValue)
        {
            AddRow(content, text["Version"], string.Format(
                text.Culture,
                text["UefiDriverVersionFormat"],
                string.IsNullOrWhiteSpace(driver.Version) ? text["NotApplicable"] : driver.Version,
                driver.BuildNumber?.ToString(text.Culture) ?? text["NotApplicable"]));
        }
        AddRow(content, text["UefiDriverFirmwareVolume"], string.Format(
            text.Culture,
            text["UefiDriverVolumeFormat"],
            driver.VolumeOffset,
            driver.VolumeFileSystem));
        AddRow(content, text["UefiDriverFfs"], string.Format(
            text.Culture,
            text["UefiDriverFfsFormat"],
            driver.FfsType,
            driver.FfsAttributes,
            driver.FfsHeaderSize,
            driver.RequiredDataAlignment,
            driver.FixedLocation ? text["Yes"] : text["No"]));
        AddRow(content, text["UefiDriverSections"], string.Format(
            text.Culture,
            text["UefiDriverSectionsFormat"],
            driver.SectionCount,
            driver.CompressionSectionCount,
            driver.GuidedSectionCount,
            driver.DependencySectionCount));

        if (driver.Executables.Count > 0)
        {
            string machines = string.Join(text["InlineListSeparator"], driver.Executables
                .Select(executable => text["UefiMachine" + executable.Machine])
                .Distinct(StringComparer.Ordinal));
            string subsystems = string.Join(text["InlineListSeparator"], driver.Executables
                .Select(executable => text["UefiSubsystem" + executable.Subsystem])
                .Distinct(StringComparer.Ordinal));
            AddRow(content, text["UefiDriverExecutables"], string.Format(
                text.Culture,
                text["UefiDriverExecutableOverviewFormat"],
                driver.Executables.Count,
                machines,
                subsystems));
        }

        if (compact)
        {
            var details = new StackPanel
            {
                Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing),
                Visibility = Visibility.Collapsed
            };
            AddDriverExtendedDetails(details, driver);

            var detailsButton = new Button
            {
                Content = text["ShowDetails"],
                HorizontalAlignment = HorizontalAlignment.Left
            };
            detailsButton.Click += (_, _) =>
            {
                bool expand = details.Visibility != Visibility.Visible;
                details.Visibility = expand ? Visibility.Visible : Visibility.Collapsed;
                string caption = text[expand ? "HideDetails" : "ShowDetails"];
                detailsButton.Content = caption;
                Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(detailsButton, caption);
            };
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(detailsButton, text["ShowDetails"]);
            if (details.Children.Count > 0)
            {
                content.Children.Add(detailsButton);
                content.Children.Add(details);
            }
        }
        else
        {
            AddDriverExtendedDetails(content, driver);
        }

        return new Border
        {
            Child = content,
            Style = UiResources.Get<Style>(DriverBorderStyleKey(driver.SecurityStatus))
        };
    }

    private void AddDriverExtendedDetails(StackPanel content, UefiDriverInfo driver)
    {
        if (driver.DependencySha256.Count > 0)
        {
            AddRow(content, text["UefiDriverDependencyHashes"],
                string.Join(Environment.NewLine, driver.DependencySha256));
        }
        if (driver.VulnerabilityIds.Count > 0)
        {
            AddRow(content, text["UefiDriverVulnerabilities"],
                string.Join(text["InlineListSeparator"], driver.VulnerabilityIds));
        }
        if (driver.Issues.Count > 0)
        {
            AddRow(content, text["UefiDriverFindings"],
                string.Join(Environment.NewLine, driver.Issues.Select(DriverIssueText)));
        }
        if (driver.Executables.Count > 0)
        {
            AddRow(content, text["UefiDriverExecutableDetails"],
                string.Join(Environment.NewLine + Environment.NewLine,
                    driver.Executables.Select(DriverExecutableText)));
        }
    }

    private string DriverExecutableText(UefiExecutableInfo executable)
    {
        string nx = TriState(executable.NxCompatible);
        string dynamicBase = TriState(executable.DynamicBase);
        return string.Format(
            text.Culture,
            text["UefiDriverExecutableFormat"],
            text["UefiExecutableFormat" + executable.Format],
            text["UefiMachine" + executable.Machine],
            text["UefiSubsystem" + executable.Subsystem],
            executable.ImageSize,
            executable.SectionCount,
            nx,
            dynamicBase,
            executable.WritableExecutableSection ? text["Yes"] : text["No"],
            executable.Sha256);
    }

    private string TriState(bool? value) => value switch
    {
        true => text["Yes"],
        false => text["No"],
        null => text["NotApplicable"]
    };

    private string DriverIssueText(string issue)
    {
        string key = "UefiDriverIssue" + issue;
        return text.Keys.Contains(key) ? text[key] : issue;
    }

    private string DriverKindText(UefiDriverKind kind) => text["UefiDriverKind" + kind];

    private string DriverStatusText(UefiDriverSecurityStatus status) => text["UefiDriverStatus" + status];

    private string DriverDisplayName(UefiDriverInfo driver) =>
        string.IsNullOrWhiteSpace(driver.Name) ? driver.FileGuid.ToString() : driver.Name;

    private static string DriverBorderStyleKey(UefiDriverSecurityStatus status) => status switch
    {
        UefiDriverSecurityStatus.KnownVulnerable => UiResourceKeys.UefiDriverErrorBorderStyle,
        UefiDriverSecurityStatus.ReviewRecommended => UiResourceKeys.UefiDriverWarningBorderStyle,
        UefiDriverSecurityStatus.Unknown => UiResourceKeys.UefiDriverInformationBorderStyle,
        _ => UiResourceKeys.UefiDriverBorderStyle
    };

    private static string DriverStatusStyleKey(UefiDriverSecurityStatus status) => status switch
    {
        UefiDriverSecurityStatus.KnownVulnerable => UiResourceKeys.UefiDriverErrorTextStyle,
        UefiDriverSecurityStatus.ReviewRecommended => UiResourceKeys.UefiDriverWarningTextStyle,
        UefiDriverSecurityStatus.Unknown => UiResourceKeys.UefiDriverInformationTextStyle,
        _ => UiResourceKeys.UefiDriverSuccessTextStyle
    };

    private static int DriverStatusRank(UefiDriverSecurityStatus status) => status switch
    {
        UefiDriverSecurityStatus.KnownVulnerable => 0,
        UefiDriverSecurityStatus.ReviewRecommended => 1,
        UefiDriverSecurityStatus.Unknown => 2,
        _ => 3
    };
}
