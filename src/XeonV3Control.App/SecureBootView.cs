using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private static StackPanel IconText(string glyph, string caption)
    {
        var panel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutInlineIconSpacing)
        };
        panel.Children.Add(new FontIcon
        {
            Glyph = glyph,
            FontSize = UiResources.Get<double>(UiResourceKeys.LayoutInlineIconFontSize)
        });
        panel.Children.Add(new TextBlock { Text = caption });
        return panel;
    }

    private void DecorateButtons()
    {
        OpenButton.Content = IconText(UiGlyphs.OpenFile, text["Open"]);
        ReadButton.Content = IconText(UiGlyphs.ReadFirmware, text["Read"]);
        CancelButton.Content = IconText(UiGlyphs.Cancel, text["Cancel"]);
        ToolTipService.SetToolTip(OpenButton, text["FileTip"]);
        ToolTipService.SetToolTip(ReadButton, text["ReadTip"]);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(OpenButton, text["Open"]);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(ReadButton, text["Read"]);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(CancelButton, text["Cancel"]);
    }

    private void ShowSecureBootOverview(SecureBootReport report)
    {
        StackPanel card = Card(Results, text["SecureBootSummary"]);
        var noticeHost = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutNoticeStackSpacing)
        };
        AddSecureBootNotices(
            noticeHost,
            report,
            includeMissingCertificates: false,
            includeUpdateBlocked: false);
        card.Children.Add(noticeHost);

        int expectedModern = SecureBootInspector.Catalog.Count(certificate => certificate.Modern);
        int presentModern = Math.Max(0, expectedModern - report.Missing2023.Count);
        var metrics = new Grid
        {
            ColumnSpacing = UiResources.Get<double>(UiResourceKeys.LayoutSecureBootMetricsColumnSpacing)
        };
        metrics.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        metrics.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        metrics.Children.Add(Metric(text["Certificates"], report.Certificates.Count.ToString(text.Culture)));
        FrameworkElement modern = Metric(text["Microsoft2023"],
            string.Format(text.Culture, text["CountRatioFormat"], presentModern, expectedModern));
        Grid.SetColumn(modern, 1);
        metrics.Children.Add(modern);
        card.Children.Add(metrics);

        var detailsButton = new Button
        {
            Content = IconText(UiGlyphs.Navigate, text["OpenSecureBoot"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        detailsButton.Click += ShowSecureBootPage;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(detailsButton, text["OpenSecureBoot"]);
        card.Children.Add(detailsButton);
    }

    private void AddSecureBootNotices(
        StackPanel host,
        SecureBootReport report,
        bool includeMissingCertificates,
        bool includeUpdateBlocked)
    {
        foreach (SecureBootNoticeItem notice in BuildSecureBootNotices(
                     report,
                     includeMissingCertificates,
                     includeUpdateBlocked))
        {
            host.Children.Add(CreateSecureBootNotice(notice));
        }
    }

    private IReadOnlyList<SecureBootNoticeItem> BuildSecureBootNotices(
        SecureBootReport report,
        bool includeMissingCertificates,
        bool includeUpdateBlocked)
    {
        var notices = new List<SecureBootNoticeItem>();

        if (report.Certificates.Count == 0)
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeUnknownTitle"],
                text["CertUnknown"],
                InfoBarSeverity.Informational));
        }
        else
        {
            if (report.HasLegacy)
            {
                notices.Add(new SecureBootNoticeItem(
                    text["CertNoticeLegacyTitle"],
                    text["CertLegacy"],
                    InfoBarSeverity.Warning));
            }

            if (report.Missing2023.Count > 0)
            {
                string message = text["CertMissing"];
                if (includeMissingCertificates)
                {
                    string missing = string.Join(Environment.NewLine, report.Missing2023.Select(certificate =>
                        string.Format(text.Culture, text["InlinePairFormat"], certificate.Role, certificate.DisplayName)));
                    message = string.Join(
                        Environment.NewLine,
                        message,
                        text["CertMissingNames"],
                        missing);
                }

                notices.Add(new SecureBootNoticeItem(
                    text["CertNoticeMissingTitle"],
                    message,
                    InfoBarSeverity.Warning));
            }

            if (!report.HasLegacy && report.Missing2023.Count == 0 && !report.HasDangerousCertificate)
            {
                notices.Add(new SecureBootNoticeItem(
                    text["CertNoticeModernTitle"],
                    text["CertModern"],
                    InfoBarSeverity.Success));
            }
        }

        if (report.HasTestKey)
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeTestKeyTitle"],
                text["CertTestKey"],
                InfoBarSeverity.Warning));
        }
        if (report.HasDangerousNonTestCertificate)
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeDangerousTitle"],
                text["CertDangerous"],
                InfoBarSeverity.Warning));
        }
        if (report.Incomplete)
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeIncompleteTitle"],
                text["CertIncomplete"],
                InfoBarSeverity.Warning));
        }
        if (report.HasCertificateIntegrityFailure)
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeIntegrityTitle"],
                text["CertIntegrityWarning"],
                InfoBarSeverity.Error));
        }
        if (report.HasCertificateCryptographicWarning)
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeCryptoTitle"],
                text["CertCryptoWarning"],
                InfoBarSeverity.Warning));
        }

        bool maintenanceRequired = report.Missing2023.Count > 0 || report.HasLegacy || report.HasDangerousCertificate;
        if (includeUpdateBlocked && maintenanceRequired && !SecureBootMutationPolicy.CanModify(report))
        {
            notices.Add(new SecureBootNoticeItem(
                text["CertNoticeUpdateBlockedTitle"],
                text["CertUpdateBlocked"],
                InfoBarSeverity.Warning));
        }

        return notices
            .DistinctBy(notice => (notice.Title, notice.Message, notice.Severity))
            .ToArray();
    }

    private InfoBar CreateSecureBootNotice(SecureBootNoticeItem notice)
    {
        var bar = new InfoBar
        {
            IsOpen = true,
            IsClosable = false,
            Title = notice.Title,
            Message = notice.Message,
            Severity = notice.Severity
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            bar,
            AccessibleNoticeName(notice.Title, notice.Message));
        return bar;
    }

    private sealed record SecureBootNoticeItem(string Title, string Message, InfoBarSeverity Severity);

    private static Brush? SemanticBrush(InfoBarSeverity severity)
    {
        string resource = severity switch
        {
            InfoBarSeverity.Success => UiResourceKeys.SemanticSuccessBrush,
            InfoBarSeverity.Warning => UiResourceKeys.SemanticWarningBrush,
            InfoBarSeverity.Error => UiResourceKeys.SemanticErrorBrush,
            _ => UiResourceKeys.SemanticInformationBrush
        };
        return Application.Current.Resources.TryGetValue(resource, out object? value) ? value as Brush : null;
    }

    private static Brush? SemanticBackgroundBrush(InfoBarSeverity severity)
    {
        string resource = severity switch
        {
            InfoBarSeverity.Success => UiResourceKeys.SemanticSuccessBackgroundBrush,
            InfoBarSeverity.Warning => UiResourceKeys.SemanticWarningBackgroundBrush,
            InfoBarSeverity.Error => UiResourceKeys.SemanticErrorBackgroundBrush,
            _ => UiResourceKeys.SemanticInformationBackgroundBrush
        };
        return Application.Current.Resources.TryGetValue(resource, out object? value) ? value as Brush : null;
    }

    private static Grid Metric(string name, string value)
    {
        var panel = new StackPanel { Spacing = UiResources.Get<double>(UiResourceKeys.LayoutMetricSpacing) };
        TextBlock caption = Label(name);
        caption.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutMetricCaptionOpacity);
        panel.Children.Add(caption);
        panel.Children.Add(new TextBlock
        {
            Text = value,
            FontSize = UiResources.Get<double>(UiResourceKeys.LayoutMetricValueFontSize),
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            IsTextSelectionEnabled = true
        });
        var host = new Grid();
        host.Children.Add(panel);
        return host;
    }

    private void ShowSecureBootDetails(SecureBootReport report, bool managedLayoutAvailable)
    {
        SecureBootIssueHost.Children.Clear();
        AddSecureBootNotices(
            SecureBootIssueHost,
            report,
            includeMissingCertificates: true,
            includeUpdateBlocked: true);

        StackPanel card = Card(SecureBootResults, text["SecureBootStatus"]);
        card.Children.Add(Label(text["CertScope"]));

        bool maintenanceRequired = report.Missing2023.Count > 0 || report.HasLegacy || report.HasDangerousCertificate;
        bool mutationBlocked = !SecureBootMutationPolicy.CanModify(report);
        if (managedLayoutAvailable && maintenanceRequired && !mutationBlocked)
        {
            var repairButton = new Button
            {
                Content = IconText(UiGlyphs.UpdateCertificate, text["CertUpdate"]),
                HorizontalAlignment = HorizontalAlignment.Left,
                Style = UiResources.Get<Style>(UiResourceKeys.PrimaryActionButtonStyle)
            };
            ToolTipService.SetToolTip(repairButton, text["CertUpdateHint"]);
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(repairButton, text["CertUpdate"]);
            repairButton.Click += RepairSecureBoot;
            card.Children.Add(repairButton);
        }

        var list = new StackPanel { Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateListSpacing) };
        DateTime now = DateTime.UtcNow;
        foreach (FirmwareCertificate certificate in report.Certificates)
        {
            string dateState = certificate.NotBeforeUtc > now ? text["CertNotYetValid"] :
                certificate.ExpiresUtc <= now ? text["CertExpired"] :
                certificate.ExpiresUtc <= now.AddMonths(SecureBootCertificatePolicy.ExpiryWarningMonths)
                    ? string.Format(text.Culture, text["CertExpiresSoonFormat"], SecureBootCertificatePolicy.ExpiryWarningMonths)
                    : text["CertValidDate"];
            string verification = CertificateVerificationText(certificate);
            string keyInfo = string.Format(text.Culture, text["CertKeyInfo"], certificate.PublicKeyAlgorithm,
                certificate.PublicKeyBits, certificate.SignatureAlgorithm);
            if (!certificate.StrongPublicKey)
            {
                keyInfo = string.Format(text.Culture, text["InlinePairFormat"], keyInfo, text["CertWeakKey"]);
            }
            keyInfo = certificate.SignatureAlgorithmStatus switch
            {
                CertificateSignatureAlgorithmStatus.Weak => string.Format(
                    text.Culture, text["InlinePairFormat"], keyInfo, text["CertWeakSignatureAlgorithm"]),
                CertificateSignatureAlgorithmStatus.Unsupported => string.Format(
                    text.Culture, text["InlinePairFormat"], keyInfo, text["CertUnsupportedSignatureAlgorithm"]),
                _ => keyInfo
            };

            list.Children.Add(CertificateItem(certificate, dateState, verification, keyInfo, now));
        }

        if (report.InvalidCertificateCount > 0)
        {
            TextBlock invalidCount = Label(string.Format(
                text.Culture,
                text["CertInvalidCount"],
                report.InvalidCertificateCount));
            invalidCount.Foreground = SemanticBrush(InfoBarSeverity.Error);
            list.Children.Add(invalidCount);
        }

        card.Children.Add(new Expander
        {
            Header = Label(string.Format(text.Culture, text["CountTitleFormat"],
                text["CertDetails"], report.Certificates.Count)),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Content = list
        });
    }

    private FrameworkElement CertificateItem(
        FirmwareCertificate certificate,
        string dateState,
        string verification,
        string keyInfo,
        DateTime now)
    {
        InfoBarSeverity? severity = CertificateSeverity(certificate, now);
        var content = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
        };
        content.Children.Add(new TextBlock
        {
            Text = certificate.Name,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true
        });
        content.Children.Add(Label(string.Format(
            text.Culture,
            text["CertificateDetailsFormat"],
            dateState,
            certificate.ExpiresUtc,
            verification,
            keyInfo,
            certificate.Sha256,
            certificate.Location)));

        var border = new Border
        {
            Child = content,
            Padding = UiResources.Get<Thickness>(UiResourceKeys.LayoutCertificateItemPadding),
            BorderThickness = UiResources.Get<Thickness>(UiResourceKeys.LayoutCertificateItemBorderThickness),
            CornerRadius = UiResources.Get<CornerRadius>(UiResourceKeys.LayoutCertificateItemCornerRadius),
            BorderBrush = UiResources.Get<Brush>(UiResourceKeys.CardStrokeBrush),
            Background = UiResources.Get<Brush>(UiResourceKeys.ControlFillBrush)
        };
        if (severity is InfoBarSeverity warningSeverity)
        {
            border.BorderBrush = SemanticBrush(warningSeverity);
            border.Background = SemanticBackgroundBrush(warningSeverity);
        }
        return border;
    }

    private static InfoBarSeverity? CertificateSeverity(FirmwareCertificate certificate, DateTime now)
    {
        if (certificate.SignatureStatus == CertificateSignatureStatus.Invalid)
        {
            return InfoBarSeverity.Error;
        }
        if (certificate.Dangerous || !certificate.StrongPublicKey ||
            certificate.SignatureAlgorithmStatus != CertificateSignatureAlgorithmStatus.Strong ||
            certificate.NotBeforeUtc > now || certificate.ExpiresUtc <= now ||
            certificate.ExpiresUtc <= now.AddMonths(SecureBootCertificatePolicy.ExpiryWarningMonths))
        {
            return InfoBarSeverity.Warning;
        }
        return null;
    }

    private string CertificateVerificationText(FirmwareCertificate certificate)
    {
        if (certificate.OfficialMicrosoft)
        {
            return text["CertReferenceVerified"];
        }

        return certificate.SignatureStatus switch
        {
            CertificateSignatureStatus.Verified => text["CertSelfSignatureVerified"],
            CertificateSignatureStatus.Invalid => text["CertSignatureInvalid"],
            CertificateSignatureStatus.UnsupportedAlgorithm => text["CertSignatureUnsupported"],
            _ => text["CertIssuerUnavailable"]
        };
    }


    private async void RepairSecureBoot(object sender, RoutedEventArgs args)
    {
        try
        {
            if (operation is not null || activeImage is null)
            {
                return;
            }
            string target = temporary.NewBiosPath(TemporaryBiosArtifact.SecureBootRepair);
            BiosImage sourceImage = activeImage;
            await RunOperation(async token =>
            {
                BiosImage updatedImage = await Task.Run(async () =>
                {
                    await SecureBootImageUpdater.UpdateFileAsync(sourceImage.FilePath, target, token)
                        .ConfigureAwait(false);
                    return await BiosImageLoader.LoadValidatedAsync(target, token)
                        .ConfigureAwait(false);
                }, token);
                ShowImage(updatedImage, ImageSourceKind.UpdatedImage, WorkspacePage.SecureBoot);
                SetNotice(
                    SecureBootNoticeBar,
                    text["CertUpdated"],
                    text["CertUpdateCompleted"],
                    InfoBarSeverity.Success);
            }, UiOperationKind.UpdatingCertificates);
        }
        catch (Exception error)
        {
            ShowOperationError(UiOperationKind.UpdatingCertificates, error);
        }
    }


    private void AnimateResults()
    {
        if (!new Windows.UI.ViewManagement.UISettings().AnimationsEnabled)
        {
            return;
        }
        var fade = new DoubleAnimation
        {
            From = 0,
            To = 1,
            Duration = new Duration(TimeSpan.FromMilliseconds(UiDesign.ResultFadeDurationMilliseconds))
        };
        Storyboard.SetTarget(fade, Results);
        Storyboard.SetTargetProperty(fade, "Opacity");
        var storyboard = new Storyboard();
        storyboard.Children.Add(fade);
        storyboard.Begin();
    }
}
