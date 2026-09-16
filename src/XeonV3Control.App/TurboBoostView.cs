using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private void ShowTurboBoostOverview(TurboBoostUnlockReport report)
    {
        StackPanel card = Card(Results, text["TurboBoostOverview"]);
        card.Children.Add(TurboBoostStatusNotice(report));
        AddRow(card, text["TurboBoostStatus"], TurboBoostStatusText(report.Status));
        AddRow(card, text["TurboBoostCpuPatchRemovalStatus"], TurboBoostCpuPatchRemovalStatusText(report));
        AddRow(card, text["TurboBoostFindings"], report.Findings.Count.ToString("N0", text.Culture));
        AddRow(card, text["TurboBoostRetainedUnlockModules"], report.RetainedUnlockModules.Count.ToString("N0", text.Culture));
        AddRow(card, text["TurboBoostForeignUnlockModules"], report.ForeignUnlockModules.Count.ToString("N0", text.Culture));
        AddRow(card, text["TurboBoostUnclassifiedUnlockModules"], report.UnclassifiedUnlockModules.Count.ToString("N0", text.Culture));
        AddRow(card, text["TurboBoostCpuPatch306F2"], report.XeonE5V3CpuPatches.Count.ToString("N0", text.Culture));

        var detailsButton = new Button
        {
            Content = IconText(UiGlyphs.Navigate, text["OpenTurboBoost"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        detailsButton.Click += ShowTurboBoostPage;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(detailsButton, text["OpenTurboBoost"]);
        card.Children.Add(detailsButton);
    }

    private void ShowTurboBoostDetails(TurboBoostUnlockReport report)
    {
        StackPanel summary = Card(TurboBoostResults, text["TurboBoostSummary"]);
        summary.Children.Add(TurboBoostStatusNotice(report));
        AddRow(summary, text["TurboBoostStatus"], TurboBoostStatusText(report.Status));
        AddRow(summary, text["TurboBoostCpuPatchRemovalStatus"], TurboBoostCpuPatchRemovalStatusText(report));
        AddRow(summary, text["TurboBoostFindings"], report.Findings.Count.ToString("N0", text.Culture));
        AddRow(summary, text["TurboBoostRetainedUnlockModules"], report.RetainedUnlockModules.Count.ToString("N0", text.Culture));
        AddRow(summary, text["TurboBoostForeignUnlockModules"], report.ForeignUnlockModules.Count.ToString("N0", text.Culture));
        AddRow(summary, text["TurboBoostUnclassifiedUnlockModules"], report.UnclassifiedUnlockModules.Count.ToString("N0", text.Culture));
        AddRow(summary, text["TurboBoostCpuPatch306F2"], report.XeonE5V3CpuPatches.Count.ToString("N0", text.Culture));

        ShowTurboBoostUnlockModules(report);
        ShowTurboBoostCpuPatches(report);
        ShowTurboBoostFindings(report);
    }

    private void ShowTurboBoostUnlockModules(TurboBoostUnlockReport report)
    {
        StackPanel card = Card(TurboBoostResults, string.Format(
            text.Culture,
            text["CountTitleFormat"],
            text["TurboBoostUnlockModulesTitle"],
            report.Modules.Count));

        if (report.ForeignUnlockModules.Count != 0)
        {
            card.Children.Add(Notice(
                text["TurboBoostForeignUnlockWarningTitle"],
                text["TurboBoostForeignUnlockWarningMessage"],
                InfoBarSeverity.Warning));
        }
        else if (report.RetainedUnlockModules.Count != 0)
        {
            card.Children.Add(Notice(
                text["TurboBoostRetainedUnlockTitle"],
                text["TurboBoostRetainedUnlockMessage"],
                InfoBarSeverity.Success));
        }

        if (report.Modules.Count == 0)
        {
            card.Children.Add(Label(text["TurboBoostNoUnlockModules"]));
            return;
        }

        var list = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateListSpacing)
        };
        card.Children.Add(list);
        foreach (TurboBoostUnlockModule module in report.Modules)
        {
            TurboBoostForeignRemovalPlan plan = CurrentTurboBoostForeignRemovalPlan(module);
            var content = new StackPanel
            {
                Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
            };
            string family = module.Families.Count == 0
                ? text["TurboBoostUnknownFamily"]
                : string.Join(text["InlineListSeparator"], module.Families);
            content.Children.Add(new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(module.Name) ? family : $"{module.Name} · {family}",
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true
            });
            AddRow(content, text["TurboBoostUnlockModuleDisposition"], text["TurboBoostUnlockDisposition" + module.Disposition]);
            AddRow(
                content,
                text["TurboBoostUnlockConfidence"],
                module.Verified ? text["TurboBoostUnlockConfidenceVerified"] : text["TurboBoostUnlockConfidenceHeuristic"]);
            content.Children.Add(Label(string.Format(
                text.Culture,
                text["TurboBoostUnlockModuleDetailsFormat"],
                module.FileGuid,
                module.VolumeOffset,
                module.FileOffset,
                module.FileSize,
                module.FfsSha256)));
            AddRow(content, text["TurboBoostForeignRemovalStatus"], TurboBoostForeignRemovalStatusText(module, plan));
            AddRow(content, text["TurboBoostForeignRemovalReason"], TurboBoostForeignRemovalReasonText(module, plan));
            AddRow(content, text["TurboBoostForeignProposedAction"], TurboBoostForeignProposedActionText(module, plan));
            AddRow(content, text["TurboBoostUnlockModuleEvidence"], string.Join(
                text["InlineListSeparator"],
                module.Evidence.Select(TurboBoostEvidenceText)));

            if (module.Disposition == TurboBoostUnlockModuleDisposition.Foreign &&
                plan.CanExecute &&
                plan.Operation == TurboBoostForeignRemovalOperation.RemoveInjectedFfs)
            {
                content.Children.Add(CreateForeignUnlockRemovalButton(plan));
            }

            list.Children.Add(new Border
            {
                Style = UiResources.Get<Style>(UiResourceKeys.UefiDriverBorderStyle),
                Child = content
            });
        }

    }

    private static TurboBoostForeignRemovalPlan CurrentTurboBoostForeignRemovalPlan(
        TurboBoostUnlockModule module) => module.RemovalPlan;

    private static bool PlanTargetsModule(TurboBoostForeignRemovalPlan plan, TurboBoostUnlockModule module) =>
        plan.FileGuid == module.FileGuid &&
        plan.VolumeOffset == module.VolumeOffset &&
        plan.FileOffset == module.FileOffset &&
        plan.FileSize == module.FileSize &&
        string.Equals(plan.FfsSha256, module.FfsSha256, StringComparison.OrdinalIgnoreCase);

    private string TurboBoostForeignRemovalStatusText(
        TurboBoostUnlockModule module,
        TurboBoostForeignRemovalPlan plan) => module.Disposition switch
    {
        TurboBoostUnlockModuleDisposition.Retained => text["TurboBoostForeignRemovalKeep"],
        TurboBoostUnlockModuleDisposition.Unclassified => text["TurboBoostForeignRemovalUnclassified"],
        _ => plan.Status switch
        {
            TurboBoostForeignRemovalStatus.Ready => text["TurboBoostForeignRemovalReady"],
            TurboBoostForeignRemovalStatus.RequiresBaselineByteAuthorization => text["TurboBoostForeignRemovalNeedsByteAuthorization"],
            TurboBoostForeignRemovalStatus.Unsupported => text["TurboBoostForeignRemovalBlocked"],
            _ => text["TurboBoostForeignRemovalBlocked"]
        }
    };

    private string TurboBoostForeignRemovalReasonText(
        TurboBoostUnlockModule module,
        TurboBoostForeignRemovalPlan plan)
    {
        if (module.Disposition == TurboBoostUnlockModuleDisposition.Retained)
        {
            return text["TurboBoostForeignReasonRetainedFamily"];
        }
        if (module.Disposition == TurboBoostUnlockModuleDisposition.Unclassified)
        {
            return plan.Reason == TurboBoostForeignRemovalReason.AmbiguousFamily
                ? text["TurboBoostForeignReasonAmbiguousFamily"]
                : text["TurboBoostForeignReasonUnverifiedCandidate"];
        }

        return plan.Reason switch
        {
            TurboBoostForeignRemovalReason.None => text["TurboBoostForeignReasonNone"],
            TurboBoostForeignRemovalReason.RetainedFamily => text["TurboBoostForeignReasonRetainedFamily"],
            TurboBoostForeignRemovalReason.UnverifiedCandidate => text["TurboBoostForeignReasonUnverifiedCandidate"],
            TurboBoostForeignRemovalReason.AmbiguousFamily => text["TurboBoostForeignReasonAmbiguousFamily"],
            TurboBoostForeignRemovalReason.DriverNotLocated => text["TurboBoostForeignReasonDriverNotLocated"],
            TurboBoostForeignRemovalReason.SourceAnalysisIncomplete => text["TurboBoostForeignReasonSourceAnalysisIncomplete"],
            TurboBoostForeignRemovalReason.BaselineAnalysisIncomplete => text["TurboBoostForeignReasonBaselineAnalysisIncomplete"],
            TurboBoostForeignRemovalReason.BaselineContainsUnlock => text["TurboBoostForeignReasonBaselineContainsUnlock"],
            TurboBoostForeignRemovalReason.BaselineImageMismatch => text["TurboBoostForeignReasonBaselineImageMismatch"],
            TurboBoostForeignRemovalReason.VolumeLayoutMismatch => text["TurboBoostForeignReasonVolumeLayoutMismatch"],
            TurboBoostForeignRemovalReason.ComplexTopologyChange => text["TurboBoostForeignReasonComplexTopologyChange"],
            TurboBoostForeignRemovalReason.InjectionGroupContainsNonForeignFiles => text["TurboBoostForeignReasonInjectionGroupContainsNonForeignFiles"],
            TurboBoostForeignRemovalReason.BaselineContradiction => text["TurboBoostForeignReasonBaselineContradiction"],
            TurboBoostForeignRemovalReason.BaselineTopologyEvidenceInsufficient => text["TurboBoostForeignReasonBaselineTopologyEvidenceInsufficient"],
            TurboBoostForeignRemovalReason.BaselineByteAuthorizationRequired => text["TurboBoostForeignReasonBaselineByteAuthorizationRequired"],
            TurboBoostForeignRemovalReason.MutationPlannerRejected => text["TurboBoostForeignReasonMutationPlannerRejected"],
            _ => text["TurboBoostForeignActionRequiresReview"]
        };
    }

    private string TurboBoostForeignProposedActionText(
        TurboBoostUnlockModule module,
        TurboBoostForeignRemovalPlan plan)
    {
        if (module.Disposition == TurboBoostUnlockModuleDisposition.Retained)
        {
            return text["TurboBoostForeignActionKeep"];
        }
        if (module.Disposition != TurboBoostUnlockModuleDisposition.Foreign)
        {
            return text["TurboBoostForeignActionRequiresReview"];
        }

        return plan.Operation switch
        {
            TurboBoostForeignRemovalOperation.RemoveInjectedFfs => text["TurboBoostForeignActionRemoveInjectedFfs"],
            TurboBoostForeignRemovalOperation.RestoreBaselineFfs => text["TurboBoostForeignActionRestoreBaselineFfs"],
            _ => text["TurboBoostForeignActionRequiresReview"]
        };
    }

    private Button CreateForeignUnlockRemovalButton(TurboBoostForeignRemovalPlan plan)
    {
        var button = new Button
        {
            Content = text["TurboBoostForeignRemoveButton"],
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = plan.CanExecute && plan.Operation == TurboBoostForeignRemovalOperation.RemoveInjectedFfs,
            Tag = plan
        };
        button.Click += RemoveTurboBoostForeignUnlock;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            button,
            text["TurboBoostForeignRemoveButton"]);
        return button;
    }

    private async void RemoveTurboBoostForeignUnlock(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: TurboBoostForeignRemovalPlan plan } ||
            !plan.CanExecute ||
            plan.Operation != TurboBoostForeignRemovalOperation.RemoveInjectedFfs ||
            operation is not null ||
            activeImage is not BiosImage sourceImage)
        {
            return;
        }

        TurboBoostUnlockModule[] matches = sourceImage.TurboBoostUnlock.ForeignUnlockModules
            .Where(module => PlanTargetsModule(plan, module))
            .ToArray();
        if (matches.Length != 1)
        {
            ShowOperationNotice(
                UiOperationKind.RemovingForeignUnlock,
                text["Error"],
                text[OperationError.TurboBoostForeignRemovalUnsupported],
                InfoBarSeverity.Error);
            return;
        }
        TurboBoostUnlockModule module = matches[0];
        string family = module.Families.Count == 0
            ? text["TurboBoostUnknownFamily"]
            : string.Join(text["InlineListSeparator"], module.Families);

        string destination = temporary.NewBiosPath(TemporaryBiosArtifact.ForeignUnlockRemoval);
        await RunOperation(async token =>
        {
            BiosImage updated = await Task.Run(
                () => TurboBoostForeignUnlockImageUpdater.RemoveInjectedFfsFileAsync(
                    sourceImage.FilePath,
                    destination,
                    plan,
                    token),
                token);
            ShowImage(updated, ImageSourceKind.UpdatedImage, WorkspacePage.TurboBoost);
            SetNotice(
                TurboBoostNoticeBar,
                text["TurboBoostForeignRemovalCompletedTitle"],
                string.Format(
                    text.Culture,
                    text["TurboBoostForeignRemovalCompletedMessage"],
                    family,
                    module.FileGuid,
                    updated.Sha256),
                InfoBarSeverity.Success);
        }, UiOperationKind.RemovingForeignUnlock);
    }

    private InfoBar TurboBoostStatusNotice(TurboBoostUnlockReport report) => report.Status switch
    {
        TurboBoostUnlockStatus.Detected => Notice(
            text["TurboBoostDetectedTitle"],
            text["TurboBoostDetectedMessage"],
            InfoBarSeverity.Warning),
        TurboBoostUnlockStatus.Possible => Notice(
            text["TurboBoostPossibleTitle"],
            text["TurboBoostPossibleMessage"],
            InfoBarSeverity.Warning),
        TurboBoostUnlockStatus.NotDetected => Notice(
            text["TurboBoostNotDetectedTitle"],
            text["TurboBoostNotDetectedMessage"],
            InfoBarSeverity.Warning),
        _ => Notice(
            text["TurboBoostInconclusiveTitle"],
            text["TurboBoostInconclusiveMessage"],
            InfoBarSeverity.Warning)
    };

    private void ShowTurboBoostCpuPatches(TurboBoostUnlockReport report)
    {
        StackPanel card = Card(TurboBoostResults, string.Format(
            text.Culture,
            text["CountTitleFormat"],
            text["TurboBoostCpuPatches"],
            report.Microcodes.Count));

        IntelMicrocodeInfo[] target = report.XeonE5V3CpuPatches.ToArray();
        if (target.Length != 0)
        {
            card.Children.Add(Notice(
                text["TurboBoostCpuPatchRecommendationTitle"],
                string.Format(text.Culture, text["TurboBoostCpuPatchRecommendation"], target.Length),
                InfoBarSeverity.Warning));
            card.Children.Add(CreateCpuPatchRemovalButton(report));
        }
        else
        {
            card.Children.Add(Notice(
                text["TurboBoostCpuPatchNotFoundTitle"],
                text["TurboBoostCpuPatchNotFound"],
                InfoBarSeverity.Informational));
        }

        if (report.Microcodes.Count == 0)
        {
            card.Children.Add(Label(text["TurboBoostNoMicrocodes"]));
            return;
        }

        var list = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateListSpacing)
        };
        card.Children.Add(list);
        foreach (IntelMicrocodeInfo microcode in report.Microcodes)
        {
            list.Children.Add(MicrocodeItem(microcode, report.CpuPatchRemovalPlans));
        }
    }

    private Border MicrocodeItem(IntelMicrocodeInfo microcode, IReadOnlyList<CpuPatchRemovalPlan> plans)
    {
        var content = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
        };
        bool isTarget = TurboBoostUnlockReport.IsXeonE5V3TurboUnlockCpuPatch(microcode);
        content.Children.Add(new TextBlock
        {
            Text = string.Format(
                text.Culture,
                text["TurboBoostMicrocodeHeaderFormat"],
                ShortCpuId(microcode.ProcessorSignature),
                microcode.ProcessorFlags,
                microcode.UpdateRevision),
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true
        });
        content.Children.Add(Label(string.Format(
            text.Culture,
            text["TurboBoostMicrocodeDetailsFormat"],
            FullCpuId(microcode.ProcessorSignature),
            FormatMicrocodeDate(microcode),
            microcode.Size,
            microcode.Offset,
            microcode.FileGuid,
            microcode.FileOffset,
            microcode.Sha256)));

        if (isTarget)
        {
            CpuPatchRemovalPlan? plan = plans.FirstOrDefault(item =>
                item.PatchOffset == microcode.Offset &&
                string.Equals(item.PatchSha256, microcode.Sha256, StringComparison.Ordinal));
            if (plan is not null)
            {
                string planText = plan.CanApply
                    ? text["TurboBoostRemovalReady"]
                    : text["TurboBoostRemovalUnsupported"];
                content.Children.Add(Label(string.Format(
                    text.Culture,
                    text["TurboBoostRemovalPlanFormat"],
                    planText,
                    plan.RelativePatchOffset,
                    plan.FileSize,
                    plan.FitOffset,
                    plan.FitMicrocodeEntryCount)));
                AddRow(
                    content,
                    text["TurboBoostRemovalReason"],
                    text["CpuPatchRemovalReason" + plan.Reason]);

            }
        }

        return new Border
        {
            Style = UiResources.Get<Style>(UiResourceKeys.UefiDriverBorderStyle),
            Child = content
        };
    }

    private Button CreateCpuPatchRemovalButton(TurboBoostUnlockReport report)
    {
        CpuPatchRemovalPlan? plan = report.CpuPatchRemovalPlans.FirstOrDefault(item => item.CanApply);
        var button = new Button
        {
            Content = text["TurboBoostRemoveCpuPatch"],
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = plan is not null,
            Tag = plan
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            button,
            text["TurboBoostRemoveCpuPatch"]);

        if (plan is not null)
        {
            button.Click += RemoveCpuPatch;
        }
        else
        {
            ToolTipService.SetToolTip(button, text["TurboBoostRemoveCpuPatchUnavailableHint"]);
        }

        return button;
    }

    private string TurboBoostCpuPatchRemovalStatusText(TurboBoostUnlockReport report)
    {
        int targetCount = report.XeonE5V3CpuPatches.Count;
        if (targetCount == 0)
        {
            return text["TurboBoostCpuPatchRemovalStatusRemoved"];
        }

        int readyCount = report.RemovableXeonE5V3CpuPatchCount;
        if (readyCount == targetCount)
        {
            return text["TurboBoostCpuPatchRemovalStatusPresentReady"];
        }
        if (readyCount > 0)
        {
            return text["TurboBoostCpuPatchRemovalStatusPresentPartial"];
        }
        return text["TurboBoostCpuPatchRemovalStatusPresentBlocked"];
    }

    private async void RemoveCpuPatch(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: CpuPatchRemovalPlan plan } ||
            !plan.CanApply ||
            activeImage is null ||
            operation is not null)
        {
            return;
        }

        BiosImage sourceImage = activeImage;
        if (!string.Equals(sourceImage.Sha256, plan.SourceImageSha256, StringComparison.OrdinalIgnoreCase))
        {
            ShowOperationNotice(
                UiOperationKind.RemovingCpuPatch,
                text["Error"],
                text[OperationError.CpuPatchSourceChanged],
                InfoBarSeverity.Error);
            return;
        }

        string destination = temporary.NewBiosPath(TemporaryBiosArtifact.CpuPatchRemoval);
        await RunOperation(async token =>
        {
            BiosImage updated = await Task.Run(
                () => CpuPatchImageUpdater.RemoveFileAsync(
                    sourceImage.FilePath,
                    destination,
                    plan,
                    token),
                token);
            ShowImage(updated, ImageSourceKind.UpdatedImage, WorkspacePage.TurboBoost);
            SetNotice(
                TurboBoostNoticeBar,
                text["TurboBoostRemovalCompletedTitle"],
                string.Format(
                    text.Culture,
                    text["TurboBoostRemovalCompleted"],
                    plan.ProcessorFlags,
                    ShortCpuId(plan.ProcessorSignature),
                    plan.UpdateRevision,
                    updated.Sha256),
                InfoBarSeverity.Success);
        }, UiOperationKind.RemovingCpuPatch);
    }

    private void ShowTurboBoostFindings(TurboBoostUnlockReport report)
    {
        StackPanel card = Card(TurboBoostResults, string.Format(
            text.Culture,
            text["CountTitleFormat"],
            text["TurboBoostFindings"],
            report.Findings.Count));
        if (report.Findings.Count == 0)
        {
            card.Children.Add(Label(text["TurboBoostNoFindings"]));
            return;
        }

        var list = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateListSpacing)
        };
        card.Children.Add(list);
        foreach (TurboBoostUnlockFinding finding in report.Findings)
        {
            var content = new StackPanel
            {
                Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
            };
            string family = string.IsNullOrWhiteSpace(finding.Family) ? text["TurboBoostUnknownFamily"] : finding.Family;
            content.Children.Add(new TextBlock
            {
                Text = family,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true
            });
            content.Children.Add(Label(string.Format(
                text.Culture,
                text["TurboBoostFindingDetailsFormat"],
                TurboBoostEvidenceText(finding.Evidence),
                finding.FileGuid?.ToString() ?? text["Unknown"],
                finding.VolumeOffset is long volume ? $"0x{volume:X}" : text["Unknown"],
                finding.FileOffset is long file ? $"0x{file:X}" : text["Unknown"],
                finding.Sha256)));
            if (finding.RelevantMsrs.Count != 0)
            {
                AddRow(content, text["TurboBoostRelevantMsrs"], string.Join(text["InlineListSeparator"], finding.RelevantMsrs));
            }
            string[] familyMarkers = finding.MarkerHits
                .Where(marker => !IsEmbeddedTurboBoostDiagnostic(marker))
                .ToArray();
            if (familyMarkers.Length != 0)
            {
                AddRow(content, text["TurboBoostMarkers"], string.Join(text["InlineListSeparator"], familyMarkers));
            }
            list.Children.Add(new Border
            {
                Style = UiResources.Get<Style>(UiResourceKeys.UefiDriverBorderStyle),
                Child = content
            });
        }

        string[] embeddedDiagnostics = report.Findings
            .SelectMany(finding => finding.MarkerHits)
            .Where(IsEmbeddedTurboBoostDiagnostic)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        if (embeddedDiagnostics.Length != 0)
        {
            var diagnostics = new StackPanel
            {
                Spacing = UiResources.Get<double>(UiResourceKeys.LayoutCertificateItemSpacing)
            };
            diagnostics.Children.Add(new TextBlock
            {
                Text = text["TurboBoostEmbeddedDiagnosticsExplanation"],
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true
            });
            foreach (string diagnostic in embeddedDiagnostics)
            {
                diagnostics.Children.Add(new TextBlock
                {
                    Text = diagnostic,
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true
                });
            }

            card.Children.Add(new Expander
            {
                Header = Label(string.Format(
                    text.Culture,
                    text["CountTitleFormat"],
                    text["TurboBoostEmbeddedDiagnosticsTitle"],
                    embeddedDiagnostics.Length)),
                IsExpanded = false,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Content = diagnostics
            });
        }
    }

    private static bool IsEmbeddedTurboBoostDiagnostic(string value) =>
        value.StartsWith("Failure -", StringComparison.Ordinal) ||
        value.StartsWith("Success -", StringComparison.Ordinal);

    private string TurboBoostStatusText(TurboBoostUnlockStatus status) => text["TurboBoostStatus" + status];

    private string TurboBoostEvidenceText(TurboBoostUnlockEvidenceKind evidence) => text["TurboBoostEvidence" + evidence];

    private string FormatMicrocodeDate(IntelMicrocodeInfo microcode) =>
        microcode.Date is DateOnly value
            ? value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : string.Format(CultureInfo.InvariantCulture, "0x{0:X8}", microcode.DateRaw);

    private static string ShortCpuId(uint signature) => (signature & 0xFFFF).ToString("X4", CultureInfo.InvariantCulture);

    private static string FullCpuId(uint signature) => signature.ToString("X8", CultureInfo.InvariantCulture);
}
