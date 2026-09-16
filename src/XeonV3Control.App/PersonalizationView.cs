using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private sealed class BootLogoEditorState
    {
        internal required BootLogoKind Kind { get; init; }
        internal required string Title { get; init; }
        internal required int Width { get; init; }
        internal required int Height { get; init; }
        internal required byte[] CurrentBmp { get; init; }
        internal required Image Preview { get; init; }
        internal required TextBlock PreviewCaption { get; init; }
        internal required Button SelectButton { get; init; }
        internal required Button DeleteButton { get; init; }
        internal required Button ApplyButton { get; init; }
        internal required Button CancelButton { get; init; }
        internal byte[]? PendingBmp { get; set; }
        internal bool PendingRemoval { get; set; }
        internal int PreviewVersion { get; set; }
    }

    private void ShowPersonalizationOverview(PersonalizationReport report)
    {
        StackPanel card = Card(Results, text["PersonalizationTitle"]);
        int availableLogos = new[] { report.LargeLogo, report.SmallLogo }
            .Count(logo => logo.Status == PersonalizationFeatureStatus.Available);
        AddRow(card, text["PersonalizationBootImages"],
            string.Format(text.Culture, text["CountRatioFormat"], availableLogos, 2));
        AddRow(card, text["PersonalizationBeeper"], StartupBeeperStatusText(report.Beeper.Status));

        var button = new Button
        {
            Content = IconText(UiGlyphs.Navigate, text["OpenPersonalization"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        button.Click += ShowPersonalizationPage;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, text["OpenPersonalization"]);
        card.Children.Add(button);
    }

    private void ShowPersonalizationDetails(PersonalizationReport report)
    {
        ShowBootLogoCard(report.LargeLogo);
        ShowBootLogoCard(report.SmallLogo);
        ShowStartupBeeperCard(report.Beeper);
    }

    private void ShowBootLogoCard(BootLogoInfo logo)
    {
        string title = text[logo.Kind switch
        {
            BootLogoKind.LargeBoot => "PersonalizationLargeLogo",
            BootLogoKind.SmallAmi => "PersonalizationSmallLogo",
            _ => throw new ArgumentOutOfRangeException(nameof(logo), logo.Kind, null)
        }];
        StackPanel card = Card(PersonalizationResults, title);
        AddRow(card, text["Status"], PersonalizationFeatureStatusText(logo.Status));
        if (logo.Status != PersonalizationFeatureStatus.Available || logo.BmpData.IsEmpty)
        {
            card.Children.Add(Notice(
                text["PersonalizationUnavailableTitle"],
                text["PersonalizationLogoUnavailableMessage"],
                InfoBarSeverity.Warning));
            return;
        }

        AddRow(card, text["PersonalizationDimensions"],
            string.Format(text.Culture, text["PersonalizationDimensionsFormat"], logo.Width, logo.Height));
        AddRow(card, text["PersonalizationBitsPerPixel"], logo.BitsPerPixel.ToString(text.Culture));
        AddRow(card, text["Size"], string.Format(text.Culture, text["ByteSizeFormat"],
            logo.BmpBytes, logo.BmpBytes / (double)UiDesign.BytesPerMebibyte));
        AddRow(card, text["Sha256"], logo.BmpSha256);

        var requirements = Label(string.Format(
            text.Culture,
            text["PersonalizationImageRequirements"],
            logo.Width,
            logo.Height,
            logo.BitsPerPixel));
        requirements.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutSecondaryTextOpacity);
        card.Children.Add(requirements);

        var previewCaption = Label(text["PersonalizationPreviewCurrent"]);
        var preview = new Image
        {
            Height = UiResources.Get<double>(UiResourceKeys.LayoutBootLogoPreviewHeight),
            Stretch = Stretch.Uniform,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            preview,
            string.Format(text.Culture, text["PersonalizationPreviewNamed"], title));
        var previewBorder = new Border
        {
            Background = new SolidColorBrush(Colors.Black),
            CornerRadius = UiResources.Get<CornerRadius>(UiResourceKeys.LayoutCardCornerRadius),
            Child = preview
        };
        card.Children.Add(previewCaption);
        card.Children.Add(previewBorder);

        var selectButton = new Button
        {
            Content = IconText(UiGlyphs.OpenFile, text["PersonalizationReplaceImage"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        var deleteButton = new Button
        {
            Content = IconText(UiGlyphs.Delete, text["PersonalizationDeleteImage"]),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        var applyButton = new Button
        {
            Content = IconText(UiGlyphs.Apply, text["PersonalizationApplyImage"]),
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = false,
            Style = UiResources.Get<Style>(UiResourceKeys.PrimaryActionButtonStyle)
        };
        var cancelButton = new Button
        {
            Content = IconText(UiGlyphs.Cancel, text["Cancel"]),
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = false
        };
        var state = new BootLogoEditorState
        {
            Kind = logo.Kind,
            Title = title,
            Width = logo.Width,
            Height = logo.Height,
            CurrentBmp = logo.BmpData.ToArray(),
            Preview = preview,
            PreviewCaption = previewCaption,
            SelectButton = selectButton,
            DeleteButton = deleteButton,
            ApplyButton = applyButton,
            CancelButton = cancelButton
        };

        selectButton.Tag = state;
        deleteButton.Tag = state;
        applyButton.Tag = state;
        cancelButton.Tag = state;
        selectButton.Click += SelectBootLogoImage;
        deleteButton.Click += PreviewBlackBootLogo;
        applyButton.Click += ApplyBootLogo;
        cancelButton.Click += CancelBootLogoPreview;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(selectButton,
            string.Format(text.Culture, text["PersonalizationReplaceImageNamed"], title));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(deleteButton,
            string.Format(text.Culture, text["PersonalizationDeleteImageNamed"], title));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(applyButton,
            string.Format(text.Culture, text["PersonalizationApplyImageNamed"], title));

        var actions = new StackPanel
        {
            Spacing = UiResources.Get<double>(UiResourceKeys.LayoutHeaderStackSpacing)
        };
        actions.Children.Add(selectButton);
        actions.Children.Add(deleteButton);
        actions.Children.Add(applyButton);
        actions.Children.Add(cancelButton);
        card.Children.Add(actions);
        SetBootLogoPreview(state, state.CurrentBmp);
    }

    private async void SelectBootLogoImage(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: BootLogoEditorState state } || operation is not null)
        {
            return;
        }

        try
        {
            nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            string? selected = SystemFileOpenDialog.PickSingleFile(
                hwnd,
                [new SystemFileOpenDialog.Filter(text["FileTypeImages"], BootLogoImageDecoder.SupportedExtensions)]);
            if (selected is null)
            {
                return;
            }

            SetBootLogoEditorEnabled(state, false);
            byte[] bgra = await BootLogoImageDecoder.DecodeFittedBgraAsync(
                selected, state.Width, state.Height, CancellationToken.None);
            state.PendingBmp = await Task.Run(() =>
                BootLogoBitmapConverter.ConvertBgraToTemplate(
                    bgra, state.Width, state.Height, state.CurrentBmp));
            state.PendingRemoval = false;
            state.PreviewCaption.Text = text["PersonalizationPreviewReplacement"];
            SetBootLogoPreview(state, state.PendingBmp);
        }
        catch (Exception error)
        {
            ShowError(error);
        }
        finally
        {
            SetBootLogoEditorEnabled(state, true);
        }
    }

    private void PreviewBlackBootLogo(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: BootLogoEditorState state } || operation is not null)
        {
            return;
        }

        try
        {
            state.PendingBmp = BootLogoBitmapConverter.CreateBlackTemplate(state.CurrentBmp);
            state.PendingRemoval = true;
            state.PreviewCaption.Text = text["PersonalizationPreviewBlack"];
            SetBootLogoPreview(state, state.PendingBmp);
            SetBootLogoEditorEnabled(state, true);
        }
        catch (Exception error)
        {
            ShowError(error);
        }
    }

    private async void ApplyBootLogo(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: BootLogoEditorState state } ||
            state.PendingBmp is not byte[] replacement ||
            operation is not null ||
            activeImage is not BiosImage sourceImage)
        {
            return;
        }

        TemporaryBiosArtifact artifact = state.Kind switch
        {
            BootLogoKind.LargeBoot => TemporaryBiosArtifact.LargeBootLogo,
            BootLogoKind.SmallAmi => TemporaryBiosArtifact.SmallAmiLogo,
            _ => throw new ArgumentOutOfRangeException(nameof(state.Kind), state.Kind, null)
        };
        string destination = temporary.NewBiosPath(artifact);
        bool removed = state.PendingRemoval;
        await RunOperation(async token =>
        {
            BiosImage updated = await Task.Run(
                () => PersonalizationImageUpdater.ReplaceBootLogoAsync(
                    sourceImage.FilePath,
                    destination,
                    sourceImage,
                    state.Kind,
                    replacement,
                    token),
                token);
            ShowImage(updated, ImageSourceKind.UpdatedImage, WorkspacePage.Personalization);
            SetNotice(
                PersonalizationNoticeBar,
                text["Completed"],
                text[removed ? "PersonalizationImageDeletedMessage" : "PersonalizationImageUpdatedMessage"],
                InfoBarSeverity.Success);
        }, UiOperationKind.UpdatingBootLogo);
    }

    private void CancelBootLogoPreview(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: BootLogoEditorState state } || operation is not null)
        {
            return;
        }
        state.PendingBmp = null;
        state.PendingRemoval = false;
        state.PreviewCaption.Text = text["PersonalizationPreviewCurrent"];
        SetBootLogoPreview(state, state.CurrentBmp);
        SetBootLogoEditorEnabled(state, true);
    }

    private void SetBootLogoEditorEnabled(BootLogoEditorState state, bool enabled)
    {
        state.SelectButton.IsEnabled = enabled;
        state.DeleteButton.IsEnabled = enabled;
        state.ApplyButton.IsEnabled = enabled && state.PendingBmp is not null;
        state.CancelButton.IsEnabled = enabled && state.PendingBmp is not null;
    }

    private async void SetBootLogoPreview(BootLogoEditorState state, byte[] bmp)
    {
        int previewVersion = ++state.PreviewVersion;
        try
        {
            using var stream = new InMemoryRandomAccessStream();
            using (var writer = new DataWriter(stream))
            {
                writer.WriteBytes(bmp);
                await writer.StoreAsync();
                writer.DetachStream();
            }
            stream.Seek(0);
            BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);
            using SoftwareBitmap bitmap = await decoder.GetSoftwareBitmapAsync(
                BitmapPixelFormat.Bgra8,
                BitmapAlphaMode.Premultiplied);
            var source = new SoftwareBitmapSource();
            await source.SetBitmapAsync(bitmap);
            if (previewVersion == state.PreviewVersion)
            {
                state.Preview.Source = source;
            }
        }
        catch (Exception error)
        {
            ShowError(error);
        }
    }

    private void ShowStartupBeeperCard(StartupBeeperInfo beeper)
    {
        StackPanel card = Card(PersonalizationResults, text["PersonalizationBeeper"]);
        AddRow(card, text["Status"], StartupBeeperStatusText(beeper.Status));

        if (beeper.Status is StartupBeeperStatus.NotFound or StartupBeeperStatus.Unsupported)
        {
            card.Children.Add(Notice(
                text["PersonalizationUnavailableTitle"],
                text["PersonalizationBeeperUnavailableMessage"],
                InfoBarSeverity.Warning));
            return;
        }

        var explanation = Label(text["PersonalizationBeeperScope"]);
        explanation.Opacity = UiResources.Get<double>(UiResourceKeys.LayoutSecondaryTextOpacity);
        card.Children.Add(explanation);

        bool disable = beeper.Status == StartupBeeperStatus.Enabled;
        string caption = text[disable ? "PersonalizationDisableBeeper" : "PersonalizationEnableBeeper"];
        var button = new Button
        {
            Content = IconText(UiGlyphs.Audio, caption),
            HorizontalAlignment = HorizontalAlignment.Left,
            Tag = disable
        };
        button.Click += ChangeStartupBeeper;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, caption);
        card.Children.Add(button);
    }

    private async void ChangeStartupBeeper(object sender, RoutedEventArgs args)
    {
        _ = args;
        if (sender is not Button { Tag: bool disable } ||
            operation is not null || activeImage is not BiosImage sourceImage)
        {
            return;
        }

        string destination = temporary.NewBiosPath(disable
            ? TemporaryBiosArtifact.BeeperDisabled
            : TemporaryBiosArtifact.BeeperEnabled);
        await RunOperation(async token =>
        {
            BiosImage updated = await Task.Run(
                () => PersonalizationImageUpdater.SetStartupBeeperDisabledAsync(
                    sourceImage.FilePath,
                    destination,
                    sourceImage,
                    disable,
                    token),
                token);
            ShowImage(updated, ImageSourceKind.UpdatedImage, WorkspacePage.Personalization);
            SetNotice(
                PersonalizationNoticeBar,
                text["Completed"],
                text[disable ? "PersonalizationBeeperDisabledMessage" : "PersonalizationBeeperEnabledMessage"],
                InfoBarSeverity.Success);
        }, UiOperationKind.UpdatingBeeper);
    }

    private void ShowPersonalizationPage(object sender, RoutedEventArgs e) =>
        NavigateTo(WorkspacePage.Personalization);

    private string PersonalizationFeatureStatusText(PersonalizationFeatureStatus status) => status switch
    {
        PersonalizationFeatureStatus.Available => text["PersonalizationAvailable"],
        PersonalizationFeatureStatus.NotFound => text["PersonalizationNotFound"],
        _ => text["PersonalizationFeatureUnsupported"]
    };

    private string StartupBeeperStatusText(StartupBeeperStatus status) => status switch
    {
        StartupBeeperStatus.Enabled => text["PersonalizationBeeperEnabled"],
        StartupBeeperStatus.Disabled => text["PersonalizationBeeperDisabled"],
        StartupBeeperStatus.NotFound => text["PersonalizationNotFound"],
        _ => text["PersonalizationFeatureUnsupported"]
    };
}
