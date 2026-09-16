using System.Security.Cryptography;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using XeonV3Control.App.Hardware;
using XeonV3Control.Core;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private void ShowSaveDetails(BiosImage image)
    {
        StackPanel save = Card(SaveResults, text["SaveImage"]);
        AddRow(save, text["Sha256"], image.Sha256);
        save.Children.Add(Label(text["SaveImageHint"]));
        var saveButton = new Button
        {
            Content = text["SaveImageButton"],
            HorizontalAlignment = HorizontalAlignment.Left
        };
        saveButton.Click += SaveActiveImage;
        save.Children.Add(saveButton);

        StackPanel flash = Card(SaveResults, text["FlashImage"]);
        flash.Children.Add(Notice(text["FlashWarningTitle"], text["FlashWarningMessage"], InfoBarSeverity.Warning));
        var flashButton = new Button
        {
            Content = text["FlashImageButton"],
            HorizontalAlignment = HorizontalAlignment.Left
        };
        flashButton.Click += FlashActiveImage;
        flash.Children.Add(flashButton);
    }

    private async void SaveActiveImage(object sender, RoutedEventArgs args)
    {
        _ = sender;
        _ = args;
        if (activeImage is not BiosImage image || operation is not null)
        {
            return;
        }
        try
        {
            nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            string baseName = Path.GetFileNameWithoutExtension(activeInputPath ?? image.FilePath);
            string? destination = SystemFileSaveDialog.PickFile(hwnd, baseName + "-modified.bin", text["BiosImageFilter"], ".bin");
            if (string.IsNullOrWhiteSpace(destination))
            {
                return;
            }
            await RunOperation(token => SaveVerifiedAsync(image, destination, token), UiOperationKind.SavingImage);
        }
        catch (Exception error)
        {
            ShowError(error);
        }
    }

    private async Task SaveVerifiedAsync(BiosImage image, string destination, CancellationToken token)
    {
        byte[] bytes = await File.ReadAllBytesAsync(image.FilePath, token);
        string hash = Convert.ToHexString(SHA256.HashData(bytes));
        if (!string.Equals(hash, image.Sha256, StringComparison.Ordinal))
        {
            throw new IOException(OperationError.OutputVerification);
        }
        string full = Path.GetFullPath(destination);
        if (string.Equals(full, Path.GetFullPath(image.FilePath), StringComparison.OrdinalIgnoreCase))
        {
            SetNotice(SaveNoticeBar, text["Completed"], text["SaveSameFileMessage"], InfoBarSeverity.Informational);
            return;
        }
        string partial = full + "." + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            await using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(bytes, token);
                await output.FlushAsync(token);
                output.Flush(true);
            }
            byte[] verify = await File.ReadAllBytesAsync(partial, token);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), SHA256.HashData(verify)))
            {
                throw new IOException(OperationError.OutputVerification);
            }
            File.Move(partial, full, overwrite: true);
            SetNotice(SaveNoticeBar, text["Completed"], string.Format(text.Culture, text["SaveCompletedMessage"], full), InfoBarSeverity.Success);
        }
        finally
        {
            if (File.Exists(partial))
            {
                try { File.Delete(partial); } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { AppLog.Error(error); }
            }
        }
    }

    private async void FlashActiveImage(object sender, RoutedEventArgs args)
    {
        _ = sender;
        _ = args;
        if (activeImage is not BiosImage image || operation is not null)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            Title = text["FlashConfirmTitle"],
            Content = new TextBlock { Text = text["FlashConfirmMessage"], TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true },
            PrimaryButtonText = text["FlashImageButton"],
            CloseButtonText = text["Cancel"],
            DefaultButton = ContentDialogButton.Close
        };
        if (await ShowDialogAsync(dialog) != ContentDialogResult.Primary)
        {
            return;
        }

        await RunOperation(async token =>
        {
            byte[] target = await File.ReadAllBytesAsync(image.FilePath, token);
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(target)), image.Sha256, StringComparison.Ordinal))
            {
                throw new IOException(OperationError.OutputVerification);
            }
            if (image.TpmFirmware.DebugDriverCopies != 0 &&
                !TpmDebugDriverImageUpdater.IsCurrentInstallation(target, image))
            {
                throw new InvalidDataException(OperationError.TpmDebugDriverUnsafeVersion);
            }
            var reporter = new Progress<double>(value => Progress.Value = value * UiDesign.ProgressPercentageScale);
            FirmwareFlashResult result = await Task.Run(() =>
            {
                using var gate = new Semaphore(1, 1, ApplicationIdentity.SpiReadSemaphoreName);
                if (!gate.WaitOne(0)) throw new IOException(OperationError.SpiBusy);
                try
                {
                    using var driver = ThrottleStopDriver.Open(cancellationToken: token);
                    return new X99SpiFlasher(driver).FlashBios(target, image, reporter, token);
                }
                finally { gate.Release(); }
            }, token);
            SetNotice(SaveNoticeBar, text["FlashCompletedTitle"],
                string.Format(text.Culture, text["FlashCompletedMessage"], result.ChangedSectors, result.BiosSha256),
                InfoBarSeverity.Success);
        }, UiOperationKind.FlashingImage);
    }
}
