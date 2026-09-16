using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics.Imaging;
using Windows.Storage;
using XeonV3Control.Core;

namespace XeonV3Control.App;

internal static class UiSmoke
{
    internal static void VerifyStaDataTransfer()
    {
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException(OperationError.StaApartmentRequired);
        }

        var package = new DataPackage();
        package.SetText(ApplicationIdentity.DisplayName);
        _ = package.GetView();
    }

    internal static async Task CaptureAsync(FrameworkElement root, string path)
    {
        await Task.Delay(UiDesign.SmokeRenderSettleMilliseconds);
        root.UpdateLayout();
        var bitmap = new RenderTargetBitmap();
        await bitmap.RenderAsync(root);
        var pixels = await bitmap.GetPixelsAsync();
        if (bitmap.PixelWidth < 1 || bitmap.PixelHeight < 1)
        {
            throw new IOException("UI did not render");
        }
        var file = await StorageFile.GetFileFromPathAsync(path);
        using var output = await file.OpenAsync(FileAccessMode.ReadWrite);
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, output);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
            (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, UiDesign.StandardDpi, UiDesign.StandardDpi, pixels.ToArray());
        await encoder.FlushAsync();
    }
}
