using Windows.Graphics.Imaging;
using Windows.Storage;

namespace XeonV3Control.App;

internal static class BootLogoImageDecoder
{
    private const ulong MaximumInputBytes = 128UL * 1024 * 1024;
    private const ulong MaximumDecodedPixels = 100_000_000;

    internal static readonly IReadOnlyList<string> SupportedExtensions =
    [
        ".bmp", ".dib", ".png", ".jpg", ".jpeg", ".jpe", ".jfif",
        ".gif", ".tif", ".tiff", ".ico", ".wdp", ".jxr", ".webp", ".heic", ".avif"
    ];

    internal static async Task<byte[]> DecodeFittedBgraAsync(
        string path,
        int targetWidth,
        int targetHeight,
        CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (targetWidth <= 0 || targetHeight <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(targetWidth));
        }

        try
        {
            token.ThrowIfCancellationRequested();
            StorageFile file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(path));
            ulong fileSize = (await file.GetBasicPropertiesAsync()).Size;
            if (fileSize == 0 || fileSize > MaximumInputBytes)
            {
                throw new InvalidDataException(Core.OperationError.PersonalizationInvalidImage);
            }

            using var stream = await file.OpenReadAsync();
            BitmapDecoder decoder = await BitmapDecoder.CreateAsync(stream);
            uint sourceWidth = decoder.OrientedPixelWidth;
            uint sourceHeight = decoder.OrientedPixelHeight;
            if (sourceWidth == 0 || sourceHeight == 0 ||
                (ulong)sourceWidth * sourceHeight > MaximumDecodedPixels)
            {
                throw new InvalidDataException(Core.OperationError.PersonalizationInvalidImage);
            }

            double scale = Math.Min(targetWidth / (double)sourceWidth, targetHeight / (double)sourceHeight);
            uint scaledWidth = checked((uint)Math.Clamp(
                Math.Round(sourceWidth * scale, MidpointRounding.AwayFromZero), 1d, targetWidth));
            uint scaledHeight = checked((uint)Math.Clamp(
                Math.Round(sourceHeight * scale, MidpointRounding.AwayFromZero), 1d, targetHeight));
            var transform = new BitmapTransform
            {
                ScaledWidth = scaledWidth,
                ScaledHeight = scaledHeight,
                InterpolationMode = BitmapInterpolationMode.Fant
            };

            PixelDataProvider pixels = await decoder.GetPixelDataAsync(
                BitmapPixelFormat.Bgra8,
                BitmapAlphaMode.Straight,
                transform,
                ExifOrientationMode.RespectExifOrientation,
                ColorManagementMode.ColorManageToSRgb);
            token.ThrowIfCancellationRequested();
            byte[] scaled = pixels.DetachPixelData();
            int scaledStride = checked((int)scaledWidth * 4);
            if (scaled.Length != checked(scaledStride * (int)scaledHeight))
            {
                throw new InvalidDataException(Core.OperationError.PersonalizationInvalidImage);
            }

            byte[] result = new byte[checked(targetWidth * targetHeight * 4)];
            for (int alpha = 3; alpha < result.Length; alpha += 4)
            {
                result[alpha] = byte.MaxValue;
            }

            int offsetX = (targetWidth - (int)scaledWidth) / 2;
            int offsetY = (targetHeight - (int)scaledHeight) / 2;
            for (int y = 0; y < scaledHeight; y++)
            {
                int sourceRow = y * scaledStride;
                int targetRow = ((offsetY + y) * targetWidth + offsetX) * 4;
                for (int x = 0; x < scaledWidth; x++)
                {
                    int sourcePixel = sourceRow + x * 4;
                    int targetPixel = targetRow + x * 4;
                    int alpha = scaled[sourcePixel + 3];
                    result[targetPixel] = (byte)((scaled[sourcePixel] * alpha + 127) / 255);
                    result[targetPixel + 1] = (byte)((scaled[sourcePixel + 1] * alpha + 127) / 255);
                    result[targetPixel + 2] = (byte)((scaled[sourcePixel + 2] * alpha + 127) / 255);
                    result[targetPixel + 3] = byte.MaxValue;
                }
            }
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (InvalidDataException error) when (
            string.Equals(error.Message, Core.OperationError.PersonalizationInvalidImage, StringComparison.Ordinal))
        {
            throw;
        }
        catch (Exception error)
        {
            throw new InvalidDataException(Core.OperationError.PersonalizationInvalidImage, error);
        }
    }
}
