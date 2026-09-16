using System.Buffers.Binary;

namespace XeonV3Control.Core;

/// <summary>Encodes a top-down BGRA image into the exact uncompressed BMP layout used by a BIOS logo.</summary>
public static class BootLogoBitmapConverter
{
    public static byte[] ConvertBgraToTemplate(
        ReadOnlySpan<byte> bgra,
        int width,
        int height,
        ReadOnlySpan<byte> templateBmp)
    {
        if (!PersonalizationInspector.BmpInfo.TryParse(templateBmp, out var info) ||
            width != info.Width || height != info.Height ||
            bgra.Length != checked(width * height * 4))
        {
            throw new InvalidDataException(OperationError.PersonalizationInvalidImage);
        }

        byte[] result = templateBmp.ToArray();
        int stride = checked((int)((((long)width * info.BitsPerPixel) + 31) / 32 * 4));
        result.AsSpan(info.PixelOffset, checked(stride * height)).Clear();

        if (info.BitsPerPixel <= 8)
        {
            EncodeIndexed(bgra, result, info, stride);
        }
        else
        {
            EncodeTrueColor(bgra, result, info, stride);
        }
        return result;
    }

    public static byte[] CreateBlackTemplate(ReadOnlySpan<byte> templateBmp)
    {
        if (!PersonalizationInspector.BmpInfo.TryParse(templateBmp, out var info))
        {
            throw new InvalidDataException(OperationError.PersonalizationInvalidBmp);
        }
        byte[] black = new byte[checked(info.Width * info.Height * 4)];
        for (int index = 3; index < black.Length; index += 4)
        {
            black[index] = byte.MaxValue;
        }
        return ConvertBgraToTemplate(black, info.Width, info.Height, templateBmp);
    }

    private static void EncodeIndexed(
        ReadOnlySpan<byte> bgra,
        Span<byte> destination,
        PersonalizationInspector.BmpInfo info,
        int stride)
    {
        int colorCount = 1 << info.BitsPerPixel;
        int paletteOffset = checked(14 + (int)info.DibHeaderSize);
        if (paletteOffset > info.PixelOffset - colorCount * 4)
        {
            throw new InvalidDataException(OperationError.PersonalizationInvalidBmp);
        }

        for (int index = 0; index < colorCount; index++)
        {
            (byte red, byte green, byte blue) = PaletteColor(index, info.BitsPerPixel);
            int entry = paletteOffset + index * 4;
            destination[entry] = blue;
            destination[entry + 1] = green;
            destination[entry + 2] = red;
            destination[entry + 3] = 0;
        }
        if (info.DibHeaderSize >= 40)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(46, 4), (uint)colorCount);
        }

        for (int y = 0; y < info.Height; y++)
        {
            int targetY = info.TopDown ? y : info.Height - 1 - y;
            Span<byte> row = destination.Slice(info.PixelOffset + targetY * stride, stride);
            for (int x = 0; x < info.Width; x++)
            {
                int pixel = (y * info.Width + x) * 4;
                int paletteIndex = NearestPaletteIndex(
                    bgra[pixel + 2], bgra[pixel + 1], bgra[pixel], info.BitsPerPixel);
                if (info.BitsPerPixel == 8)
                {
                    row[x] = (byte)paletteIndex;
                }
                else if (info.BitsPerPixel == 4)
                {
                    int packed = x / 2;
                    row[packed] |= (byte)(x % 2 == 0 ? paletteIndex << 4 : paletteIndex);
                }
                else if (paletteIndex != 0)
                {
                    row[x / 8] |= (byte)(1 << (7 - x % 8));
                }
            }
        }
    }

    private static void EncodeTrueColor(
        ReadOnlySpan<byte> bgra,
        Span<byte> destination,
        PersonalizationInspector.BmpInfo info,
        int stride)
    {
        for (int y = 0; y < info.Height; y++)
        {
            int targetY = info.TopDown ? y : info.Height - 1 - y;
            Span<byte> row = destination.Slice(info.PixelOffset + targetY * stride, stride);
            for (int x = 0; x < info.Width; x++)
            {
                int source = (y * info.Width + x) * 4;
                int target = x * info.BitsPerPixel / 8;
                byte blue = bgra[source];
                byte green = bgra[source + 1];
                byte red = bgra[source + 2];
                if (info.BitsPerPixel == 16)
                {
                    ushort rgb555 = (ushort)(((red >> 3) << 10) | ((green >> 3) << 5) | (blue >> 3));
                    BinaryPrimitives.WriteUInt16LittleEndian(row[target..], rgb555);
                }
                else
                {
                    row[target] = blue;
                    row[target + 1] = green;
                    row[target + 2] = red;
                    if (info.BitsPerPixel == 32)
                    {
                        row[target + 3] = byte.MaxValue;
                    }
                }
            }
        }
    }

    private static int NearestPaletteIndex(byte red, byte green, byte blue, ushort bitsPerPixel)
    {
        if (bitsPerPixel == 8)
        {
            return ((red * 7 + 127) / 255 << 5) |
                ((green * 7 + 127) / 255 << 2) |
                ((blue * 3 + 127) / 255);
        }
        if (bitsPerPixel == 4)
        {
            int best = 0;
            int bestDistance = int.MaxValue;
            for (int index = 0; index < 16; index++)
            {
                (byte pr, byte pg, byte pb) = PaletteColor(index, bitsPerPixel);
                int dr = red - pr;
                int dg = green - pg;
                int db = blue - pb;
                int distance = dr * dr + dg * dg + db * db;
                if (distance < bestDistance)
                {
                    bestDistance = distance;
                    best = index;
                }
            }
            return best;
        }
        return (red + green + blue) >= 384 ? 1 : 0;
    }

    private static (byte Red, byte Green, byte Blue) PaletteColor(int index, ushort bitsPerPixel)
    {
        if (bitsPerPixel == 8)
        {
            return ((byte)(((index >> 5) & 7) * 255 / 7),
                (byte)(((index >> 2) & 7) * 255 / 7),
                (byte)((index & 3) * 255 / 3));
        }
        if (bitsPerPixel == 4)
        {
            int boost = (index & 8) == 0 ? 0 : 85;
            return ((byte)(((index & 4) == 0 ? 0 : 170) + boost),
                (byte)(((index & 2) == 0 ? 0 : 170) + boost),
                (byte)(((index & 1) == 0 ? 0 : 170) + boost));
        }
        byte value = index == 0 ? (byte)0 : byte.MaxValue;
        return (value, value, value);
    }
}
