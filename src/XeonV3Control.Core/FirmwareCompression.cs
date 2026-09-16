// UEFI decompression behavior is based on the TianoCore EDK II reference implementation.
// Reference source: BaseTools/Source/C/Common/Decompress.c
// Copyright (c) 2004-2018 Intel Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent
// See third_party/edk2/LICENSE.txt.

using System.Buffers.Binary;
using SharpCompress.Common;

namespace XeonV3Control.Core;

/// <summary>Classifies failures produced while decoding untrusted firmware compression payloads.</summary>
internal static class FirmwareCompressionFailure
{
    internal static bool IsMalformedInput(Exception error) =>
        error is SharpCompressException or IOException or InvalidDataException or ArgumentException or OverflowException;
}

/// <summary>
/// Managed EFI/Tiano decompressor for PI standard-compression and compatible guided sections.
/// This is a bounds-checked C# port of the EDK II BaseTools decompressor and performs no
/// native interop, external process execution, or unmanaged allocation.
/// </summary>
internal static class EfiCompressionDecoder
{
    private const int HeaderBytes = 8;
    private const int BitBufferBits = 32;
    private const int MaximumMatch = 256;
    private const int Threshold = 3;
    private const int CodeBits = 16;
    private const int CharacterCount = byte.MaxValue + MaximumMatch + 2 - Threshold;
    private const int CharacterBits = 9;
    private const int EfiPositionBits = 4;
    private const int TianoPositionBits = 5;
    private const int ExtraBits = 5;
    private const int MaximumPositionCount = (1 << 5) - 1;
    private const int ExtraCount = CodeBits + 3;
    private const int PositionTableCount = MaximumPositionCount > ExtraCount ? MaximumPositionCount : ExtraCount;
    private const int CharacterTableBits = 12;
    private const int PositionTableBits = 8;
    private const int MaximumCodeLength = 16;
    private const int DecodeCancellationInterval = 4096;

    internal static bool TryGetExpandedSize(
        ReadOnlySpan<byte> source,
        int maximumSize,
        out int expandedSize)
    {
        expandedSize = 0;
        if (!TryReadHeader(source, maximumSize, out _, out int originalSize))
        {
            return false;
        }

        expandedSize = originalSize;
        return true;
    }

    internal static bool TryDecompressEfi(
        ReadOnlySpan<byte> source,
        int expectedSize,
        int maximumSize,
        CancellationToken token,
        out byte[] expanded) =>
        TryDecompress(source, expectedSize, maximumSize, EfiPositionBits, token, out expanded);

    internal static bool TryDecompressTiano(
        ReadOnlySpan<byte> source,
        int expectedSize,
        int maximumSize,
        CancellationToken token,
        out byte[] expanded) =>
        TryDecompress(source, expectedSize, maximumSize, TianoPositionBits, token, out expanded);

    private static bool TryDecompress(
        ReadOnlySpan<byte> source,
        int expectedSize,
        int maximumSize,
        int positionBits,
        CancellationToken token,
        out byte[] expanded)
    {
        expanded = [];
        if (expectedSize < 0 || expectedSize > maximumSize ||
            (positionBits != EfiPositionBits && positionBits != TianoPositionBits) ||
            !TryReadHeader(source, maximumSize, out int compressedSize, out int originalSize) ||
            originalSize != expectedSize || (expectedSize != 0 && compressedSize == 0))
        {
            return false;
        }

        byte[] destination = new byte[expectedSize];
        if (destination.Length == 0)
        {
            expanded = destination;
            return true;
        }

        token.ThrowIfCancellationRequested();
        var decoder = new Decoder(source.Slice(HeaderBytes, compressedSize), destination, positionBits, token);
        if (!decoder.TryDecode())
        {
            return false;
        }

        expanded = destination;
        return true;
    }

    private static bool TryReadHeader(
        ReadOnlySpan<byte> source,
        int maximumSize,
        out int compressedSize,
        out int originalSize)
    {
        compressedSize = 0;
        originalSize = 0;
        if (maximumSize < 0 || source.Length < HeaderBytes)
        {
            return false;
        }

        uint compressedSizeValue = BinaryPrimitives.ReadUInt32LittleEndian(source);
        uint originalSizeValue = BinaryPrimitives.ReadUInt32LittleEndian(source[sizeof(uint)..]);
        if (compressedSizeValue > int.MaxValue || originalSizeValue > int.MaxValue ||
            originalSizeValue > (uint)maximumSize ||
            compressedSizeValue > (uint)(source.Length - HeaderBytes))
        {
            return false;
        }

        compressedSize = checked((int)compressedSizeValue);
        originalSize = checked((int)originalSizeValue);
        return true;
    }

    private ref struct Decoder
    {
        private readonly ReadOnlySpan<byte> source;
        private Span<byte> destination;
        private readonly int positionBits;
        private readonly CancellationToken token;
        private readonly ushort[] left;
        private readonly ushort[] right;
        private readonly byte[] characterLengths;
        private readonly byte[] positionLengths;
        private readonly ushort[] characterTable;
        private readonly ushort[] positionTable;
        private int sourceOffset;
        private int compressedBytesRemaining;
        private int outputOffset;
        private int bitCount;
        private uint bitBuffer;
        private uint subBitBuffer;
        private ushort blockSize;

        internal Decoder(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            int positionBits,
            CancellationToken token)
        {
            this.source = source;
            this.destination = destination;
            this.positionBits = positionBits;
            this.token = token;
            left = new ushort[2 * CharacterCount - 1];
            right = new ushort[2 * CharacterCount - 1];
            characterLengths = new byte[CharacterCount];
            positionLengths = new byte[PositionTableCount];
            characterTable = new ushort[1 << CharacterTableBits];
            positionTable = new ushort[1 << PositionTableBits];
            sourceOffset = 0;
            compressedBytesRemaining = source.Length;
            outputOffset = 0;
            bitCount = 0;
            bitBuffer = 0;
            subBitBuffer = 0;
            blockSize = 0;
            FillBuffer(BitBufferBits);
        }

        internal bool TryDecode()
        {
            while (outputOffset < destination.Length)
            {
                if ((outputOffset & (DecodeCancellationInterval - 1)) == 0)
                {
                    token.ThrowIfCancellationRequested();
                }

                if (!TryDecodeCharacter(out ushort character))
                {
                    return false;
                }

                if (character < byte.MaxValue + 1)
                {
                    destination[outputOffset++] = checked((byte)character);
                    continue;
                }

                int bytesToCopy = character - (byte.MaxValue + 1 - Threshold);
                if (bytesToCopy <= 0 || !TryDecodePosition(out uint position) ||
                    position >= (uint)outputOffset)
                {
                    return false;
                }

                int sourceIndex = outputOffset - checked((int)position) - 1;
                for (int index = 0; index < bytesToCopy && outputOffset < destination.Length; index++)
                {
                    if ((uint)sourceIndex >= (uint)outputOffset)
                    {
                        return false;
                    }
                    destination[outputOffset++] = destination[sourceIndex++];
                }
            }

            return true;
        }

        private void FillBuffer(int numberOfBits)
        {
            bitBuffer = (uint)((ulong)bitBuffer << numberOfBits);
            while (numberOfBits > bitCount)
            {
                numberOfBits -= bitCount;
                bitBuffer |= (uint)((ulong)subBitBuffer << numberOfBits);

                if (compressedBytesRemaining > 0)
                {
                    compressedBytesRemaining--;
                    subBitBuffer = source[sourceOffset++];
                    bitCount = 8;
                }
                else
                {
                    subBitBuffer = 0;
                    bitCount = 8;
                }
            }

            bitCount -= numberOfBits;
            bitBuffer |= subBitBuffer >> bitCount;
        }

        private uint GetBits(int numberOfBits)
        {
            if (numberOfBits == 0)
            {
                return 0;
            }

            uint result = bitBuffer >> (BitBufferBits - numberOfBits);
            FillBuffer(numberOfBits);
            return result;
        }

        private bool TryMakeTable(int symbolCount, byte[] bitLengths, int tableBits, ushort[] table)
        {
            Span<ushort> counts = stackalloc ushort[MaximumCodeLength + 1];
            Span<ushort> weights = stackalloc ushort[MaximumCodeLength + 1];
            Span<ushort> starts = stackalloc ushort[MaximumCodeLength + 2];

            for (int index = 0; index < symbolCount; index++)
            {
                int length = bitLengths[index];
                if (length > MaximumCodeLength)
                {
                    return false;
                }
                counts[length]++;
            }

            starts[1] = 0;
            for (int index = 1; index <= MaximumCodeLength; index++)
            {
                starts[index + 1] = unchecked((ushort)(starts[index] +
                    (counts[index] << (MaximumCodeLength - index))));
            }
            if (starts[MaximumCodeLength + 1] != 0)
            {
                return false;
            }

            int adjustmentBits = MaximumCodeLength - tableBits;
            int lengthIndex = 1;
            for (; lengthIndex <= tableBits; lengthIndex++)
            {
                starts[lengthIndex] >>= adjustmentBits;
                weights[lengthIndex] = checked((ushort)(1 << (tableBits - lengthIndex)));
            }
            for (; lengthIndex <= MaximumCodeLength; lengthIndex++)
            {
                weights[lengthIndex] = checked((ushort)(1 << (MaximumCodeLength - lengthIndex)));
            }

            int tableIndex = starts[tableBits + 1] >> adjustmentBits;
            if (tableIndex != 0)
            {
                int tableEnd = 1 << tableBits;
                if (tableIndex > tableEnd || tableEnd > table.Length)
                {
                    return false;
                }
                Array.Clear(table, tableIndex, tableEnd - tableIndex);
            }

            int availableNode = symbolCount;
            ushort mask = checked((ushort)(1 << (MaximumCodeLength - 1 - tableBits)));
            int maximumTableLength = 1 << tableBits;

            for (ushort symbol = 0; symbol < symbolCount; symbol++)
            {
                int length = bitLengths[symbol];
                if (length is 0 or > MaximumCodeLength)
                {
                    continue;
                }

                ushort nextCode = unchecked((ushort)(starts[length] + weights[length]));
                if (length <= tableBits)
                {
                    if (starts[length] >= nextCode || nextCode > maximumTableLength)
                    {
                        return false;
                    }
                    for (int index = starts[length]; index < nextCode; index++)
                    {
                        table[index] = symbol;
                    }
                }
                else
                {
                    ushort code = starts[length];
                    ushort[] target = table;
                    int targetIndex = code >> adjustmentBits;
                    int remainingBits = length - tableBits;

                    while (remainingBits-- > 0)
                    {
                        if ((uint)targetIndex >= (uint)target.Length)
                        {
                            return false;
                        }

                        ushort node = target[targetIndex];
                        if (node == 0)
                        {
                            if ((uint)availableNode >= (uint)left.Length)
                            {
                                return false;
                            }
                            left[availableNode] = 0;
                            right[availableNode] = 0;
                            node = checked((ushort)availableNode++);
                            target[targetIndex] = node;
                        }
                        if ((uint)node >= (uint)left.Length)
                        {
                            return false;
                        }

                        target = (code & mask) != 0 ? right : left;
                        targetIndex = node;
                        code = unchecked((ushort)(code << 1));
                    }

                    if ((uint)targetIndex >= (uint)target.Length)
                    {
                        return false;
                    }
                    target[targetIndex] = symbol;
                }

                starts[length] = nextCode;
            }

            return true;
        }

        private bool TryReadPositionLengths(int symbolCount, int countBits, int specialIndex)
        {
            if (symbolCount > PositionTableCount)
            {
                return false;
            }

            int number = checked((int)GetBits(countBits));
            if (number == 0)
            {
                int symbol = checked((int)GetBits(countBits));
                if ((uint)symbol >= (uint)symbolCount)
                {
                    return false;
                }
                Array.Fill(positionTable, checked((ushort)symbol));
                Array.Clear(positionLengths, 0, symbolCount);
                return true;
            }
            if (number > symbolCount)
            {
                return false;
            }

            int index = 0;
            while (index < number)
            {
                int codeLength = checked((int)(bitBuffer >> (BitBufferBits - 3)));
                if (codeLength == 7)
                {
                    uint mask = 1u << (BitBufferBits - 1 - 3);
                    while ((bitBuffer & mask) != 0)
                    {
                        mask >>= 1;
                        codeLength++;
                        if (codeLength > MaximumCodeLength)
                        {
                            return false;
                        }
                    }
                }

                FillBuffer(codeLength < 7 ? 3 : codeLength - 3);
                positionLengths[index++] = checked((byte)codeLength);

                if (index == specialIndex)
                {
                    int zeroCount = checked((int)GetBits(2));
                    if (index + zeroCount > symbolCount)
                    {
                        return false;
                    }
                    while (zeroCount-- > 0)
                    {
                        positionLengths[index++] = 0;
                    }
                }
            }

            Array.Clear(positionLengths, index, symbolCount - index);
            return TryMakeTable(symbolCount, positionLengths, PositionTableBits, positionTable);
        }

        private bool TryReadCharacterLengths()
        {
            int number = checked((int)GetBits(CharacterBits));
            if (number == 0)
            {
                int symbol = checked((int)GetBits(CharacterBits));
                if ((uint)symbol >= CharacterCount)
                {
                    return false;
                }
                Array.Clear(characterLengths, 0, characterLengths.Length);
                Array.Fill(characterTable, checked((ushort)symbol));
                return true;
            }
            if (number > CharacterCount)
            {
                return false;
            }

            int index = 0;
            while (index < number)
            {
                ushort code = positionTable[checked((int)(bitBuffer >> (BitBufferBits - PositionTableBits)))];
                if (code >= ExtraCount)
                {
                    uint mask = 1u << (BitBufferBits - 1 - PositionTableBits);
                    int traversalDepth = 0;
                    do
                    {
                        if ((uint)code >= (uint)left.Length || mask == 0 || traversalDepth++ >= MaximumCodeLength)
                        {
                            return false;
                        }
                        code = (bitBuffer & mask) != 0 ? right[code] : left[code];
                        mask >>= 1;
                    }
                    while (code >= ExtraCount);
                }
                if ((uint)code >= (uint)positionLengths.Length)
                {
                    return false;
                }

                FillBuffer(positionLengths[code]);
                if (code <= 2)
                {
                    int zeroCount = code switch
                    {
                        0 => 1,
                        1 => checked((int)GetBits(4) + 3),
                        _ => checked((int)GetBits(CharacterBits) + 20)
                    };
                    if (index + zeroCount > CharacterCount)
                    {
                        return false;
                    }
                    while (zeroCount-- > 0)
                    {
                        characterLengths[index++] = 0;
                    }
                }
                else
                {
                    characterLengths[index++] = checked((byte)(code - 2));
                }
            }

            Array.Clear(characterLengths, index, CharacterCount - index);
            return TryMakeTable(CharacterCount, characterLengths, CharacterTableBits, characterTable);
        }

        private bool TryDecodeCharacter(out ushort character)
        {
            character = 0;
            if (blockSize == 0)
            {
                blockSize = checked((ushort)GetBits(16));
                if (!TryReadPositionLengths(ExtraCount, ExtraBits, 3) ||
                    !TryReadCharacterLengths() ||
                    !TryReadPositionLengths(MaximumPositionCount, positionBits, -1))
                {
                    return false;
                }
            }

            blockSize = unchecked((ushort)(blockSize - 1));
            ushort value = characterTable[checked((int)(bitBuffer >> (BitBufferBits - CharacterTableBits)))];
            if (value >= CharacterCount)
            {
                uint mask = 1u << (BitBufferBits - 1 - CharacterTableBits);
                int traversalDepth = 0;
                do
                {
                    if ((uint)value >= (uint)left.Length || mask == 0 || traversalDepth++ >= MaximumCodeLength)
                    {
                        return false;
                    }
                    value = (bitBuffer & mask) != 0 ? right[value] : left[value];
                    mask >>= 1;
                }
                while (value >= CharacterCount);
            }
            if ((uint)value >= (uint)characterLengths.Length)
            {
                return false;
            }

            FillBuffer(characterLengths[value]);
            character = value;
            return true;
        }

        private bool TryDecodePosition(out uint position)
        {
            position = 0;
            ushort value = positionTable[checked((int)(bitBuffer >> (BitBufferBits - PositionTableBits)))];
            if (value >= MaximumPositionCount)
            {
                uint mask = 1u << (BitBufferBits - 1 - PositionTableBits);
                int traversalDepth = 0;
                do
                {
                    if ((uint)value >= (uint)left.Length || mask == 0 || traversalDepth++ >= MaximumCodeLength)
                    {
                        return false;
                    }
                    value = (bitBuffer & mask) != 0 ? right[value] : left[value];
                    mask >>= 1;
                }
                while (value >= MaximumPositionCount);
            }
            if ((uint)value >= (uint)positionLengths.Length)
            {
                return false;
            }

            FillBuffer(positionLengths[value]);
            position = value;
            if (value > 1)
            {
                position = (1u << (value - 1)) + GetBits(value - 1);
            }
            return true;
        }
    }
}
