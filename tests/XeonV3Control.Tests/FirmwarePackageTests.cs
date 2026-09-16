using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class FirmwarePackageTests
{
    private static readonly byte[] s_dellSectionMagic =
        [0xAA, 0xEE, 0xAA, 0x76, 0x1B, 0xEC, 0xBB, 0x20, 0xF1, 0xE6, 0x51];
    private static readonly byte[] s_dellSectionFooterMagic =
        [0xEE, 0xAA, 0xEE, 0x8F, 0x49, 0x1B, 0xE8, 0xAE, 0x14, 0x37, 0x90];

    [TestMethod]
    public void InputExtensionsIncludeRawArchivesAndExe()
    {
        CollectionAssert.Contains(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".bin");
        CollectionAssert.Contains(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".zip");
        CollectionAssert.Contains(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".7z");
        CollectionAssert.Contains(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".rar");
        CollectionAssert.DoesNotContain(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".cab");
        CollectionAssert.DoesNotContain(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".iso");
        CollectionAssert.Contains(FirmwarePackageLoader.SupportedInputExtensions.ToArray(), ".exe");
        Assert.IsTrue(FirmwarePackageLoader.HasSupportedInputExtension("update.EXE"));
        Assert.IsTrue(FirmwarePackageLoader.IsPackagePath("update.zip"));
        Assert.IsFalse(FirmwarePackageLoader.IsPackagePath("bios.bin"));
    }

    [TestMethod]
    public async Task ZipPackageFindsBiosAndRejectsAuxiliaryFirmware()
    {
        string path = TemporaryPath(".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "BIOS/main.rom", FirmwareTests.Image());
                WriteEntry(archive, "ME/me.bin", FirmwareTests.Image());
                WriteEntry(archive, "docs/readme.txt", "not firmware"u8.ToArray());
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            Assert.AreEqual("main.rom", Path.GetFileName(result.Candidates[0].LogicalPath));
            Assert.IsFalse(result.Candidates[0].LogicalPath.Contains("ME/me.bin", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SingleStreamGzipCanContainARawBiosImage()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin.gz");
        try
        {
            await using (var output = File.Create(path))
            await using (var gzip = new GZipStream(output, CompressionLevel.Fastest))
            {
                await gzip.WriteAsync(FirmwareTests.Image().AsMemory());
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            Assert.AreEqual(".bin", Path.GetExtension(result.Candidates[0].LogicalPath));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task AuxiliaryTokenInOuterPackageNameDoesNotHideAValidBiosEntry()
    {
        string path = Path.Combine(Path.GetTempPath(), "ME_" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "BIOS/main.bin", FirmwareTests.Image());
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task UnsafeArchivePathsAreIgnored()
    {
        string path = TemporaryPath(".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "../escape.bin", FirmwareTests.Image());
                WriteEntry(archive, "BIOS/main.bin", FirmwareTests.Image());
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            Assert.IsFalse(result.Candidates[0].LogicalPath.Contains("..", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task NestedArchiveIsInspectedRecursively()
    {
        string path = TemporaryPath(".zip");
        try
        {
            byte[] nestedBytes;
            using (var nestedStream = new MemoryStream())
            {
                using (var nested = new ZipArchive(nestedStream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    WriteEntry(nested, "payload/board.bin", FirmwareTests.Image());
                }
                nestedBytes = nestedStream.ToArray();
            }

            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "payload.zip", nestedBytes);
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            StringAssert.Contains(result.Candidates[0].LogicalPath, "payload.zip!payload/board.bin");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task MultipleDistinctBiosImagesAreReturnedForExplicitSelection()
    {
        string path = TemporaryPath(".zip");
        try
        {
            byte[] first = FirmwareTests.Image();
            byte[] second = FirmwareTests.Image();
            second[512] = 0x5A;
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "BIOS/primary.bin", first);
                WriteEntry(archive, "BIOS/recovery.bin", second);
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(2, result.Candidates);
            Assert.AreNotEqual(result.Candidates[0].Image.Sha256, result.Candidates[1].Image.Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SelfExtractingZipExeIsInspectedWithoutExecutingIt()
    {
        string path = TemporaryPath(".exe");
        try
        {
            byte[] zipPayload;
            using (var stream = new MemoryStream())
            {
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    WriteEntry(archive, "BIOS/main.bin", FirmwareTests.Image());
                }
                zipPayload = stream.ToArray();
            }

            File.WriteAllBytes(path, Combine("MZ"u8.ToArray(), new byte[510], zipPayload));

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            Assert.AreEqual("main.bin", Path.GetFileName(result.Candidates[0].LogicalPath));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task DellPfsExeReturnsNamedSystemBiosWithoutExecutingPackage()
    {
        string path = TemporaryPath(".exe");
        try
        {
            File.WriteAllBytes(path, CreateDellPfsUpdater(FirmwareTests.Image(8 * 1024 * 1024)));

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            Assert.AreEqual("<DELL_PFS>/System BIOS.bin", result.Candidates[0].LogicalPath);
            Assert.AreEqual(8 * 1024 * 1024, result.Candidates[0].Data.Length);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task NestedDellPfsExeIsInspectedWithoutExecutingIt()
    {
        string path = TemporaryPath(".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "vendor/update.exe", CreateDellPfsUpdater(FirmwareTests.Image(8 * 1024 * 1024)));
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.HasCount(1, result.Candidates);
            StringAssert.Contains(result.Candidates[0].LogicalPath, "update.exe!<DELL_PFS>/System BIOS.bin");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task PackageWithoutBiosReturnsNoCandidateInsteadOfGuessing()
    {
        string path = TemporaryPath(".zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "flash.exe", CreatePeWithFirmwareMarker());
                WriteEntry(archive, "README.txt", "documentation"u8.ToArray());
            }

            FirmwarePackageInspection result = await FirmwarePackageLoader.InspectAsync(path);

            Assert.IsEmpty(result.Candidates);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static void WriteEntry(ZipArchive archive, string path, byte[] data)
    {
        ZipArchiveEntry entry = archive.CreateEntry(path, CompressionLevel.Fastest);
        using Stream stream = entry.Open();
        stream.Write(data);
    }

    private static byte[] CreatePeWithFirmwareMarker()
    {
        byte[] data = new byte[2 * 1024 * 1024];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        "_FVH"u8.CopyTo(data.AsSpan(0x1000));
        return data;
    }

    private static byte[] CreateDellPfsUpdater(byte[] bios)
    {
        const string biosGuid = "E8C11705DD2216A342A03FE37EC6C2B0";
        const string infoGuid = "B033CB16EC9B45A14055F80E4D583FD3";

        byte[] infoData = CreateDellPfsNameRecord(biosGuid, "System BIOS");
        byte[] payload = Combine(
            CreateDellPfsEntry(biosGuid, bios),
            CreateDellPfsEntry(infoGuid, infoData));
        uint footerCrc = ~ComputeCrc32(payload);
        byte[] volume = Combine(
            "PFS.HDR."u8.ToArray(),
            U32(1),
            U32(checked((uint)payload.Length)),
            payload,
            U32(checked((uint)payload.Length)),
            U32(footerCrc),
            "PFS.FTR."u8.ToArray());

        byte[] compressed;
        using (var output = new MemoryStream())
        {
            using (var zlib = new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                zlib.Write(volume);
            }
            compressed = output.ToArray();
        }

        byte[] sectionHeader = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(sectionHeader, checked((uint)compressed.Length));
        s_dellSectionMagic.CopyTo(sectionHeader, 4);
        sectionHeader[15] = Xor8(sectionHeader.AsSpan(0, 15));

        byte[] sectionFooter = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(sectionFooter, checked((uint)compressed.Length));
        s_dellSectionFooterMagic.CopyTo(sectionFooter, 4);
        sectionFooter[15] = Xor8(sectionFooter.AsSpan(0, 15));

        return Combine("MZ"u8.ToArray(), new byte[510], sectionHeader, compressed, sectionFooter);
    }

    private static byte[] CreateDellPfsEntry(string guid, byte[] data)
    {
        byte[] header = new byte[0x48];
        DellGuidBytes(guid).CopyTo(header, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0x10), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0x28), checked((uint)data.Length));
        return Combine(header, data);
    }

    private static byte[] CreateDellPfsNameRecord(string guid, string name)
    {
        byte[] encodedName = Encoding.Unicode.GetBytes(name);
        byte[] record = new byte[0x22 + encodedName.Length + 2];
        BinaryPrimitives.WriteUInt32LittleEndian(record, 1);
        DellGuidBytes(guid).CopyTo(record, 4);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x20), checked((ushort)(encodedName.Length / 2)));
        encodedName.CopyTo(record, 0x22);
        return record;
    }

    private static byte[] DellGuidBytes(string displayGuid)
    {
        uint[] words = Enumerable.Range(0, 4)
            .Select(index => Convert.ToUInt32(displayGuid.Substring(index * 8, 8), 16))
            .Reverse()
            .ToArray();
        byte[] result = new byte[16];
        for (int index = 0; index < words.Length; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(index * 4), words[index]);
        }
        return result;
    }

    private static byte[] U32(uint value)
    {
        byte[] result = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(result, value);
        return result;
    }

    private static byte[] Combine(params byte[][] parts)
    {
        int size = parts.Sum(part => part.Length);
        byte[] result = new byte[size];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }
        return result;
    }

    private static byte Xor8(ReadOnlySpan<byte> data)
    {
        byte value = 0;
        foreach (byte item in data)
        {
            value ^= item;
        }
        return value;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte item in data)
        {
            crc ^= item;
            for (int bit = 0; bit < 8; bit++)
            {
                uint mask = unchecked((uint)-(int)(crc & 1));
                crc = (crc >> 1) ^ (0xEDB88320U & mask);
            }
        }
        return ~crc;
    }

    private static string TemporaryPath(string extension) =>
        Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + extension);
}
