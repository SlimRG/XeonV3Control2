using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using XeonV3Control.Core;

namespace XeonV3Control.Tests;

[TestClass]
public sealed class SpiTests
{
    [TestMethod]
    public void ReadsCompleteSpiWhenAllMappedRegionsAreReadable()
    {
        var fake = new Registers();
        var reader = new X99SpiReader(fake);

        FirmwareReadSnapshot snapshot = reader.ReadFirmware(null, CancellationToken.None);

        Assert.AreEqual(FirmwareReadScope.FullSpi, snapshot.Scope);
        Assert.HasCount(Registers.FlashLength, snapshot.Data);
        Assert.AreEqual(Registers.FlashLength / X99Platform.Spi.TransferBytes, fake.Cycles);
        Assert.IsFalse(reader.Capabilities.CanWrite);
        Assert.AreEqual(0u, fake.FirstAddress);
        Assert.AreEqual(
            Registers.FlashLength - (uint)X99Platform.Spi.TransferBytes,
            fake.Address);
        Assert.IsTrue(snapshot.Regions.All(region => region.Readable));
        CollectionAssert.AreEqual(fake.Flash, snapshot.Data);
    }

    [TestMethod]
    public void UnreadableManagementEngineProducesExplicitPartialSpiImage()
    {
        var fake = new Registers
        {
            Permissions = X99Platform.Spi.DescriptorRegionReadAccess |
                X99Platform.Spi.BiosRegionReadAccess |
                X99Platform.Spi.GigabitEthernetRegionReadAccess
        };

        FirmwareReadSnapshot snapshot = new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None);

        Assert.AreEqual(FirmwareReadScope.PartialSpi, snapshot.Scope);
        FirmwareRegionReadStatus me = snapshot.Regions.Single(region => region.Kind == FlashRegionKind.ME);
        Assert.IsFalse(me.Readable);
        Assert.IsTrue(snapshot.Data.AsSpan((int)me.Start, me.Length).ToArray().All(value => value == byte.MaxValue));
        Assert.IsTrue(snapshot.Regions.Single(region => region.Kind == FlashRegionKind.Descriptor).Readable);
        Assert.IsTrue(snapshot.Regions.Single(region => region.Kind == FlashRegionKind.BIOS).Readable);
    }

    [TestMethod]
    public void DescriptorReadPermissionMissingFallsBackToBiosRegion()
    {
        var fake = new Registers
        {
            Permissions = X99Platform.Spi.BiosRegionReadAccess
        };

        FirmwareReadSnapshot snapshot = new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None);

        Assert.AreEqual(FirmwareReadScope.BiosRegion, snapshot.Scope);
        Assert.HasCount(Registers.BiosLength, snapshot.Data);
        CollectionAssert.AreEqual(
            fake.Flash.AsSpan((int)Registers.BiosStart, Registers.BiosLength).ToArray(),
            snapshot.Data);
    }

    [TestMethod]
    public void BiosReadPermissionDeniedDoesNotStartACycle()
    {
        var fake = new Registers
        {
            Permissions = X99Platform.Spi.DescriptorRegionReadAccess
        };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None));

        Assert.AreEqual(OperationError.ReadProtected, error.Message);
        Assert.AreEqual(0, fake.Cycles);
    }

    [TestMethod]
    public void CanonicalUnusedDescriptorRegionIsAccepted()
    {
        var fake = new Registers();

        FirmwareReadSnapshot snapshot = new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None);

        Assert.IsFalse(snapshot.Regions.Any(region => region.Kind == FlashRegionKind.PDR));
        Assert.IsTrue(snapshot.Regions.Any(region => region.Kind == FlashRegionKind.BIOS));
    }

    [TestMethod]
    public void InvalidDescriptorStatusDoesNotStartACycle()
    {
        var fake = new Registers { Status = 0 };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None));

        Assert.AreEqual(OperationError.DescriptorUnavailable, error.Message);
        Assert.AreEqual(0, fake.Cycles);
    }

    [TestMethod]
    public void BusyControllerIsNeverOverwritten()
    {
        var fake = new Registers
        {
            Status = X99Platform.Spi.DescriptorValid | X99Platform.Spi.CycleInProgress
        };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None));

        Assert.AreEqual(OperationError.SpiBusy, error.Message);
        Assert.AreEqual(0, fake.Cycles);
    }

    [TestMethod]
    public void PersistentCycleErrorRetriesAndThenStops()
    {
        var fake = new Registers { CycleErrorAddress = Registers.BiosStart };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None));

        Assert.AreEqual(OperationError.SpiCycleError, error.Message);
        Assert.AreEqual(Registers.BiosStart, fake.Address);
        Assert.IsTrue(fake.Cycles >= 3);
    }

    [TestMethod]
    public void TransientCycleErrorIsRetriedForReadOnlyCycle()
    {
        var fake = new Registers { CycleErrorsRemaining = 1 };

        FirmwareReadSnapshot snapshot = new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None);

        Assert.AreEqual(FirmwareReadScope.FullSpi, snapshot.Scope);
        Assert.AreEqual(Registers.FlashLength / X99Platform.Spi.TransferBytes + 1, fake.Cycles);
        CollectionAssert.AreEqual(fake.Flash, snapshot.Data);
    }

    [TestMethod]
    public void PersistentNonBiosCycleErrorFallsBackToBiosRegion()
    {
        var fake = new Registers { CycleErrorAddress = Registers.DescriptorStart };

        FirmwareReadSnapshot snapshot = new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None);

        Assert.AreEqual(FirmwareReadScope.BiosRegion, snapshot.Scope);
        Assert.IsFalse(snapshot.Regions.Single(region => region.Kind == FlashRegionKind.Descriptor).Readable);
        Assert.IsTrue(snapshot.Regions.Single(region => region.Kind == FlashRegionKind.BIOS).Readable);
    }

    [TestMethod]
    public void DescriptorAccessErrorFallsBackWithoutPretendingItWasRead()
    {
        var fake = new Registers { AccessErrorAddress = Registers.DescriptorStart };

        FirmwareReadSnapshot snapshot = new X99SpiReader(fake).ReadFirmware(null, CancellationToken.None);

        Assert.AreEqual(FirmwareReadScope.BiosRegion, snapshot.Scope);
        Assert.IsFalse(snapshot.Regions.Single(region => region.Kind == FlashRegionKind.Descriptor).Readable);
        Assert.IsTrue(snapshot.Regions.Single(region => region.Kind == FlashRegionKind.BIOS).Readable);
    }

    [TestMethod]
    public void CancelDoesNotStartACycle()
    {
        var fake = new Registers();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            new X99SpiReader(fake).ReadFirmware(null, cancellation.Token));
        Assert.AreEqual(0, fake.Cycles);
    }

    [TestMethod]
    public void DescriptorComponentDensityDefinesWholeFlashSize()
    {
        var fake = new Registers();
        var descriptor = new FirmwareRegionReadStatus(
            FlashRegionKind.Descriptor,
            Registers.DescriptorStart,
            checked((int)(Registers.DescriptorEndExclusive - Registers.DescriptorStart)),
            true);

        bool decoded = X99SpiReader.TryDecodeFlashSize(fake.Flash, descriptor, out uint flashSize);

        Assert.IsTrue(decoded);
        Assert.AreEqual((uint)Registers.FlashLength, flashSize);
    }

    [TestMethod]
    public void DisabledRegionIsRejectedByBiosDecoder()
    {
        uint disabled = EncodeRegionFields(X99Platform.Spi.RegionFieldMask, 0);
        Assert.Throws<InvalidDataException>(() => X99SpiReader.DecodeBiosRegion(disabled));
    }

    [TestMethod]
    public void ExtendedRegionAddressBitsWithinWellsburgHardwareLimitAreAccepted()
    {
        const uint extendedEndExclusive = 0x01180000;
        uint register = EncodeRegion(Registers.BiosStart, extendedEndExclusive);

        var region = X99SpiReader.DecodeBiosRegion(register);

        Assert.AreEqual(Registers.BiosStart, region.Start);
        Assert.AreEqual(checked((int)(extendedEndExclusive - Registers.BiosStart)), region.Length);
    }

    [TestMethod]
    public void RegionAboveHardwareSequencingAddressLimitIsRejected()
    {
        uint register = EncodeRegion(Registers.BiosStart, X99Platform.Spi.MaximumHardwareSequenceAddressExclusive + 0x1000);
        Assert.Throws<InvalidDataException>(() => X99SpiReader.DecodeBiosRegion(register));
    }

    [TestMethod]
    public void ReservedRegionBitsAreRejected()
    {
        uint register = EncodeRegion(Registers.BiosStart, Registers.BiosEndExclusive) |
            X99Platform.Spi.RegionLimitReservedBit;
        Assert.Throws<InvalidDataException>(() => X99SpiReader.DecodeBiosRegion(register));
    }

    [TestMethod]
    public void ReservedBaseRegionBitsAreRejected()
    {
        uint register = EncodeRegion(Registers.BiosStart, Registers.BiosEndExclusive) |
            X99Platform.Spi.RegionBaseReservedBit;
        Assert.Throws<InvalidDataException>(() => X99SpiReader.DecodeBiosRegion(register));
    }


    [TestMethod]
    public async Task FlasherWritesOnlyChangedBiosSectorsAndVerifiesFinalImage()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        Assert.IsTrue(plan.CanExecute);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        BiosImageLoader.EnsureValidBiosImage(targetImage);
        var registers = new WritableRegisters(source);

        FirmwareFlashResult result = new X99SpiFlasher(registers).FlashBios(target, targetImage);

        Assert.IsTrue(result.ChangedSectors > 0);
        CollectionAssert.AreEqual(target, registers.Flash);
        CollectionAssert.AreEqual(source.AsSpan(0, (int)WritableRegisters.BiosStart).ToArray(),
            registers.Flash.AsSpan(0, (int)WritableRegisters.BiosStart).ToArray());
    }

    [TestMethod]
    public async Task FlasherAllowsUnlockedProtectionConfigurationWhenItRemainsStable()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source)
        {
            Status = X99Platform.Spi.DescriptorValid | X99Platform.Spi.BlockEraseSize4K
        };

        FirmwareFlashResult result = new X99SpiFlasher(registers).FlashBios(target, targetImage);

        Assert.IsTrue(result.ChangedSectors > 0);
        Assert.IsTrue(registers.EraseCycles > 0);
        CollectionAssert.AreEqual(target, registers.Flash);
    }

    [TestMethod]
    public async Task ProtectionDriftAfterEraseCompletesCurrentSectorThenStops()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source);
        registers.OnFirstErase = () => registers.Permissions ^= X99Platform.Spi.DescriptorRegionReadAccess;

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage));

        Assert.AreEqual(OperationError.FlashProtectionStateChanged, error.Message);
        Assert.AreEqual(1, registers.EraseCycles);
        int firstChanged = Enumerable.Range((int)WritableRegisters.BiosStart, WritableRegisters.BiosLength)
            .First(index => source[index] != target[index]);
        int sectorStart = firstChanged & ~0xFFF;
        CollectionAssert.AreEqual(target.AsSpan(sectorStart, 4096).ToArray(),
            registers.Flash.AsSpan(sectorStart, 4096).ToArray(),
            "The sector whose erase already started must be programmed and verified before protection drift is reported.");
    }

    [TestMethod]
    public async Task ProtectedRangeOverlapBlocksBeforeAnyErase()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source);
        int firstChanged = Enumerable.Range((int)WritableRegisters.BiosStart, WritableRegisters.BiosLength)
            .First(index => source[index] != target[index]);
        uint protectedStart = checked((uint)(firstChanged & ~0xFFF));
        registers.ProtectedRanges[0] = EncodeProtectedRange(protectedStart, protectedStart + 4096u);

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage));

        Assert.AreEqual(OperationError.WriteProtected, error.Message);
        Assert.AreEqual(0, registers.EraseCycles);
        CollectionAssert.AreEqual(source, registers.Flash);
    }

    [TestMethod]
    public async Task Non4KBlockEraseIsRejectedBeforeAnyErase()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source)
        {
            Status = X99Platform.Spi.DescriptorValid | X99Platform.Spi.FlashConfigurationLockDown |
                (2u << 3) // 8 KiB BERASE.
        };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage));

        Assert.AreEqual(OperationError.FlashEraseSizeUnsupported, error.Message);
        Assert.AreEqual(0, registers.EraseCycles);
        CollectionAssert.AreEqual(source, registers.Flash);
    }

    [TestMethod]
    public async Task CancellationAfterEraseFinishesCurrentSectorBeforeStopping()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        BiosImageLoader.EnsureValidBiosImage(targetImage);
        var registers = new WritableRegisters(source);
        using var cancellation = new CancellationTokenSource();
        registers.OnFirstErase = cancellation.Cancel;

        Assert.Throws<OperationCanceledException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage, cancellationToken: cancellation.Token));

        int firstChanged = Enumerable.Range((int)WritableRegisters.BiosStart, WritableRegisters.BiosLength)
            .First(index => source[index] != target[index]);
        int sectorStart = firstChanged & ~0xFFF;
        CollectionAssert.AreEqual(target.AsSpan(sectorStart, 4096).ToArray(),
            registers.Flash.AsSpan(sectorStart, 4096).ToArray(),
            "The sector whose erase already started must be fully programmed and verified before cancellation is observed.");
    }

    [TestMethod]
    public async Task FlasherTemporarilyEnablesAndRestoresBiosWriteEnable()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source) { BiosControl = 0x08 };

        _ = new X99SpiFlasher(registers).FlashBios(target, targetImage);

        Assert.AreEqual((byte)0x08, registers.BiosControl, "Original BIOSWE=0 state must be restored.");
        CollectionAssert.AreEqual(target, registers.Flash);
    }

    [TestMethod]
    public async Task BiosWriteEnableIsRestoredWhenEraseCycleFails()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source)
        {
            BiosControl = 0x08,
            FailFirstEraseCycle = true
        };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage));

        Assert.AreEqual(OperationError.SpiCycleError, error.Message);
        Assert.AreEqual((byte)0x08, registers.BiosControl, "BIOSWE must be restored after an erase failure.");
    }

    [TestMethod]
    public async Task SmmBwpBlocksBeforeAnyErase()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source)
        {
            BiosControl = (byte)(0x08 | X99Platform.SmmBiosWriteProtection)
        };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage));

        Assert.AreEqual(OperationError.FlashSmmWriteProtectionEnabled, error.Message);
        Assert.AreEqual(0, registers.EraseCycles);
        CollectionAssert.AreEqual(source, registers.Flash);
    }

    [TestMethod]
    public async Task BiosWriteEnableRejectedBlocksBeforeAnyErase()
    {
        string path = RepositoryTestFiles.Find("tests", "8DPV11.bin");
        byte[] source = await File.ReadAllBytesAsync(path);
        BiosImage sourceImage = await BiosImageLoader.LoadValidatedAsync(path);
        TpmDebugDriverPlan plan = TpmDebugDriverImageUpdater.Plan(source, sourceImage);
        byte[] target = TpmDebugDriverImageUpdater.Apply(source, plan);
        BiosImage targetImage = BiosImageLoader.Analyze(target);
        var registers = new WritableRegisters(source)
        {
            BiosControl = 0x08,
            RejectBiosWriteEnable = true
        };

        IOException error = Assert.Throws<IOException>(() =>
            new X99SpiFlasher(registers).FlashBios(target, targetImage));

        Assert.AreEqual(OperationError.FlashBiosWriteEnableUnavailable, error.Message);
        Assert.AreEqual(0, registers.EraseCycles);
        CollectionAssert.AreEqual(source, registers.Flash);
    }

    private static uint EncodeRegion(uint start, uint endExclusive)
    {
        uint startField = start >> X99Platform.Spi.RegionAddressShift;
        uint endField = (endExclusive - 1) >> X99Platform.Spi.RegionAddressShift;
        return EncodeRegionFields(startField, endField);
    }

    private static uint EncodeProtectedRange(uint start, uint endExclusive)
    {
        uint startField = start >> X99Platform.Spi.RegionAddressShift;
        uint endField = (endExclusive - 1) >> X99Platform.Spi.RegionAddressShift;
        Assert.IsTrue(startField <= X99Platform.Spi.ProtectedRangeFieldMask);
        Assert.IsTrue(endField <= X99Platform.Spi.ProtectedRangeFieldMask);
        return X99Platform.Spi.ProtectedRangeWriteProtection | startField | (endField << 16);
    }

    private static uint EncodeRegionFields(uint startField, uint endField) =>
        (startField & X99Platform.Spi.RegionFieldMask) |
        ((endField & X99Platform.Spi.RegionFieldMask) << 16);


    private sealed class WritableRegisters : IX99SpiFlashAccess
    {
        internal const uint BiosStart = 0x00800000;
        internal const int BiosLength = 0x00800000;
        internal const uint BiosEndExclusive = BiosStart + BiosLength;
        private readonly byte[] dataWindow = new byte[X99Platform.Spi.TransferBytes];
        private uint address;
        private uint status = X99Platform.Spi.DescriptorValid | X99Platform.Spi.FlashConfigurationLockDown |
            X99Platform.Spi.BlockEraseSize4K;
        private bool firstErase = true;

        internal WritableRegisters(byte[] source)
        {
            Flash = source.ToArray();
            Assert.AreEqual((int)BiosEndExclusive, Flash.Length);
        }

        internal byte[] Flash { get; }
        internal uint[] ProtectedRanges { get; } = new uint[X99Platform.Spi.ProtectedRangeCount];
        internal int EraseCycles { get; private set; }
        internal uint Status { get => status; set => status = value; }
        internal uint Permissions { get; set; } = 1u << (8 + (int)FlashRegionKind.BIOS);
        internal Action? OnFirstErase { get; set; }
        internal byte BiosControl { get; set; } = 0x08;
        internal bool RejectBiosWriteEnable { get; set; }
        internal bool FailFirstEraseCycle { get; set; }

        public byte ReadBiosControl() => BiosControl;

        public void SetBiosWriteEnable(bool enabled)
        {
            if (enabled && RejectBiosWriteEnable)
            {
                BiosControl = (byte)(BiosControl & ~X99Platform.BiosWriteEnable);
                return;
            }
            BiosControl = enabled
                ? (byte)(BiosControl | X99Platform.BiosWriteEnable)
                : (byte)(BiosControl & ~X99Platform.BiosWriteEnable);
        }

        public uint Read(int offset, int width)
        {
            if (offset == X99Platform.Spi.HardwareStatusRegister)
            {
                Assert.AreEqual(X99Platform.Spi.WordWidth, width);
                return status;
            }
            if (offset == X99Platform.Spi.FlashRegionAccessPermissionsRegister)
            {
                Assert.AreEqual(X99Platform.Spi.DwordWidth, width);
                return Permissions;
            }
            if (offset == X99Platform.Spi.BiosRegionRegister)
            {
                Assert.AreEqual(X99Platform.Spi.DwordWidth, width);
                return EncodeRegion(BiosStart, BiosEndExclusive);
            }
            if (offset >= X99Platform.Spi.ProtectedRange0Register &&
                offset <= X99Platform.Spi.ProtectedRange4Register)
            {
                Assert.AreEqual(X99Platform.Spi.DwordWidth, width);
                Assert.AreEqual(0, (offset - X99Platform.Spi.ProtectedRange0Register) %
                    X99Platform.Spi.ProtectedRangeRegisterStride);
                int index = (offset - X99Platform.Spi.ProtectedRange0Register) /
                    X99Platform.Spi.ProtectedRangeRegisterStride;
                return ProtectedRanges[index];
            }
            if (offset >= X99Platform.Spi.FlashData0Register && offset <= X99Platform.Spi.FlashDataLastRegister)
            {
                int dataOffset = offset - X99Platform.Spi.FlashData0Register;
                return BinaryPrimitives.ReadUInt32LittleEndian(dataWindow.AsSpan(dataOffset, sizeof(uint)));
            }
            throw new AssertFailedException($"Unexpected writable-register read at 0x{offset:X} width {width}.");
        }

        public void Write(int offset, int width, uint value)
        {
            if (offset == X99Platform.Spi.HardwareStatusRegister)
            {
                Assert.AreEqual(X99Platform.Spi.WordWidth, width);
                Assert.AreEqual(0u, value & ~X99Platform.Spi.CompletionStatusWriteOneToClear);
                status &= ~value;
                return;
            }
            if (offset == X99Platform.Spi.FlashAddressRegister)
            {
                Assert.AreEqual(X99Platform.Spi.DwordWidth, width);
                Assert.IsTrue(value <= Flash.Length - X99Platform.Spi.TransferBytes);
                address = value;
                return;
            }
            if (offset >= X99Platform.Spi.FlashData0Register && offset <= X99Platform.Spi.FlashDataLastRegister)
            {
                Assert.AreEqual(X99Platform.Spi.DwordWidth, width);
                int dataOffset = offset - X99Platform.Spi.FlashData0Register;
                BinaryPrimitives.WriteUInt32LittleEndian(dataWindow.AsSpan(dataOffset, sizeof(uint)), value);
                return;
            }
            if (offset == X99Platform.Spi.HardwareControlRegister)
            {
                Assert.AreEqual(X99Platform.Spi.WordWidth, width);
                status &= ~(X99Platform.Spi.CycleDone | X99Platform.Spi.CycleError | X99Platform.Spi.AccessError);
                if (value == X99Platform.Spi.ReadCycleCommand)
                {
                    Flash.AsSpan(checked((int)address), X99Platform.Spi.TransferBytes).CopyTo(dataWindow);
                }
                else if (value == X99Platform.Spi.ProgramCycleCommand)
                {
                    Assert.IsTrue((BiosControl & X99Platform.BiosWriteEnable) != 0,
                        "Program cycle must not start with BIOSWE=0.");
                    dataWindow.AsSpan().CopyTo(Flash.AsSpan(checked((int)address), X99Platform.Spi.TransferBytes));
                }
                else if (value == X99Platform.Spi.Erase4KCycleCommand)
                {
                    Assert.IsTrue((BiosControl & X99Platform.BiosWriteEnable) != 0,
                        "Erase cycle must not start with BIOSWE=0.");
                    Assert.AreEqual(0u, address & 0xFFFu);
                    EraseCycles++;
                    if (firstErase && FailFirstEraseCycle)
                    {
                        firstErase = false;
                        status |= X99Platform.Spi.CycleDone | X99Platform.Spi.CycleError;
                        return;
                    }
                    Flash.AsSpan(checked((int)address), 4096).Fill(byte.MaxValue);
                    if (firstErase)
                    {
                        firstErase = false;
                        OnFirstErase?.Invoke();
                    }
                }
                else
                {
                    throw new AssertFailedException($"Unexpected hardware cycle command 0x{value:X}.");
                }
                status |= X99Platform.Spi.CycleDone;
                return;
            }
            throw new AssertFailedException($"Unexpected writable-register write at 0x{offset:X} width {width}.");
        }
    }

    private sealed class Registers : ISpiRegisters
    {
        internal const uint DescriptorStart = 0x00000000;
        internal const uint DescriptorEndExclusive = 0x00001000;
        internal const uint GbeStart = DescriptorEndExclusive;
        internal const uint GbeEndExclusive = 0x00003000;
        internal const uint MeStart = GbeEndExclusive;
        internal const uint MeEndExclusive = 0x00080000;
        internal const uint BiosStart = MeEndExclusive;
        internal const int BiosLength = X99Platform.Spi.MinimumReadableBiosRegionBytes;
        internal const uint BiosEndExclusive = BiosStart + BiosLength;
        internal const int FlashLength = (int)BiosEndExclusive;

        private static readonly uint[] RegionRegisters =
        [
            EncodeRegion(DescriptorStart, DescriptorEndExclusive),
            EncodeRegion(BiosStart, BiosEndExclusive),
            EncodeRegion(MeStart, MeEndExclusive),
            EncodeRegion(GbeStart, GbeEndExclusive),
            IntelFlashDescriptorSpecification.RegionAddressFieldMask
        ];

        public Registers()
        {
            Flash = new byte[FlashLength];
            for (int index = 0; index < Flash.Length; index++)
            {
                Flash[index] = unchecked((byte)(index * 37 + 11));
            }

            BinaryPrimitives.WriteUInt32LittleEndian(
                Flash.AsSpan(IntelFlashDescriptorSpecification.SignatureOffset),
                IntelFlashDescriptorSpecification.Signature);
            uint flashMap0 = 3u << IntelFlashDescriptorSpecification.ComponentBaseFieldShift;
            BinaryPrimitives.WriteUInt32LittleEndian(
                Flash.AsSpan(IntelFlashDescriptorSpecification.FlashMap0Offset),
                flashMap0);
            BinaryPrimitives.WriteUInt32LittleEndian(
                Flash.AsSpan(3 * IntelFlashDescriptorSpecification.ComponentSectionAddressUnitBytes),
                1u); // One 1 MiB component on Wellsburg.
        }

        public byte[] Flash { get; }
        public uint Status = X99Platform.Spi.DescriptorValid;
        public uint Permissions = X99Platform.Spi.DescriptorRegionReadAccess |
            X99Platform.Spi.BiosRegionReadAccess |
            X99Platform.Spi.ManagementEngineRegionReadAccess |
            X99Platform.Spi.GigabitEthernetRegionReadAccess;
        public int CycleErrorsRemaining;
        public uint? CycleErrorAddress;
        public uint? AccessErrorAddress;
        public int Cycles;
        public uint Address;
        public uint FirstAddress;

        public uint Read(int offset, int width)
        {
            if (offset == X99Platform.Spi.HardwareStatusRegister)
            {
                return Status;
            }
            if (offset == X99Platform.Spi.FlashRegionAccessPermissionsRegister)
            {
                return Permissions;
            }
            if (offset >= X99Platform.Spi.FirstFlashRegionRegister &&
                offset <= X99Platform.Spi.LastFlashRegionRegister)
            {
                int regionIndex = (offset - X99Platform.Spi.FirstFlashRegionRegister) /
                    X99Platform.Spi.FlashRegionRegisterStride;
                return RegionRegisters[regionIndex];
            }
            if (offset >= X99Platform.Spi.FlashData0Register && offset <= X99Platform.Spi.FlashDataLastRegister)
            {
                int dataOffset = offset - X99Platform.Spi.FlashData0Register;
                return BinaryPrimitives.ReadUInt32LittleEndian(
                    Flash.AsSpan(checked((int)Address + dataOffset), sizeof(uint)));
            }

            throw new AssertFailedException($"Unexpected register read at 0x{offset:X} with width {width}.");
        }

        public void Write(int offset, int width, uint value)
        {
            switch (offset)
            {
                case X99Platform.Spi.HardwareStatusRegister:
                    Assert.AreEqual(X99Platform.Spi.WordWidth, width);
                    Assert.AreEqual(0u, value & ~X99Platform.Spi.CompletionStatusWriteOneToClear);
                    Status &= ~value;
                    break;
                case X99Platform.Spi.FlashAddressRegister:
                    Assert.AreEqual(X99Platform.Spi.DwordWidth, width);
                    Assert.IsTrue(value <= FlashLength - X99Platform.Spi.TransferBytes);
                    Address = value;
                    if (Cycles == 0)
                    {
                        FirstAddress = value;
                    }
                    break;
                case X99Platform.Spi.HardwareControlRegister:
                    Assert.AreEqual(X99Platform.Spi.WordWidth, width);
                    Assert.AreEqual(X99Platform.Spi.ReadCycleCommand, value);
                    Cycles++;
                    bool cycleError = CycleErrorAddress == Address || CycleErrorsRemaining > 0;
                    if (CycleErrorsRemaining > 0)
                    {
                        CycleErrorsRemaining--;
                    }
                    Status |= cycleError
                        ? X99Platform.Spi.CycleError
                        : AccessErrorAddress == Address
                            ? X99Platform.Spi.AccessError
                            : X99Platform.Spi.CycleDone;
                    break;
                default:
                    throw new AssertFailedException($"Unexpected register write at 0x{offset:X} with width {width}.");
            }
        }
    }
}
