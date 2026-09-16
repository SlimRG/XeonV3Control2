namespace XeonV3Control.Core;

/// <summary>Intel C610/X99 hardware constants used by the fail-closed SPI read/write paths.</summary>
public static class X99Platform
{
    public const int CpuIdVendorLeaf = 0;
    public const int CpuIdVersionLeaf = 1;
    public const int CpuBaseFamilyShift = 8;
    public const int CpuBaseModelShift = 4;
    public const int CpuExtendedModelShift = 12;
    public const int CpuNibbleMask = 0x0F;
    public const int CpuExtendedModelMask = 0xF0;

    public const int IntelCpuFamily = 6;
    public const int HaswellEModel = 0x3F;
    public const int BroadwellEModel = 0x4F;

    // CPUID vendor string "GenuineIntel" returned as EBX, EDX, ECX.
    public const int IntelVendorEbx = 0x756E6547;
    public const int IntelVendorEdx = 0x49656E69;
    public const int IntelVendorEcx = 0x6C65746E;

    public const uint LpcVendorDeviceRegister = 0x00;
    public const uint LpcRcbaRegister = 0xF0;
    public const uint LpcBiosControlRegister = 0xDC;
    public const byte BiosWriteEnable = 1 << 0;
    public const byte BiosLockEnable = 1 << 1;
    public const byte SmmBiosWriteProtection = 1 << 5;
    public const int LpcBusNumber = 0;
    public const int LpcDeviceNumber = 31;
    public const int LpcFunctionNumber = 0;
    public const uint WellsburgLpcDeviceId8D40 = 0x8D408086u;
    public const uint WellsburgLpcDeviceId8D44 = 0x8D448086u;
    public const uint WellsburgLpcDeviceId8D47 = 0x8D478086u;
    public const uint RcbaEnableFlag = 1u;
    public const uint RcbaAddressMask = 0xFFFFC000u;
    public const uint SpiBarOffsetFromRcba = 0x3800u;

    public static bool IsSupportedCpuModel(int model) => model is HaswellEModel or BroadwellEModel;

    public static bool IsSupportedLpcDeviceId(uint vendorDeviceId) => vendorDeviceId is
        WellsburgLpcDeviceId8D40 or
        WellsburgLpcDeviceId8D44 or
        WellsburgLpcDeviceId8D47;

    public static class Spi
    {
        public const int HardwareStatusRegister = 0x04;
        public const int HardwareControlRegister = 0x06;
        public const int FlashAddressRegister = 0x08;
        public const int FlashData0Register = 0x10;
        public const int FlashDataLastRegister = 0x4C;
        public const int FlashRegionAccessPermissionsRegister = 0x50;
        public const int FlashDescriptorRegionRegister = 0x54;
        public const int BiosRegionRegister = 0x58;
        public const int ManagementEngineRegionRegister = 0x5C;
        public const int GigabitEthernetRegionRegister = 0x60;
        public const int PlatformDataRegionRegister = 0x64;
        public const int ProtectedRange0Register = 0x74;
        public const int ProtectedRange4Register = 0x84;
        public const int ProtectedRangeRegisterStride = sizeof(uint);
        public const int ProtectedRangeCount = 5;
        public const int FirstFlashRegionRegister = FlashDescriptorRegionRegister;
        public const int LastFlashRegionRegister = PlatformDataRegionRegister;
        public const int FlashRegionRegisterStride = sizeof(uint);
        public const int FlashRegionCount = 5;

        public const int ByteWidth = 1;
        public const int WordWidth = 2;
        public const int DwordWidth = 4;

        public const uint FlashConfigurationLockDown = 1u << 15;
        public const uint DescriptorValid = 1u << 14;
        public const uint CycleInProgress = 1u << 5;
        public const uint BlockEraseSizeMask = 3u << 3;
        public const uint BlockEraseSize4K = 1u << 3;
        public const uint AccessError = 1u << 2;
        public const uint CycleError = 1u << 1;
        public const uint CycleDone = 1u;
        public const uint CompletionStatusWriteOneToClear = CycleDone | CycleError | AccessError;
        public const uint DescriptorRegionReadAccess = 1u << 0;
        public const uint BiosRegionReadAccess = 1u << 1;
        public const uint ManagementEngineRegionReadAccess = 1u << 2;
        public const uint GigabitEthernetRegionReadAccess = 1u << 3;
        public const uint PlatformDataRegionReadAccess = 1u << 4;
        public const uint RegionReadAccessMask = 0xFFu;
        public const uint RegionWriteAccessMask = 0xFF00u;

        public const int TransferBytes = 64;
        public const int TransferDwords = TransferBytes / DwordWidth;
        public const uint ReadCycleCommand = ((TransferBytes - 1u) << 8) | 1u;
        // Wellsburg uses the ICH9-style FCYCLE encoding: 0=read, 2=write, 3=block erase.
        // Direct flashing permits FCYCLE=3 only after HSFS.BERASE is preflighted as 4 KiB.
        public const uint ProgramCycleCommand = ((TransferBytes - 1u) << 8) | (2u << 1) | 1u;
        public const uint Erase4KCycleCommand = (3u << 1) | 1u;
        public const int ProgressReportIntervalBytes = 64 * 1024;
        public static readonly TimeSpan ReadCycleTimeout = TimeSpan.FromSeconds(1);

        // C610/X99 FREG and PR fields encode FLA bits 24:12 (13 bits).
        public const uint RegionFieldMask = 0x1FFFu;
        public const uint RegionBaseReservedBit = 1u << 13;
        public const uint RegionLimitReservedBit = 1u << 29;
        public const uint RegionBaseReservedBitsMask = 0x0000_E000u;
        public const uint RegionLimitReservedBitsMask = 0xE000_0000u;
        public const uint RegionReservedBitsMask = RegionBaseReservedBitsMask | RegionLimitReservedBitsMask;

        public const uint ProtectedRangeFieldMask = 0x1FFFu;
        public const uint ProtectedRangeWriteProtection = 1u << 31;
        public const uint ProtectedRangeReadProtection = 1u << 15;
        public const uint ProtectedRangeReservedBitsMask = 0x6000_6000u;
        public const int RegionAddressShift = 12;
        public const uint RegionTailMask = (1u << RegionAddressShift) - 1u;
        // Wellsburg uses the pre-PCH100 hardware-sequencing FADDR field (25 address bits).
        public const uint FlashAddressMask = 0x01FF_FFFFu;
        public const uint MaximumHardwareSequenceAddressExclusive = FlashAddressMask + 1u;
        public const uint MaximumFlashAddressExclusive = MaximumHardwareSequenceAddressExclusive;
        public const int MinimumReadableBiosRegionBytes = 512 * 1024;
    }
}
