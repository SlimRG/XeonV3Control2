using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace XeonV3Control.App.Hardware;

internal enum TpmBootDebugReason : uint
{
    Unknown = 0,
    FirmwareSeesTpm2 = 1,
    Tcg2ProtocolTpmAbsent = 2,
    TpmRespondsTcg2Missing = 3,
    AcpiTpm2ButNoTpmResponse = 4,
    TpmRespondsAcpiTpm2Missing = 5,
    NoTpmResponse = 6,
    LegacyTcgOnly = 7,
    PciRootBridgeUnavailable = 8,
    Tcg2CapabilityFailed = 9,
    Tcg2AbsentButInterfaceValid = 10,
    Tcg2CapabilityDeferred = 11,
    AcpiDeviceDisabled = 12
}

internal sealed record TpmBootLocalityReadStatuses(
    ulong Access, ulong Status, ulong DidVid, ulong InterfaceId, ulong Rid);

internal sealed record TpmBootLocality(
    byte Access, byte Rid, uint Status, uint DidVid, uint InterfaceId, TpmBootLocalityReadStatuses? ReadStatuses = null)
{
    internal bool Responding =>
        (DidVid != 0 && DidVid != uint.MaxValue) ||
        (InterfaceId != 0 && InterfaceId != uint.MaxValue) ||
        Access != byte.MaxValue;
}

internal sealed record TpmBootRootBridge(
    uint SegmentNumber,
    uint Flags,
    uint BusMin,
    uint BusMax,
    uint LpcVendorDevice,
    ulong HandleProtocolStatus,
    ulong ConfigurationStatus,
    ulong LpcReadStatus)
{
    internal bool ConfigurationAvailable => (Flags & (1u << 0)) != 0;
    internal bool BusRangeAvailable => (Flags & (1u << 1)) != 0;
    internal bool WellsburgLpc => (Flags & (1u << 2)) != 0;
    internal bool Chosen => (Flags & (1u << 3)) != 0;
}

internal sealed record TpmBootDebugReport(
    ushort ReportVersion,
    uint Flags,
    TpmBootDebugReason Reason,
    uint RootBridgeCount,
    uint LpcVendorDevice,
    uint LpcRcba,
    IReadOnlyList<uint> LpcDecodeRegisters,
    ulong Tcg2LocateStatus,
    ulong Tcg2CapabilityStatus,
    ulong Tcg1LocateStatus,
    ulong RootBridgeLocateStatus,
    ulong AcpiStatus,
    ulong TisAccessReadStatus,
    ulong TisRegisterReadStatus,
    ulong Tpm2ControlReadStatus,
    byte TisAccess,
    byte TisRid,
    uint TisStatus,
    uint TisInterfaceCapability,
    uint TisDidVid,
    uint PtpInterfaceId,
    uint Tpm2TableCount,
    uint TcpaTableCount,
    uint Msft0101Count,
    uint Tpm2StartMethod,
    ulong Tpm2ControlArea,
    uint Tpm2ControlValue,
    byte Tcg2PresentFlag,
    byte Tcg2StructureMajor,
    byte Tcg2StructureMinor,
    byte Tcg2ProtocolMajor,
    byte Tcg2ProtocolMinor,
    uint Tcg2HashAlgorithmBitmap,
    uint Tcg2SupportedEventLogs,
    ushort Tcg2MaxCommandSize,
    ushort Tcg2MaxResponseSize,
    uint Tcg2ManufacturerId,
    uint Tcg2NumberOfPcrBanks,
    uint Tcg2ActivePcrBanks,
    uint FirmwareRevision,
    ulong MpServicesLocateStatus,
    ulong MpGetNumberStatus,
    uint ProcessorCount,
    uint EnabledProcessorCount,
    uint PackageCount,
    uint AcpiObjectFlags,
    ulong AcpiStaValue,
    uint AcpiCrsBufferLength,
    uint AcpiCrsFlags,
    ulong AcpiCrsMemoryBase,
    ulong AcpiCrsMemoryLength,
    uint AcpiCrsIrq,
    uint AcpiCrsIrqCount,
    uint AcpiPolicyFlags,
    ulong AcpiTcmfValue,
    ulong AcpiTtpfValue,
    ulong AcpiDtptValue,
    ulong AcpiTtdpValue,
    ulong AcpiAmdtValue,
    ulong AcpiTpmfValue,
    ulong AcpiTpmmValue,
    ulong AcpiFtpmValue,
    uint AcpiMsftDeviceOffset,
    uint AcpiMsftDeviceLength,
    ulong AcpiCidValue,
    ulong AcpiUidValue,
    string AcpiDevicePath,
    string AcpiCidString,
    string AcpiUidString,
    uint LocalityReadableMask,
    uint LocalityRespondingMask,
    IReadOnlyList<TpmBootLocality> Localities,
    uint RootBridgeStoredCount,
    uint ChosenRootBridgeIndex,
    uint RcbaSnapshotFlags,
    uint RcbaGcs,
    uint RcbaFunctionDisable,
    uint RcbaSpiBfpr,
    uint RcbaSpiHsfsHsfc,
    ulong RcbaGcsReadStatus,
    ulong RcbaFunctionDisableReadStatus,
    ulong RcbaSpiBfprReadStatus,
    ulong RcbaSpiHsfsHsfcReadStatus,
    IReadOnlyList<TpmBootRootBridge> RootBridges)
{
    internal bool Tcg2CapabilityAvailable => (Flags & (1u << 13)) != 0;
    internal bool ReadyToBootSnapshot => (Flags & (1u << 14)) != 0;
    internal bool Tcg2CapabilityDeferred => (Flags & (1u << 15)) != 0;
    internal bool MpServicesAvailable => (Flags & (1u << 16)) != 0;
    internal bool AcpiDeviceFound => (AcpiObjectFlags & (1u << 0)) != 0;
    internal bool AcpiStaStatic => (AcpiObjectFlags & (1u << 1)) != 0;
    internal bool AcpiStaMethod => (AcpiObjectFlags & (1u << 2)) != 0;
    internal bool AcpiCrsBuffer => (AcpiObjectFlags & (1u << 3)) != 0;
    internal bool AcpiCrsMethod => (AcpiObjectFlags & (1u << 4)) != 0;
    internal bool AcpiCidPresent => (AcpiObjectFlags & (1u << 5)) != 0;
    internal bool AcpiUidPresent => (AcpiObjectFlags & (1u << 6)) != 0;
    internal bool AcpiDsmPresent => (AcpiObjectFlags & (1u << 7)) != 0;
    internal bool AcpiCidStringAvailable => (AcpiObjectFlags & (1u << 8)) != 0;
    internal bool AcpiUidStringAvailable => (AcpiObjectFlags & (1u << 9)) != 0;
    internal bool AcpiUidIntegerAvailable => (AcpiObjectFlags & (1u << 10)) != 0;
    internal bool AcpiCidIntegerAvailable => (AcpiObjectFlags & (1u << 11)) != 0;
    internal bool AcpiCrsMemoryAvailable => (AcpiCrsFlags & (1u << 0)) != 0;
    internal bool AcpiCrsIrqAvailable => (AcpiCrsFlags & (1u << 1)) != 0;
    internal bool AcpiTcmfAvailable => (AcpiPolicyFlags & (1u << 0)) != 0;
    internal bool AcpiTtpfAvailable => (AcpiPolicyFlags & (1u << 1)) != 0;
    internal bool AcpiDtptAvailable => (AcpiPolicyFlags & (1u << 2)) != 0;
    internal bool AcpiTtdpAvailable => (AcpiPolicyFlags & (1u << 3)) != 0;
    internal bool AcpiAmdtAvailable => (AcpiPolicyFlags & (1u << 4)) != 0;
    internal bool AcpiTpmfAvailable => (AcpiPolicyFlags & (1u << 5)) != 0;
    internal bool AcpiTpmmAvailable => (AcpiPolicyFlags & (1u << 6)) != 0;
    internal bool AcpiFtpmAvailable => (AcpiPolicyFlags & (1u << 7)) != 0;
    internal bool RcbaGcsAvailable => (RcbaSnapshotFlags & (1u << 0)) != 0;
    internal bool RcbaFunctionDisableAvailable => (RcbaSnapshotFlags & (1u << 1)) != 0;
    internal bool RcbaSpiBfprAvailable => (RcbaSnapshotFlags & (1u << 2)) != 0;
    internal bool RcbaSpiHsfsHsfcAvailable => (RcbaSnapshotFlags & (1u << 3)) != 0;

    // The reference AMI X99 DSDT uses TCMF/TTDP exactly this way in _HID.
    // Keep this explicitly an inference from policy values rather than claiming AML execution.
    internal string? InferredAcpiHid => !AcpiDeviceFound || !AcpiTcmfAvailable || !AcpiTtdpAvailable
        ? null
        : AcpiTcmfValue != 0 ? "ZIT0101" : AcpiTtdpValue == 0 ? "PNP0C31" : "MSFT0101";

    internal ulong? InferredAcpiSta => !AcpiDeviceFound || !AcpiTpmfAvailable || !AcpiTtdpAvailable || AcpiTtdpValue > 1
        ? null
        : AcpiTpmfValue != 0 ? 0x0FUL : 0UL;

    internal string? InferredAcpiStr => !AcpiDeviceFound || !AcpiTtdpAvailable
        ? null
        : AcpiTtdpValue == 0 ? "TPM 1.2" : "TPM 2.0";
}

internal static partial class UefiTpmDebugReportReader
{
    private const string SafeVariableName = "XeonV3TpmDebugReportSafe";
    private const string LegacyVariableName = "XeonV3TpmDebugReport";
    private const string VendorGuid = "{77c232c4-f56c-4f1c-9759-47e64f5b3921}";
    private const uint Signature = 0x31445054;
    private const ushort LegacyVersion = 1;
    private const ushort PreviousVersion = 2;
    private const ushort CurrentVersion = 3;
    private const int LegacyReportBytes = 204;
    private const int PreviousReportBytes = 588;
    private const int CurrentReportBytes = 1232;
    private const int LegacyReportCrcOffset = 200;
    private const int PreviousReportCrcOffset = 584;
    private const int CurrentReportCrcOffset = 1228;
    private const int ErrorEnvironmentVariableNotFound = 203;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNotAllAssigned = 1300;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint SePrivilegeEnabled = 0x00000002;

    internal static TpmBootDebugReport? TryRead()
    {
        using PrivilegeLease privilege = EnableSystemEnvironmentPrivilege();
        byte[] buffer = new byte[CurrentReportBytes];

        uint read = ReadVariable(SafeVariableName, buffer, out int error);
        if (read == 0 && error == ErrorEnvironmentVariableNotFound)
        {
            // Compatibility with pre-SAFE report v1-v3. The SAFE driver deliberately
            // uses a new volatile variable name so it never mutates the old NVRAM entry.
            read = ReadVariable(LegacyVariableName, buffer, out error);
        }
        if (read == 0)
        {
            if (error == ErrorEnvironmentVariableNotFound)
            {
                return null;
            }
            if (error == ErrorInsufficientBuffer)
            {
                throw new InvalidDataException("TpmDebugReportInvalid");
            }
            throw new Win32Exception(error);
        }

        return Parse(buffer.AsSpan(0, checked((int)read)));
    }

    private static uint ReadVariable(string variableName, byte[] buffer, out int error)
    {
        uint read = Native.GetFirmwareEnvironmentVariableExW(
            variableName, VendorGuid, buffer, checked((uint)buffer.Length), out _);
        error = read == 0 ? Marshal.GetLastWin32Error() : 0;
        return read;
    }

    internal static TpmBootDebugReport Parse(ReadOnlySpan<byte> source)
    {
        int reportBytes = source.Length;
        if (reportBytes < 8 || U32(source, 0) != Signature)
        {
            throw new InvalidDataException("TpmDebugReportInvalid");
        }
        ushort version = U16(source, 4);
        int expectedBytes = version switch
        {
            LegacyVersion => LegacyReportBytes,
            PreviousVersion => PreviousReportBytes,
            CurrentVersion => CurrentReportBytes,
            _ => 0
        };
        int crcOffset = version switch
        {
            LegacyVersion => LegacyReportCrcOffset,
            PreviousVersion => PreviousReportCrcOffset,
            CurrentVersion => CurrentReportCrcOffset,
            _ => 0
        };
        if (expectedBytes == 0 || reportBytes != expectedBytes || U16(source, 6) != expectedBytes)
        {
            throw new InvalidDataException("TpmDebugReportInvalid");
        }
        uint expectedCrc = U32(source, crcOffset);
        Span<byte> crcBuffer = stackalloc byte[CurrentReportBytes];
        source.CopyTo(crcBuffer);
        BinaryPrimitives.WriteUInt32LittleEndian(crcBuffer.Slice(crcOffset, 4), 0);
        if (Crc32(crcBuffer[..reportBytes]) != expectedCrc)
        {
            throw new InvalidDataException("TpmDebugReportInvalid");
        }

        IReadOnlyList<TpmBootLocality> localities;
        if (version >= PreviousVersion)
        {
            var parsedLocalities = new TpmBootLocality[5];
            for (int index = 0; index < parsedLocalities.Length; index++)
            {
                int offset = 504 + (index * 16);
                TpmBootLocalityReadStatuses? statuses = null;
                if (version == CurrentVersion)
                {
                    int statusOffset = 1028 + (index * 40);
                    statuses = new TpmBootLocalityReadStatuses(
                        U64(source, statusOffset), U64(source, statusOffset + 8), U64(source, statusOffset + 16),
                        U64(source, statusOffset + 24), U64(source, statusOffset + 32));
                }
                parsedLocalities[index] = new TpmBootLocality(
                    source[offset], source[offset + 1], U32(source, offset + 4), U32(source, offset + 8), U32(source, offset + 12), statuses);
            }
            localities = parsedLocalities;
        }
        else
        {
            localities = [new TpmBootLocality(source[116], source[117], U32(source, 120), U32(source, 128), U32(source, 132))];
        }

        IReadOnlyList<TpmBootRootBridge> rootBridges = [];
        if (version == CurrentVersion)
        {
            int stored = checked((int)Math.Min(U32(source, 584), 8u));
            var parsedRootBridges = new TpmBootRootBridge[stored];
            for (int index = 0; index < parsedRootBridges.Length; index++)
            {
                int offset = 644 + (index * 48);
                parsedRootBridges[index] = new TpmBootRootBridge(
                    U32(source, offset), U32(source, offset + 4), U32(source, offset + 8), U32(source, offset + 12),
                    U32(source, offset + 16), U64(source, offset + 24), U64(source, offset + 32), U64(source, offset + 40));
            }
            rootBridges = parsedRootBridges;
        }

        return new TpmBootDebugReport(
            version,
            U32(source, 8),
            (TpmBootDebugReason)U32(source, 12),
            U32(source, 16),
            U32(source, 20),
            U32(source, 24),
            [U32(source, 28), U32(source, 32), U32(source, 36), U32(source, 40), U32(source, 44), U32(source, 48)],
            U64(source, 52), U64(source, 60), U64(source, 68), U64(source, 76),
            U64(source, 84), U64(source, 92), U64(source, 100), U64(source, 108),
            source[116], source[117], U32(source, 120), U32(source, 124), U32(source, 128), U32(source, 132),
            U32(source, 136), U32(source, 140), U32(source, 144), U32(source, 148), U64(source, 152),
            U32(source, 160), source[164], source[165], source[166], source[167], source[168],
            U32(source, 172), U32(source, 176), U16(source, 180), U16(source, 182), U32(source, 184),
            U32(source, 188), U32(source, 192), U32(source, 196),
            version >= PreviousVersion ? U64(source, 200) : 0,
            version >= PreviousVersion ? U64(source, 208) : 0,
            version >= PreviousVersion ? U32(source, 216) : 0,
            version >= PreviousVersion ? U32(source, 220) : 0,
            version >= PreviousVersion ? U32(source, 224) : 0,
            version >= PreviousVersion ? U32(source, 228) : 0,
            version >= PreviousVersion ? U64(source, 232) : 0,
            version >= PreviousVersion ? U32(source, 240) : 0,
            version >= PreviousVersion ? U32(source, 244) : 0,
            version >= PreviousVersion ? U64(source, 248) : 0,
            version >= PreviousVersion ? U64(source, 256) : 0,
            version >= PreviousVersion ? U32(source, 264) : 0,
            version >= PreviousVersion ? U32(source, 268) : 0,
            version >= PreviousVersion ? U32(source, 272) : 0,
            version >= PreviousVersion ? U64(source, 280) : 0,
            version >= PreviousVersion ? U64(source, 288) : 0,
            version >= PreviousVersion ? U64(source, 296) : 0,
            version >= PreviousVersion ? U64(source, 304) : 0,
            version >= PreviousVersion ? U64(source, 312) : 0,
            version >= PreviousVersion ? U64(source, 320) : 0,
            version >= PreviousVersion ? U64(source, 328) : 0,
            version >= PreviousVersion ? U64(source, 336) : 0,
            version >= PreviousVersion ? U32(source, 344) : 0,
            version >= PreviousVersion ? U32(source, 348) : 0,
            version >= PreviousVersion ? U64(source, 352) : 0,
            version >= PreviousVersion ? U64(source, 360) : 0,
            version >= PreviousVersion ? Ascii(source.Slice(368, 64)) : string.Empty,
            version >= PreviousVersion ? Ascii(source.Slice(432, 32)) : string.Empty,
            version >= PreviousVersion ? Ascii(source.Slice(464, 32)) : string.Empty,
            version >= PreviousVersion ? U32(source, 496) : 1u,
            version >= PreviousVersion ? U32(source, 500) : (localities[0].Responding ? 1u : 0u),
            localities,
            version == CurrentVersion ? U32(source, 584) : 0u,
            version == CurrentVersion ? U32(source, 588) : uint.MaxValue,
            version == CurrentVersion ? U32(source, 592) : 0u,
            version == CurrentVersion ? U32(source, 596) : 0u,
            version == CurrentVersion ? U32(source, 600) : 0u,
            version == CurrentVersion ? U32(source, 604) : 0u,
            version == CurrentVersion ? U32(source, 608) : 0u,
            version == CurrentVersion ? U64(source, 612) : 0ul,
            version == CurrentVersion ? U64(source, 620) : 0ul,
            version == CurrentVersion ? U64(source, 628) : 0ul,
            version == CurrentVersion ? U64(source, 636) : 0ul,
            rootBridges);
    }

    private static string Ascii(ReadOnlySpan<byte> data)
    {
        int terminator = data.IndexOf((byte)0);
        ReadOnlySpan<byte> text = terminator >= 0 ? data[..terminator] : data;
        return System.Text.Encoding.ASCII.GetString(text);
    }

    private static PrivilegeLease EnableSystemEnvironmentPrivilege()
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), TokenQuery | TokenAdjustPrivileges, out nint token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            if (!Native.LookupPrivilegeValueW(null, "SeSystemEnvironmentPrivilege", out Luid luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var state = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            uint previousBytes = checked((uint)Marshal.SizeOf<TokenPrivileges>());
            Marshal.SetLastPInvokeError(0);
            if (!Native.AdjustTokenPrivilegesCapture(
                    token, false, ref state, previousBytes, out TokenPrivileges previousState, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            int error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotAllAssigned)
            {
                throw new Win32Exception(error);
            }
            return new PrivilegeLease(token, previousState);
        }
        catch
        {
            Native.CloseHandle(token);
            throw;
        }
    }

    private static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
    private static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
    private static ulong U64(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in data)
        {
            uint x = (crc ^ value) & 0xFFu;
            for (int bit = 0; bit < 8; bit++)
            {
                x = (x >> 1) ^ ((x & 1u) != 0 ? 0xEDB88320u : 0u);
            }
            crc = (crc >> 8) ^ x;
        }
        return ~crc;
    }

    private sealed class PrivilegeLease : IDisposable
    {
        private readonly nint token;
        private TokenPrivileges previousState;
        private int disposed;

        internal PrivilegeLease(nint token, TokenPrivileges previousState)
        {
            this.token = token;
            this.previousState = previousState;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            try
            {
                Marshal.SetLastPInvokeError(0);
                if (!Native.AdjustTokenPrivilegesRestore(
                        token, false, ref previousState, 0, nint.Zero, nint.Zero))
                {
                    XeonV3Control.App.AppLog.Error(new Win32Exception(Marshal.GetLastWin32Error()));
                }
                else
                {
                    int error = Marshal.GetLastPInvokeError();
                    if (error != 0)
                    {
                        XeonV3Control.App.AppLog.Error(new Win32Exception(error));
                    }
                }
            }
            finally
            {
                Native.CloseHandle(token);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { internal uint LowPart; internal int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        internal uint PrivilegeCount;
        internal Luid Luid;
        internal uint Attributes;
    }

    private static partial class Native
    {
        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial uint GetFirmwareEnvironmentVariableExW(
            string lpName, string lpGuid, byte[] pBuffer, uint nSize, out uint pdwAttribubutes);

        [LibraryImport("kernel32.dll")]
        internal static partial nint GetCurrentProcess();

        [LibraryImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CloseHandle(nint handle);

        [LibraryImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool OpenProcessToken(nint process, uint desiredAccess, out nint tokenHandle);

        [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

        [LibraryImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool AdjustTokenPrivilegesCapture(
            nint tokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState, uint bufferLength, out TokenPrivileges previousState, out uint returnLength);

        [LibraryImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool AdjustTokenPrivilegesRestore(
            nint tokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState, uint bufferLength, nint previousState, nint returnLength);
    }
}
