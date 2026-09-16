/*
 * XeonV3Control2 TPM boot diagnostic DXE driver.
 *
 * Passive diagnostics only: the driver does not request a TPM locality, does not
 * send TPM commands and does not change chipset decode registers. It records
 * what firmware itself exposes during DXE and a small set of read-only Wellsburg
 * / TPM MMIO observations into a vendor UEFI variable consumed by the app.
 */

typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;
typedef unsigned long long UINTN;
typedef unsigned long long EFI_STATUS;
typedef void*              EFI_HANDLE;
typedef void*              EFI_EVENT;
typedef UINT16             CHAR16;
typedef UINT8              BOOLEAN;

#define EFIAPI __attribute__((ms_abi))
#define EFI_SUCCESS ((EFI_STATUS)0)
#define EFI_ERROR(Status) (((Status) & (1ULL << 63)) != 0)
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002U
#define EFI_VARIABLE_RUNTIME_ACCESS     0x00000004U
#define EFI_LOCATE_BY_PROTOCOL          2U
#define EVT_NOTIFY_SIGNAL                0x00000200U
#define TPL_CALLBACK                     8U
#define EFI_NOT_READY ((EFI_STATUS)((1ULL << 63) | 6ULL))

#define REPORT_SIGNATURE 0x31445054U /* "TPD1" */
#define REPORT_VERSION 3U
#define REPORT_MAX_ACPI_TABLES 256U
#define ACPI_MAX_TABLE_BYTES (1024U * 1024U)
#define TPM_TIS_BASE 0xFED40000ULL
#define TPM_LOCALITY_COUNT 5U
#define TPM_LOCALITY_STRIDE 0x1000ULL
#define ROOT_BRIDGE_REPORT_COUNT 8U
#define ACPI_DEVICE_PATH_BYTES 64U
#define ACPI_ID_STRING_BYTES 32U

#define ROOT_BRIDGE_FLAG_CONFIGURATION_OK (1U << 0)
#define ROOT_BRIDGE_FLAG_BUS_RANGE        (1U << 1)
#define ROOT_BRIDGE_FLAG_WELLSBURG_LPC    (1U << 2)
#define ROOT_BRIDGE_FLAG_CHOSEN           (1U << 3)

#define RCBA_SNAPSHOT_GCS            (1U << 0)
#define RCBA_SNAPSHOT_FUNCTION_DISABLE (1U << 1)
#define RCBA_SNAPSHOT_SPI_BFPR       (1U << 2)
#define RCBA_SNAPSHOT_SPI_HSFS_HSFC  (1U << 3)

#define FLAG_TCG2_PROTOCOL           (1U << 0)
#define FLAG_TCG2_TPM_PRESENT        (1U << 1)
#define FLAG_TCG1_PROTOCOL           (1U << 2)
#define FLAG_ACPI_PRESENT            (1U << 3)
#define FLAG_ACPI_TPM2               (1U << 4)
#define FLAG_ACPI_TCPA               (1U << 5)
#define FLAG_ACPI_MSFT0101           (1U << 6)
#define FLAG_TIS_READABLE            (1U << 7)
#define FLAG_TIS_DID_VID_VALID       (1U << 8)
#define FLAG_TIS_ACCESS_VALID        (1U << 9)
#define FLAG_PTP_INTERFACE_VALID     (1U << 10)
#define FLAG_LPC_PRESENT             (1U << 11)
#define FLAG_TPM2_CONTROL_READABLE   (1U << 12)
#define FLAG_TCG2_CAPABILITY_OK      (1U << 13)
#define FLAG_REPORT_READY_TO_BOOT     (1U << 14)
#define FLAG_TCG2_CAPABILITY_SKIPPED  (1U << 15)
#define FLAG_MP_SERVICES_PRESENT       (1U << 16)
#define FLAG_ACPI_DEVICE_FOUND         (1U << 17)

#define REASON_UNKNOWN                         0U
#define REASON_FIRMWARE_SEES_TPM2              1U
#define REASON_TCG2_PROTOCOL_TPM_ABSENT        2U
#define REASON_TPM_RESPONDS_TCG2_MISSING       3U
#define REASON_ACPI_TPM2_BUT_NO_TPM_RESPONSE   4U
#define REASON_TPM_RESPONDS_ACPI_TPM2_MISSING  5U
#define REASON_NO_TPM_RESPONSE                 6U
#define REASON_LEGACY_TCG_ONLY                 7U
#define REASON_PCI_ROOT_BRIDGE_UNAVAILABLE     8U
#define REASON_TCG2_CAPABILITY_FAILED          9U
#define REASON_TCG2_ABSENT_BUT_INTERFACE_VALID  10U
#define REASON_TCG2_CAPABILITY_DEFERRED 11U
#define REASON_ACPI_DEVICE_DISABLED       12U

#define ACPI_SIG_RSDT 0x54445352U
#define ACPI_SIG_XSDT 0x54445358U
#define ACPI_SIG_TPM2 0x324D5054U
#define ACPI_SIG_TCPA 0x41504354U
#define ACPI_SIG_FACP 0x50434146U
#define ACPI_SIG_DSDT 0x54445344U

#define ACPI_OBJ_DEVICE_FOUND       (1U << 0)
#define ACPI_OBJ_STA_STATIC         (1U << 1)
#define ACPI_OBJ_STA_METHOD         (1U << 2)
#define ACPI_OBJ_CRS_BUFFER         (1U << 3)
#define ACPI_OBJ_CRS_METHOD         (1U << 4)
#define ACPI_OBJ_CID_PRESENT        (1U << 5)
#define ACPI_OBJ_UID_PRESENT        (1U << 6)
#define ACPI_OBJ_DSM_PRESENT        (1U << 7)
#define ACPI_OBJ_CID_STRING         (1U << 8)
#define ACPI_OBJ_UID_STRING         (1U << 9)
#define ACPI_OBJ_UID_INTEGER        (1U << 10)
#define ACPI_OBJ_CID_INTEGER        (1U << 11)

#define ACPI_CRS_MEMORY_FOUND       (1U << 0)
#define ACPI_CRS_IRQ_FOUND          (1U << 1)

#define ACPI_POLICY_TCMF_FOUND      (1U << 0)
#define ACPI_POLICY_TTPF_FOUND      (1U << 1)
#define ACPI_POLICY_DTPT_FOUND      (1U << 2)
#define ACPI_POLICY_TTDP_FOUND      (1U << 3)
#define ACPI_POLICY_AMDT_FOUND      (1U << 4)
#define ACPI_POLICY_TPMF_FOUND      (1U << 5)
#define ACPI_POLICY_TPMM_FOUND      (1U << 6)
#define ACPI_POLICY_FTPM_FOUND      (1U << 7)

#define AML_SCOPE_OP          0x10U
#define AML_BUFFER_OP         0x11U
#define AML_METHOD_OP         0x14U
#define AML_EXT_OP_PREFIX     0x5BU
#define AML_DEVICE_OP         0x82U
#define AML_NAME_OP           0x08U
#define AML_BYTE_PREFIX       0x0AU
#define AML_WORD_PREFIX       0x0BU
#define AML_DWORD_PREFIX      0x0CU
#define AML_STRING_PREFIX     0x0DU
#define AML_QWORD_PREFIX      0x0EU
#define AML_ZERO_OP           0x00U
#define AML_ONE_OP            0x01U
#define AML_ONES_OP           0xFFU
#define AML_ROOT_CHAR         0x5CU
#define AML_PARENT_PREFIX     0x5EU
#define AML_DUAL_NAME_PREFIX  0x2EU
#define AML_MULTI_NAME_PREFIX 0x2FU


#define PCI_LPC_BUS 0U
#define PCI_LPC_DEVICE 31U
#define PCI_LPC_FUNCTION 0U
#define PCI_LPC_VENDOR_DEVICE 0x00U
#define PCI_LPC_RCBA 0xF0U
#define WELLSBURG_8D40 0x8D408086U
#define WELLSBURG_8D44 0x8D448086U
#define WELLSBURG_8D47 0x8D478086U

#define RB_WIDTH_UINT8 0U
#define RB_WIDTH_UINT16 1U
#define RB_WIDTH_UINT32 2U

#pragma pack(push, 1)
typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8  Data4[8];
} EFI_GUID;
#pragma pack(pop)

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef struct {
    EFI_GUID VendorGuid;
    void* VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef EFI_STATUS (EFIAPI *EFI_FREE_POOL)(void* Buffer);
typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE Handle, EFI_GUID* Protocol, void** Interface);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_HANDLE_BUFFER)(UINT32 SearchType, EFI_GUID* Protocol, void* SearchKey,
                                                       UINTN* NoHandles, EFI_HANDLE** Buffer);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_PROTOCOL)(EFI_GUID* Protocol, void* Registration, void** Interface);
typedef void (EFIAPI *EFI_EVENT_NOTIFY)(EFI_EVENT Event, void* Context);
typedef EFI_STATUS (EFIAPI *EFI_CREATE_EVENT_EX)(UINT32 Type, UINTN NotifyTpl, EFI_EVENT_NOTIFY NotifyFunction,
                                                  void* NotifyContext, EFI_GUID* EventGroup, EFI_EVENT* Event);

typedef struct {
    EFI_TABLE_HEADER Hdr;
    void* RaiseTPL;
    void* RestoreTPL;
    void* AllocatePages;
    void* FreePages;
    void* GetMemoryMap;
    void* AllocatePool;
    EFI_FREE_POOL FreePool;
    void* CreateEvent;
    void* SetTimer;
    void* WaitForEvent;
    void* SignalEvent;
    void* CloseEvent;
    void* CheckEvent;
    void* InstallProtocolInterface;
    void* ReinstallProtocolInterface;
    void* UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL HandleProtocol;
    void* Reserved;
    void* RegisterProtocolNotify;
    void* LocateHandle;
    void* LocateDevicePath;
    void* InstallConfigurationTable;
    void* LoadImage;
    void* StartImage;
    void* Exit;
    void* UnloadImage;
    void* ExitBootServices;
    void* GetNextMonotonicCount;
    void* Stall;
    void* SetWatchdogTimer;
    void* ConnectController;
    void* DisconnectController;
    void* OpenProtocol;
    void* CloseProtocol;
    void* OpenProtocolInformation;
    void* ProtocolsPerHandle;
    EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
    EFI_LOCATE_PROTOCOL LocateProtocol;
    void* InstallMultipleProtocolInterfaces;
    void* UninstallMultipleProtocolInterfaces;
    void* CalculateCrc32;
    void* CopyMem;
    void* SetMem;
    EFI_CREATE_EVENT_EX CreateEventEx;
} EFI_BOOT_SERVICES;

typedef EFI_STATUS (EFIAPI *EFI_SET_VARIABLE)(CHAR16* VariableName, EFI_GUID* VendorGuid,
                                               UINT32 Attributes, UINTN DataSize, void* Data);

typedef struct {
    EFI_TABLE_HEADER Hdr;
    void* GetTime;
    void* SetTime;
    void* GetWakeupTime;
    void* SetWakeupTime;
    void* SetVirtualAddressMap;
    void* ConvertPointer;
    void* GetVariable;
    void* GetNextVariableName;
    EFI_SET_VARIABLE SetVariable;
    void* GetNextHighMonotonicCount;
    void* ResetSystem;
    void* UpdateCapsule;
    void* QueryCapsuleCapabilities;
    void* QueryVariableInfo;
} EFI_RUNTIME_SERVICES;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16* FirmwareVendor;
    UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void* ConIn;
    EFI_HANDLE ConsoleOutHandle;
    void* ConOut;
    EFI_HANDLE StandardErrorHandle;
    void* StdErr;
    EFI_RUNTIME_SERVICES* RuntimeServices;
    EFI_BOOT_SERVICES* BootServices;
    UINTN NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE* ConfigurationTable;
} EFI_SYSTEM_TABLE;

typedef EFI_STATUS (EFIAPI *RB_ACCESS_READ)(void* This, UINT32 Width, UINT64 Address, UINTN Count, void* Buffer);
typedef EFI_STATUS (EFIAPI *RB_ACCESS_WRITE)(void* This, UINT32 Width, UINT64 Address, UINTN Count, void* Buffer);
typedef struct {
    RB_ACCESS_READ Read;
    RB_ACCESS_WRITE Write;
} RB_ACCESS;

typedef struct {
    EFI_HANDLE ParentHandle;
    void* PollMem;
    void* PollIo;
    RB_ACCESS Mem;
    RB_ACCESS Io;
    RB_ACCESS Pci;
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL;

typedef struct {
    UINT32 Package;
    UINT32 Core;
    UINT32 Thread;
} EFI_CPU_PHYSICAL_LOCATION;

typedef struct {
    UINT64 ProcessorId;
    UINT32 StatusFlag;
    EFI_CPU_PHYSICAL_LOCATION Location;
} EFI_PROCESSOR_INFORMATION;

typedef EFI_STATUS (EFIAPI *MP_GET_NUMBER_OF_PROCESSORS)(void* This, UINTN* NumberOfProcessors, UINTN* NumberOfEnabledProcessors);
typedef EFI_STATUS (EFIAPI *MP_GET_PROCESSOR_INFO)(void* This, UINTN ProcessorNumber, EFI_PROCESSOR_INFORMATION* ProcessorInfo);
typedef struct {
    MP_GET_NUMBER_OF_PROCESSORS GetNumberOfProcessors;
    MP_GET_PROCESSOR_INFO GetProcessorInfo;
    void* StartupAllAPs;
    void* StartupThisAP;
    void* SwitchBSP;
    void* EnableDisableAP;
    void* WhoAmI;
} EFI_MP_SERVICES_PROTOCOL;

#pragma pack(push, 1)
typedef struct {
    UINT8 Major;
    UINT8 Minor;
} EFI_TCG2_VERSION;
#pragma pack(pop)

typedef struct {
    UINT8 Size;
    EFI_TCG2_VERSION StructureVersion;
    EFI_TCG2_VERSION ProtocolVersion;
    UINT32 HashAlgorithmBitmap;
    UINT32 SupportedEventLogs;
    BOOLEAN TPMPresentFlag;
    UINT8 ReservedForAlignment;
    UINT16 MaxCommandSize;
    UINT16 MaxResponseSize;
    UINT32 ManufacturerID;
    UINT32 NumberOfPCRBanks;
    UINT32 ActivePcrBanks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY;

typedef EFI_STATUS (EFIAPI *TCG2_GET_CAPABILITY)(void* This, EFI_TCG2_BOOT_SERVICE_CAPABILITY* Capability);
typedef struct {
    TCG2_GET_CAPABILITY GetCapability;
    void* GetEventLog;
    void* HashLogExtendEvent;
    void* SubmitCommand;
    void* GetActivePcrBanks;
    void* SetActivePcrBanks;
    void* GetResultOfSetActivePcrBanks;
} EFI_TCG2_PROTOCOL;

#pragma pack(push, 1)
typedef struct {
    char Signature[8];
    UINT8 Checksum;
    char OemId[6];
    UINT8 Revision;
    UINT32 RsdtAddress;
    UINT32 Length;
    UINT64 XsdtAddress;
    UINT8 ExtendedChecksum;
    UINT8 Reserved[3];
} ACPI_RSDP;

typedef struct {
    UINT32 Signature;
    UINT32 Length;
    UINT8 Revision;
    UINT8 Checksum;
    char OemId[6];
    char OemTableId[8];
    UINT32 OemRevision;
    UINT32 CreatorId;
    UINT32 CreatorRevision;
} ACPI_HEADER;

typedef struct {
    ACPI_HEADER Header;
    UINT32 Flags;
    UINT64 ControlArea;
    UINT32 StartMethod;
} ACPI_TPM2_MIN;

typedef struct {
    UINT8 Access;
    UINT8 Rid;
    UINT16 Reserved;
    UINT32 Status;
    UINT32 DidVid;
    UINT32 InterfaceId;
} TPM_LOCALITY_REPORT;

typedef struct {
    UINT64 AccessStatus;
    UINT64 StatusStatus;
    UINT64 DidVidStatus;
    UINT64 InterfaceIdStatus;
    UINT64 RidStatus;
} TPM_LOCALITY_STATUS_REPORT;

typedef struct {
    UINT32 SegmentNumber;
    UINT32 Flags;
    UINT32 BusMin;
    UINT32 BusMax;
    UINT32 LpcVendorDevice;
    UINT32 Reserved;
    UINT64 HandleProtocolStatus;
    UINT64 ConfigurationStatus;
    UINT64 LpcReadStatus;
} ROOT_BRIDGE_REPORT;

typedef struct {
    UINT32 Signature;
    UINT16 Version;
    UINT16 Size;
    UINT32 Flags;
    UINT32 Reason;
    UINT32 RootBridgeCount;
    UINT32 LpcVendorDevice;
    UINT32 LpcRcba;
    UINT32 LpcDecode80;
    UINT32 LpcDecode84;
    UINT32 LpcDecode88;
    UINT32 LpcDecode8C;
    UINT32 LpcDecode90;
    UINT32 LpcDecode98;
    UINT64 Tcg2LocateStatus;
    UINT64 Tcg2CapabilityStatus;
    UINT64 Tcg1LocateStatus;
    UINT64 RootBridgeLocateStatus;
    UINT64 AcpiStatus;
    UINT64 TisAccessReadStatus;
    UINT64 TisRegisterReadStatus;
    UINT64 Tpm2ControlReadStatus;
    UINT8 TisAccess;
    UINT8 TisRid;
    UINT16 Reserved0;
    UINT32 TisStatus;
    UINT32 TisInterfaceCapability;
    UINT32 TisDidVid;
    UINT32 PtpInterfaceId;
    UINT32 Tpm2TableCount;
    UINT32 TcpaTableCount;
    UINT32 Msft0101Count;
    UINT32 Tpm2StartMethod;
    UINT64 Tpm2ControlArea;
    UINT32 Tpm2ControlValue;
    UINT8 Tcg2PresentFlag;
    UINT8 Tcg2StructureMajor;
    UINT8 Tcg2StructureMinor;
    UINT8 Tcg2ProtocolMajor;
    UINT8 Tcg2ProtocolMinor;
    UINT8 Reserved1[3];
    UINT32 Tcg2HashAlgorithmBitmap;
    UINT32 Tcg2SupportedEventLogs;
    UINT16 Tcg2MaxCommandSize;
    UINT16 Tcg2MaxResponseSize;
    UINT32 Tcg2ManufacturerId;
    UINT32 Tcg2NumberOfPcrBanks;
    UINT32 Tcg2ActivePcrBanks;
    UINT32 FirmwareRevision;
    UINT64 MpServicesLocateStatus;
    UINT64 MpGetNumberStatus;
    UINT32 ProcessorCount;
    UINT32 EnabledProcessorCount;
    UINT32 PackageCount;
    UINT32 AcpiObjectFlags;
    UINT64 AcpiStaValue;
    UINT32 AcpiCrsBufferLength;
    UINT32 AcpiCrsFlags;
    UINT64 AcpiCrsMemoryBase;
    UINT64 AcpiCrsMemoryLength;
    UINT32 AcpiCrsIrq;
    UINT32 AcpiCrsIrqCount;
    UINT32 AcpiPolicyFlags;
    UINT32 AcpiPolicyReserved;
    UINT64 AcpiTcmfValue;
    UINT64 AcpiTtpfValue;
    UINT64 AcpiDtptValue;
    UINT64 AcpiTtdpValue;
    UINT64 AcpiAmdtValue;
    UINT64 AcpiTpmfValue;
    UINT64 AcpiTpmmValue;
    UINT64 AcpiFtpmValue;
    UINT32 AcpiMsftDeviceOffset;
    UINT32 AcpiMsftDeviceLength;
    UINT64 AcpiCidValue;
    UINT64 AcpiUidValue;
    char AcpiDevicePath[ACPI_DEVICE_PATH_BYTES];
    char AcpiCidString[ACPI_ID_STRING_BYTES];
    char AcpiUidString[ACPI_ID_STRING_BYTES];
    UINT32 LocalityReadableMask;
    UINT32 LocalityRespondingMask;
    TPM_LOCALITY_REPORT Localities[TPM_LOCALITY_COUNT];
    UINT32 RootBridgeStoredCount;
    UINT32 ChosenRootBridgeIndex;
    UINT32 RcbaSnapshotFlags;
    UINT32 RcbaGcs;
    UINT32 RcbaFunctionDisable;
    UINT32 RcbaSpiBfpr;
    UINT32 RcbaSpiHsfsHsfc;
    UINT64 RcbaGcsReadStatus;
    UINT64 RcbaFunctionDisableReadStatus;
    UINT64 RcbaSpiBfprReadStatus;
    UINT64 RcbaSpiHsfsHsfcReadStatus;
    ROOT_BRIDGE_REPORT RootBridges[ROOT_BRIDGE_REPORT_COUNT];
    TPM_LOCALITY_STATUS_REPORT LocalityStatuses[TPM_LOCALITY_COUNT];
    UINT32 ReportCrc32;
} TPM_DEBUG_REPORT;
#pragma pack(pop)

_Static_assert(sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY) == 36U, "Unexpected EFI_TCG2_BOOT_SERVICE_CAPABILITY layout");
_Static_assert(sizeof(TPM_LOCALITY_REPORT) == 16U, "Unexpected TPM_LOCALITY_REPORT layout");
_Static_assert(sizeof(ROOT_BRIDGE_REPORT) == 48U, "Unexpected ROOT_BRIDGE_REPORT layout");
_Static_assert(sizeof(TPM_LOCALITY_STATUS_REPORT) == 40U, "Unexpected TPM_LOCALITY_STATUS_REPORT layout");
_Static_assert(sizeof(TPM_DEBUG_REPORT) == 1232U, "Unexpected TPM_DEBUG_REPORT layout");

static EFI_GUID gTcg2ProtocolGuid = {0x607f766cU, 0x7455U, 0x42beU, {0x93U,0x0bU,0xe4U,0xd7U,0x6dU,0xb2U,0x72U,0x0fU}};
static EFI_GUID gTcg1ProtocolGuid = {0xf541796dU, 0xa62eU, 0x4954U, {0xa7U,0x75U,0x95U,0x84U,0xf6U,0x1bU,0x9cU,0xddU}};
static EFI_GUID gAcpi20TableGuid = {0x8868e871U, 0xe4f1U, 0x11d3U, {0xbcU,0x22U,0x00U,0x80U,0xc7U,0x3cU,0x88U,0x81U}};
static EFI_GUID gAcpi10TableGuid = {0xeb9d2d30U, 0x2d88U, 0x11d3U, {0x9aU,0x16U,0x00U,0x90U,0x27U,0x3fU,0xc1U,0x4dU}};
static EFI_GUID gMpServicesGuid = {0x3fdda605U, 0xa76eU, 0x4f46U, {0xadU,0x29U,0x12U,0xf4U,0x53U,0x1bU,0x3dU,0x08U}};
static EFI_GUID gRootBridgeIoGuid = {0x2f707ebbU, 0x4a1aU, 0x11d4U, {0x9aU,0x38U,0x00U,0x90U,0x27U,0x3fU,0xc1U,0x4dU}};
static EFI_GUID gReadyToBootEventGuid = {0x7ce88fb3U, 0x4bd7U, 0x4679U, {0x87U,0xa8U,0xa8U,0xd8U,0xdeU,0xe5U,0x0dU,0x2bU}};
static EFI_GUID gReportVendorGuid = {0x77c232c4U, 0xf56cU, 0x4f1cU, {0x97U,0x59U,0x47U,0xe6U,0x4fU,0x5bU,0x39U,0x21U}};
static CHAR16 gReportVariableName[] = {'X','e','o','n','V','3','T','p','m','D','e','b','u','g','R','e','p','o','r','t','S','a','f','e',0};

/* Force a base relocation into the PE image so firmware may load the driver anywhere. */
static void* volatile gRelocationAnchor = (void*)&gReportVariableName;

static UINT32 Crc32(const void* data, UINTN size)
{
    const UINT8* p = (const UINT8*)data;
    UINT32 crc = 0xFFFFFFFFU;
    UINTN i;
    for (i = 0; i < size; ++i) {
        UINT32 x = (crc ^ p[i]) & 0xFFU;
        UINT32 bit;
        for (bit = 0; bit < 8U; ++bit) {
            x = (x >> 1) ^ ((x & 1U) ? 0xEDB88320U : 0U);
        }
        crc = (crc >> 8) ^ x;
    }
    return ~crc;
}

static int GuidEqual(const EFI_GUID* a, const EFI_GUID* b)
{
    const UINT8* pa = (const UINT8*)a;
    const UINT8* pb = (const UINT8*)b;
    UINTN i;
    for (i = 0; i < sizeof(EFI_GUID); ++i) {
        if (pa[i] != pb[i]) return 0;
    }
    return 1;
}

static UINT8 Sum8(const void* data, UINTN size)
{
    const UINT8* p = (const UINT8*)data;
    UINT8 sum = 0;
    UINTN i;
    for (i = 0; i < size; ++i) sum = (UINT8)(sum + p[i]);
    return sum;
}

static int AcpiHeaderSane(const ACPI_HEADER* h)
{
    if (h == 0 || h->Length < sizeof(ACPI_HEADER) || h->Length > ACPI_MAX_TABLE_BYTES) return 0;
    return Sum8(h, h->Length) == 0;
}

static UINT32 CountAscii(const UINT8* data, UINT32 size, const char* needle, UINT32 needleSize)
{
    UINT32 count = 0;
    UINT32 i;
    if (needleSize == 0 || size < needleSize) return 0;
    for (i = 0; i <= size - needleSize; ++i) {
        UINT32 n;
        for (n = 0; n < needleSize && data[i + n] == (UINT8)needle[n]; ++n) { }
        if (n == needleSize) ++count;
    }
    return count;
}

static UINT32 Load32(const UINT8* p)
{
    return (UINT32)p[0] | ((UINT32)p[1] << 8) | ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

static UINT64 Load64(const UINT8* p)
{
    return (UINT64)Load32(p) | ((UINT64)Load32(p + 4) << 32);
}

static UINT32 AsciiLength(const char* text, UINT32 maximum)
{
    UINT32 length = 0;
    while (length < maximum && text[length] != 0) ++length;
    return length;
}

static void CopyAscii(char* destination, UINT32 destinationBytes, const char* source)
{
    UINT32 i = 0;
    if (destinationBytes == 0U) return;
    while (i + 1U < destinationBytes && source[i] != 0) {
        destination[i] = source[i];
        ++i;
    }
    destination[i] = 0;
}

static int NameSegEqual(const UINT8* p, const char* name)
{
    return p[0] == (UINT8)name[0] && p[1] == (UINT8)name[1] &&
           p[2] == (UINT8)name[2] && p[3] == (UINT8)name[3];
}

static int ParsePkgLength(const UINT8* p, UINT32 available, UINT32* packageLength, UINT32* encodedBytes)
{
    UINT8 lead;
    UINT32 follow;
    UINT32 value;
    UINT32 i;
    if (available == 0U) return 0;
    lead = p[0];
    follow = (UINT32)(lead >> 6);
    if (follow > 3U || available < follow + 1U) return 0;
    if (follow == 0U) value = (UINT32)(lead & 0x3FU);
    else {
        value = (UINT32)(lead & 0x0FU);
        for (i = 0; i < follow; ++i) value |= (UINT32)p[i + 1U] << (4U + (8U * i));
    }
    if (value < follow + 1U || value > available) return 0;
    *packageLength = value;
    *encodedBytes = follow + 1U;
    return 1;
}

static void RemoveLastPathSegment(char* path, UINT32 capacity)
{
    UINT32 length = AsciiLength(path, capacity);
    while (length > 1U && path[length - 1U] != '.') --length;
    if (length > 1U && path[length - 1U] == '.') --length;
    if (length == 0U) length = 1U;
    path[length] = 0;
}

static int AppendNameSeg(char* path, UINT32 capacity, const UINT8* segment)
{
    UINT32 length = AsciiLength(path, capacity);
    UINT32 i;
    if (length == 0U) {
        if (capacity < 2U) return 0;
        path[0] = '\\';
        path[1] = 0;
        length = 1U;
    }
    if (length > 1U) {
        if (length + 1U >= capacity) return 0;
        path[length++] = '.';
    }
    if (length + 4U >= capacity) return 0;
    for (i = 0; i < 4U; ++i) path[length + i] = (char)segment[i];
    path[length + 4U] = 0;
    return 1;
}

static int ParseAmlNameString(const UINT8* p, UINT32 available, const char* parentPath,
                              char* result, UINT32 resultBytes, UINT32* consumed)
{
    UINT32 cursor = 0;
    UINT32 parentCount = 0;
    UINT32 segments = 1;
    UINT32 i;
    int rooted = 0;
    if (available == 0U || resultBytes < 2U) return 0;
    CopyAscii(result, resultBytes, parentPath);
    if (p[cursor] == AML_ROOT_CHAR) {
        rooted = 1;
        ++cursor;
        result[0] = '\\';
        result[1] = 0;
    }
    while (cursor < available && p[cursor] == AML_PARENT_PREFIX) {
        ++parentCount;
        ++cursor;
    }
    if (!rooted) {
        for (i = 0; i < parentCount; ++i) RemoveLastPathSegment(result, resultBytes);
    }
    if (cursor >= available) return 0;
    if (p[cursor] == 0U) {
        *consumed = cursor + 1U;
        return 1;
    }
    if (p[cursor] == AML_DUAL_NAME_PREFIX) {
        segments = 2U;
        ++cursor;
    } else if (p[cursor] == AML_MULTI_NAME_PREFIX) {
        if (cursor + 1U >= available) return 0;
        segments = p[cursor + 1U];
        cursor += 2U;
        if (segments == 0U) return 0;
    }
    if (segments > 8U || available - cursor < segments * 4U) return 0;
    for (i = 0; i < segments; ++i) {
        if (!AppendNameSeg(result, resultBytes, p + cursor + (i * 4U))) return 0;
    }
    cursor += segments * 4U;
    *consumed = cursor;
    return 1;
}

static int ParseAmlInteger(const UINT8* p, UINT32 available, UINT64* value, UINT32* consumed)
{
    if (available == 0U) return 0;
    switch (p[0]) {
        case AML_ZERO_OP: *value = 0U; *consumed = 1U; return 1;
        case AML_ONE_OP: *value = 1U; *consumed = 1U; return 1;
        case AML_ONES_OP: *value = ~0ULL; *consumed = 1U; return 1;
        case AML_BYTE_PREFIX:
            if (available < 2U) return 0;
            *value = p[1]; *consumed = 2U; return 1;
        case AML_WORD_PREFIX:
            if (available < 3U) return 0;
            *value = (UINT64)p[1] | ((UINT64)p[2] << 8); *consumed = 3U; return 1;
        case AML_DWORD_PREFIX:
            if (available < 5U) return 0;
            *value = Load32(p + 1U); *consumed = 5U; return 1;
        case AML_QWORD_PREFIX:
            if (available < 9U) return 0;
            *value = Load64(p + 1U); *consumed = 9U; return 1;
        default: return 0;
    }
}

static int ParseAmlString(const UINT8* p, UINT32 available, char* destination, UINT32 destinationBytes, UINT32* consumed)
{
    UINT32 i;
    if (available < 2U || p[0] != AML_STRING_PREFIX || destinationBytes == 0U) return 0;
    for (i = 1U; i < available && p[i] != 0U; ++i) {
        if (i < destinationBytes) destination[i - 1U] = (char)p[i];
    }
    if (i >= available) return 0;
    destination[(i - 1U < destinationBytes - 1U) ? (i - 1U) : (destinationBytes - 1U)] = 0;
    *consumed = i + 1U;
    return 1;
}

static int ContainsMsft0101(const UINT8* p, UINT32 size)
{
    return CountAscii(p, size, "MSFT0101", 8U) != 0U;
}


static UINT32 CountBits16(UINT16 value)
{
    UINT32 count = 0;
    while (value != 0U) {
        count += value & 1U;
        value = (UINT16)(value >> 1);
    }
    return count;
}

static UINT32 FirstSetBit16(UINT16 value)
{
    UINT32 bit;
    for (bit = 0; bit < 16U; ++bit) {
        if ((value & (UINT16)(1U << bit)) != 0U) return bit;
    }
    return 0xFFFFFFFFU;
}

static void CaptureResourceTemplate(const UINT8* data, UINT32 size, TPM_DEBUG_REPORT* report)
{
    UINT32 pos = 0;
    while (pos < size) {
        UINT8 header = data[pos];
        if ((header & 0x80U) == 0U) {
            UINT32 kind = (header >> 3) & 0x0FU;
            UINT32 length = header & 0x07U;
            if (pos + 1U + length > size) return;
            if (kind == 0x04U && length >= 2U) {
                UINT16 mask = (UINT16)data[pos + 1U] | ((UINT16)data[pos + 2U] << 8);
                if (mask != 0U && (report->AcpiCrsFlags & ACPI_CRS_IRQ_FOUND) == 0U) {
                    report->AcpiCrsFlags |= ACPI_CRS_IRQ_FOUND;
                    report->AcpiCrsIrq = FirstSetBit16(mask);
                    report->AcpiCrsIrqCount = CountBits16(mask);
                }
            }
            if (kind == 0x0FU) return; /* EndTag */
            pos += 1U + length;
        } else {
            UINT32 kind = header & 0x7FU;
            UINT32 length;
            const UINT8* payload;
            if (pos + 3U > size) return;
            length = (UINT32)data[pos + 1U] | ((UINT32)data[pos + 2U] << 8);
            if (pos + 3U + length > size) return;
            payload = data + pos + 3U;

            if ((report->AcpiCrsFlags & ACPI_CRS_MEMORY_FOUND) == 0U) {
                if (kind == 0x06U && length >= 9U) { /* Memory32Fixed */
                    report->AcpiCrsMemoryBase = Load32(payload + 1U);
                    report->AcpiCrsMemoryLength = Load32(payload + 5U);
                    report->AcpiCrsFlags |= ACPI_CRS_MEMORY_FOUND;
                } else if (kind == 0x07U && length >= 23U && payload[0] == 0U) { /* DWord address space / memory */
                    report->AcpiCrsMemoryBase = (UINT64)Load32(payload + 7U) + (UINT64)Load32(payload + 15U);
                    report->AcpiCrsMemoryLength = Load32(payload + 19U);
                    report->AcpiCrsFlags |= ACPI_CRS_MEMORY_FOUND;
                } else if (kind == 0x0AU && length >= 43U && payload[0] == 0U) { /* QWord address space / memory */
                    report->AcpiCrsMemoryBase = Load64(payload + 11U) + Load64(payload + 27U);
                    report->AcpiCrsMemoryLength = Load64(payload + 35U);
                    report->AcpiCrsFlags |= ACPI_CRS_MEMORY_FOUND;
                }
            }
            if (kind == 0x09U && length >= 2U && (report->AcpiCrsFlags & ACPI_CRS_IRQ_FOUND) == 0U) { /* Extended IRQ */
                UINT32 count = payload[1];
                if (count != 0U && length >= 2U + count * 4U) {
                    report->AcpiCrsFlags |= ACPI_CRS_IRQ_FOUND;
                    report->AcpiCrsIrq = Load32(payload + 2U);
                    report->AcpiCrsIrqCount = count;
                }
            }
            pos += 3U + length;
        }
    }
}

static void CaptureNamedObject(const UINT8* data, UINT32 start, UINT32 end, TPM_DEBUG_REPORT* report)
{
    UINT32 pos = start;
    while (pos + 5U <= end) {
        if (data[pos] == AML_NAME_OP && pos + 5U <= end) {
            const UINT8* name = data + pos + 1U;
            const UINT8* object = data + pos + 5U;
            UINT32 remaining = end - (pos + 5U);
            UINT64 integerValue = 0;
            UINT32 objectBytes = 0;
            if (NameSegEqual(name, "_STA")) {
                if (ParseAmlInteger(object, remaining, &integerValue, &objectBytes)) {
                    report->AcpiObjectFlags |= ACPI_OBJ_STA_STATIC;
                    report->AcpiStaValue = integerValue;
                }
            } else if (NameSegEqual(name, "_CRS")) {
                if (remaining > 1U && object[0] == AML_BUFFER_OP) {
                    UINT32 packageLength;
                    UINT32 packageBytes;
                    if (ParsePkgLength(object + 1U, remaining - 1U, &packageLength, &packageBytes) &&
                        packageLength > packageBytes) {
                        UINT64 bufferLength = 0;
                        UINT32 sizeBytes = 0;
                        UINT32 bufferBody = 1U + packageBytes;
                        if (ParseAmlInteger(object + bufferBody, remaining - bufferBody, &bufferLength, &sizeBytes)) {
                            UINT32 resourceStart = bufferBody + sizeBytes;
                            UINT32 packageEnd = 1U + packageLength;
                            report->AcpiObjectFlags |= ACPI_OBJ_CRS_BUFFER;
                            report->AcpiCrsBufferLength = (UINT32)(bufferLength > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : bufferLength);
                            if (resourceStart <= packageEnd && packageEnd <= remaining &&
                                bufferLength <= (UINT64)(packageEnd - resourceStart)) {
                                CaptureResourceTemplate(object + resourceStart, (UINT32)bufferLength, report);
                            }
                        }
                    }
                }
            } else if (NameSegEqual(name, "_CID")) {
                report->AcpiObjectFlags |= ACPI_OBJ_CID_PRESENT;
                if (ParseAmlString(object, remaining, report->AcpiCidString, ACPI_ID_STRING_BYTES, &objectBytes)) {
                    report->AcpiObjectFlags |= ACPI_OBJ_CID_STRING;
                } else if (ParseAmlInteger(object, remaining, &integerValue, &objectBytes)) {
                    report->AcpiObjectFlags |= ACPI_OBJ_CID_INTEGER;
                    report->AcpiCidValue = integerValue;
                }
            } else if (NameSegEqual(name, "_UID")) {
                report->AcpiObjectFlags |= ACPI_OBJ_UID_PRESENT;
                if (ParseAmlString(object, remaining, report->AcpiUidString, ACPI_ID_STRING_BYTES, &objectBytes)) {
                    report->AcpiObjectFlags |= ACPI_OBJ_UID_STRING;
                } else if (ParseAmlInteger(object, remaining, &integerValue, &objectBytes)) {
                    report->AcpiObjectFlags |= ACPI_OBJ_UID_INTEGER;
                    report->AcpiUidValue = integerValue;
                }
            }
        } else if (data[pos] == AML_METHOD_OP && pos + 2U < end) {
            UINT32 packageLength;
            UINT32 packageBytes;
            if (ParsePkgLength(data + pos + 1U, end - (pos + 1U), &packageLength, &packageBytes)) {
                UINT32 nameOffset = pos + 1U + packageBytes;
                if (nameOffset + 4U <= pos + 1U + packageLength) {
                    if (NameSegEqual(data + nameOffset, "_STA")) report->AcpiObjectFlags |= ACPI_OBJ_STA_METHOD;
                    else if (NameSegEqual(data + nameOffset, "_CRS")) report->AcpiObjectFlags |= ACPI_OBJ_CRS_METHOD;
                    else if (NameSegEqual(data + nameOffset, "_CID")) report->AcpiObjectFlags |= ACPI_OBJ_CID_PRESENT;
                    else if (NameSegEqual(data + nameOffset, "_UID")) report->AcpiObjectFlags |= ACPI_OBJ_UID_PRESENT;
                    else if (NameSegEqual(data + nameOffset, "_DSM")) report->AcpiObjectFlags |= ACPI_OBJ_DSM_PRESENT;
                }
            }
        }
        ++pos;
    }
}

static void WalkAmlObjects(const UINT8* aml, UINT32 start, UINT32 end, const char* parentPath,
                           TPM_DEBUG_REPORT* report, UINT32 depth)
{
    UINT32 pos = start;
    if (depth > 12U || start >= end) return;
    while (pos < end) {
        UINT32 opcodeBytes = 0;
        if (aml[pos] == AML_SCOPE_OP) opcodeBytes = 1U;
        else if (pos + 1U < end && aml[pos] == AML_EXT_OP_PREFIX && aml[pos + 1U] == AML_DEVICE_OP) opcodeBytes = 2U;
        if (opcodeBytes != 0U && pos + opcodeBytes < end) {
            UINT32 packageLength;
            UINT32 packageBytes;
            UINT32 pkgStart = pos + opcodeBytes;
            if (ParsePkgLength(aml + pkgStart, end - pkgStart, &packageLength, &packageBytes)) {
                UINT32 pkgEnd = pkgStart + packageLength;
                UINT32 nameStart = pkgStart + packageBytes;
                UINT32 nameBytes = 0;
                char fullPath[ACPI_DEVICE_PATH_BYTES];
                if (pkgEnd <= end && ParseAmlNameString(aml + nameStart, pkgEnd - nameStart, parentPath,
                                                       fullPath, sizeof(fullPath), &nameBytes)) {
                    UINT32 bodyStart = nameStart + nameBytes;
                    if (bodyStart <= pkgEnd) {
                        if (opcodeBytes == 2U && ContainsMsft0101(aml + bodyStart, pkgEnd - bodyStart)) {
                            UINT32 bodyLength = pkgEnd - bodyStart;
                            if ((report->AcpiObjectFlags & ACPI_OBJ_DEVICE_FOUND) == 0U ||
                                bodyLength < report->AcpiMsftDeviceLength) {
                                report->AcpiObjectFlags = ACPI_OBJ_DEVICE_FOUND;
                                report->Flags |= FLAG_ACPI_DEVICE_FOUND;
                                report->AcpiMsftDeviceOffset = pos;
                                report->AcpiMsftDeviceLength = bodyLength;
                                report->AcpiStaValue = 0U;
                                report->AcpiCrsBufferLength = 0U;
                                report->AcpiCrsFlags = 0U;
                                report->AcpiCrsMemoryBase = 0U;
                                report->AcpiCrsMemoryLength = 0U;
                                report->AcpiCrsIrq = 0U;
                                report->AcpiCrsIrqCount = 0U;
                                report->AcpiCidValue = 0U;
                                report->AcpiUidValue = 0U;
                                report->AcpiCidString[0] = 0;
                                report->AcpiUidString[0] = 0;
                                CopyAscii(report->AcpiDevicePath, ACPI_DEVICE_PATH_BYTES, fullPath);
                                CaptureNamedObject(aml, bodyStart, pkgEnd, report);
                            }
                        }
                        WalkAmlObjects(aml, bodyStart, pkgEnd, fullPath, report, depth + 1U);
                        pos = pkgEnd;
                        continue;
                    }
                }
            }
        }
        ++pos;
    }
}

static void CaptureAcpiPolicyNames(const UINT8* data, UINT32 start, UINT32 end, TPM_DEBUG_REPORT* report)
{
    UINT32 pos;
    for (pos = start; pos + 6U <= end; ++pos) {
        UINT64 value = 0;
        UINT32 consumed = 0;
        const UINT8* name;
        if (data[pos] != AML_NAME_OP) continue;
        name = data + pos + 1U;
        if (!ParseAmlInteger(data + pos + 5U, end - (pos + 5U), &value, &consumed)) continue;
        if (NameSegEqual(name, "TCMF")) { report->AcpiPolicyFlags |= ACPI_POLICY_TCMF_FOUND; report->AcpiTcmfValue = value; }
        else if (NameSegEqual(name, "TTPF")) { report->AcpiPolicyFlags |= ACPI_POLICY_TTPF_FOUND; report->AcpiTtpfValue = value; }
        else if (NameSegEqual(name, "DTPT")) { report->AcpiPolicyFlags |= ACPI_POLICY_DTPT_FOUND; report->AcpiDtptValue = value; }
        else if (NameSegEqual(name, "TTDP")) { report->AcpiPolicyFlags |= ACPI_POLICY_TTDP_FOUND; report->AcpiTtdpValue = value; }
        else if (NameSegEqual(name, "AMDT")) { report->AcpiPolicyFlags |= ACPI_POLICY_AMDT_FOUND; report->AcpiAmdtValue = value; }
        else if (NameSegEqual(name, "TPMF")) { report->AcpiPolicyFlags |= ACPI_POLICY_TPMF_FOUND; report->AcpiTpmfValue = value; }
        else if (NameSegEqual(name, "TPMM")) { report->AcpiPolicyFlags |= ACPI_POLICY_TPMM_FOUND; report->AcpiTpmmValue = value; }
        else if (NameSegEqual(name, "FTPM")) { report->AcpiPolicyFlags |= ACPI_POLICY_FTPM_FOUND; report->AcpiFtpmValue = value; }
    }
}

static void ScanDsdtAml(ACPI_HEADER* dsdt, TPM_DEBUG_REPORT* report)
{
    if (!AcpiHeaderSane(dsdt) || dsdt->Signature != ACPI_SIG_DSDT || dsdt->Length <= sizeof(ACPI_HEADER)) return;
    CaptureAcpiPolicyNames((const UINT8*)dsdt, (UINT32)sizeof(ACPI_HEADER), dsdt->Length, report);
    WalkAmlObjects((const UINT8*)dsdt, (UINT32)sizeof(ACPI_HEADER), dsdt->Length, "\\", report, 0U);
}

static void ScanAcpiTable(ACPI_HEADER* table, TPM_DEBUG_REPORT* report)
{
    if (!AcpiHeaderSane(table)) return;
    if (table->Signature == ACPI_SIG_TPM2) {
        report->Flags |= FLAG_ACPI_TPM2;
        ++report->Tpm2TableCount;
        if (table->Length >= sizeof(ACPI_TPM2_MIN)) {
            ACPI_TPM2_MIN* tpm2 = (ACPI_TPM2_MIN*)table;
            report->Tpm2StartMethod = tpm2->StartMethod;
            report->Tpm2ControlArea = tpm2->ControlArea;
        }
    } else if (table->Signature == ACPI_SIG_TCPA) {
        report->Flags |= FLAG_ACPI_TCPA;
        ++report->TcpaTableCount;
    }

    report->Msft0101Count += CountAscii((const UINT8*)table, table->Length, "MSFT0101", 8U);
    if (report->Msft0101Count != 0) report->Flags |= FLAG_ACPI_MSFT0101;

    /* DSDT is normally referenced by FADT rather than listed in XSDT/RSDT. */
    if (table->Signature == ACPI_SIG_FACP && table->Length >= 44U) {
        UINT64 dsdtAddress = 0;
        if (table->Length >= 148U) dsdtAddress = Load64((const UINT8*)table + 140U);
        if (dsdtAddress == 0) dsdtAddress = (UINT64)Load32((const UINT8*)table + 40U);
        if (dsdtAddress != 0) {
            ACPI_HEADER* dsdt = (ACPI_HEADER*)(UINTN)dsdtAddress;
            if (AcpiHeaderSane(dsdt) && dsdt->Signature == ACPI_SIG_DSDT) {
                report->Msft0101Count += CountAscii((const UINT8*)dsdt, dsdt->Length, "MSFT0101", 8U);
                if (report->Msft0101Count != 0) report->Flags |= FLAG_ACPI_MSFT0101;
                ScanDsdtAml(dsdt, report);
            }
        }
    }
}

static void ScanAcpiRoot(void* rsdpPointer, TPM_DEBUG_REPORT* report)
{
    ACPI_RSDP* rsdp = (ACPI_RSDP*)rsdpPointer;
    UINTN i;
    if (rsdp == 0) return;
    if (Sum8(rsdp, 20U) != 0) return;
    if (rsdp->Revision >= 2U) {
        if (rsdp->Length < sizeof(ACPI_RSDP) || rsdp->Length > 4096U || Sum8(rsdp, rsdp->Length) != 0) return;
    }

    report->Flags |= FLAG_ACPI_PRESENT;
    report->AcpiStatus = EFI_SUCCESS;

    if (rsdp->Revision >= 2U && rsdp->XsdtAddress != 0) {
        ACPI_HEADER* xsdt = (ACPI_HEADER*)(UINTN)rsdp->XsdtAddress;
        if (AcpiHeaderSane(xsdt) && xsdt->Signature == ACPI_SIG_XSDT && xsdt->Length >= sizeof(ACPI_HEADER)) {
            UINT32 entries = (xsdt->Length - (UINT32)sizeof(ACPI_HEADER)) / 8U;
            UINT64* pointers = (UINT64*)((UINT8*)xsdt + sizeof(ACPI_HEADER));
            if (entries > REPORT_MAX_ACPI_TABLES) entries = REPORT_MAX_ACPI_TABLES;
            for (i = 0; i < entries; ++i) {
                if (pointers[i] != 0) ScanAcpiTable((ACPI_HEADER*)(UINTN)pointers[i], report);
            }
            return;
        }
    }

    if (rsdp->RsdtAddress != 0) {
        ACPI_HEADER* rsdt = (ACPI_HEADER*)(UINTN)rsdp->RsdtAddress;
        if (AcpiHeaderSane(rsdt) && rsdt->Signature == ACPI_SIG_RSDT && rsdt->Length >= sizeof(ACPI_HEADER)) {
            UINT32 entries = (rsdt->Length - (UINT32)sizeof(ACPI_HEADER)) / 4U;
            UINT32* pointers = (UINT32*)((UINT8*)rsdt + sizeof(ACPI_HEADER));
            if (entries > REPORT_MAX_ACPI_TABLES) entries = REPORT_MAX_ACPI_TABLES;
            for (i = 0; i < entries; ++i) {
                if (pointers[i] != 0) ScanAcpiTable((ACPI_HEADER*)(UINTN)pointers[i], report);
            }
        }
    }
}

static UINT64 PciAddress(UINT32 bus, UINT32 device, UINT32 function, UINT32 reg)
{
    return ((UINT64)bus << 24) | ((UINT64)device << 16) | ((UINT64)function << 8) | reg;
}

static int IsWellsburgLpc(UINT32 id)
{
    return id == WELLSBURG_8D40 || id == WELLSBURG_8D44 || id == WELLSBURG_8D47;
}

static EFI_STATUS PciRead32(EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* rb, UINT32 reg, UINT32* value)
{
    return rb->Pci.Read(rb, RB_WIDTH_UINT32, PciAddress(PCI_LPC_BUS, PCI_LPC_DEVICE, PCI_LPC_FUNCTION, reg), 1U, value);
}

static EFI_STATUS MemRead8(EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* rb, UINT64 address, UINT8* value)
{
    return rb->Mem.Read(rb, RB_WIDTH_UINT8, address, 1U, value);
}

static EFI_STATUS MemRead32(EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* rb, UINT64 address, UINT32* value)
{
    return rb->Mem.Read(rb, RB_WIDTH_UINT32, address, 1U, value);
}

static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* ScanRootBridges(EFI_BOOT_SERVICES* bs, TPM_DEBUG_REPORT* report)
{
    EFI_HANDLE* handles = 0;
    UINTN count = 0;
    UINTN i;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* chosen = 0;
    EFI_STATUS status = bs->LocateHandleBuffer(EFI_LOCATE_BY_PROTOCOL, &gRootBridgeIoGuid, 0, &count, &handles);
    report->RootBridgeLocateStatus = status;
    report->ChosenRootBridgeIndex = 0xFFFFFFFFU;
    if (EFI_ERROR(status) || handles == 0) return 0;
    report->RootBridgeCount = (UINT32)(count > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : count);

    /* SAFE profile: intentionally keep the root-bridge probing sequence equivalent to
     * the proven v2 path.  In particular, do not call Configuration() on firmware
     * root-bridge instances.  Some dual-socket AMI X99 implementations are unstable
     * when that callback is invoked late in DXE. */
    for (i = 0; i < count; ++i) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* rb = 0;
        UINT32 id = 0xFFFFFFFFU;
        EFI_STATUS handleStatus = bs->HandleProtocol(handles[i], &gRootBridgeIoGuid, (void**)&rb);
        ROOT_BRIDGE_REPORT* item = i < ROOT_BRIDGE_REPORT_COUNT ? &report->RootBridges[i] : 0;
        EFI_STATUS lpcStatus = EFI_NOT_READY;

        if (item != 0) {
            report->RootBridgeStoredCount = (UINT32)(i + 1U);
            item->BusMin = 0xFFFFFFFFU;
            item->BusMax = 0xFFFFFFFFU;
            item->LpcVendorDevice = 0xFFFFFFFFU;
            item->HandleProtocolStatus = handleStatus;
            item->ConfigurationStatus = EFI_NOT_READY;
            item->LpcReadStatus = EFI_NOT_READY;
        }
        if (EFI_ERROR(handleStatus) || rb == 0) continue;

        lpcStatus = PciRead32(rb, PCI_LPC_VENDOR_DEVICE, &id);
        if (item != 0) {
            item->LpcReadStatus = lpcStatus;
            item->LpcVendorDevice = id;
        }
        if (EFI_ERROR(lpcStatus) || !IsWellsburgLpc(id)) continue;

        chosen = rb;
        if (item != 0) {
            item->Flags |= ROOT_BRIDGE_FLAG_WELLSBURG_LPC | ROOT_BRIDGE_FLAG_CHOSEN;
        }
        report->ChosenRootBridgeIndex = (UINT32)(i > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : i);
        report->Flags |= FLAG_LPC_PRESENT;
        report->LpcVendorDevice = id;
        (void)PciRead32(rb, PCI_LPC_RCBA, &report->LpcRcba);
        (void)PciRead32(rb, 0x80U, &report->LpcDecode80);
        (void)PciRead32(rb, 0x84U, &report->LpcDecode84);
        (void)PciRead32(rb, 0x88U, &report->LpcDecode88);
        (void)PciRead32(rb, 0x8CU, &report->LpcDecode8C);
        (void)PciRead32(rb, 0x90U, &report->LpcDecode90);
        (void)PciRead32(rb, 0x98U, &report->LpcDecode98);
        break;
    }

    (void)bs->FreePool(handles);
    return chosen;
}

static void ScanMpServices(EFI_BOOT_SERVICES* bs, TPM_DEBUG_REPORT* report)
{
    EFI_MP_SERVICES_PROTOCOL* mp = 0;
    UINTN processors = 0;
    UINTN enabled = 0;
    UINT32 packages[32];
    UINT32 packageCount = 0;
    UINTN i;
    EFI_STATUS status;
    for (i = 0; i < 32U; ++i) packages[i] = 0xFFFFFFFFU;

    report->MpServicesLocateStatus = bs->LocateProtocol(&gMpServicesGuid, 0, (void**)&mp);
    if (EFI_ERROR(report->MpServicesLocateStatus) || mp == 0 || mp->GetNumberOfProcessors == 0) return;
    report->Flags |= FLAG_MP_SERVICES_PRESENT;
    report->MpGetNumberStatus = mp->GetNumberOfProcessors(mp, &processors, &enabled);
    if (EFI_ERROR(report->MpGetNumberStatus)) return;
    report->ProcessorCount = (UINT32)(processors > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : processors);
    report->EnabledProcessorCount = (UINT32)(enabled > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : enabled);

    if (mp->GetProcessorInfo == 0) return;
    for (i = 0; i < processors; ++i) {
        EFI_PROCESSOR_INFORMATION info;
        UINT32 j;
        int seen = 0;
        status = mp->GetProcessorInfo(mp, i, &info);
        if (EFI_ERROR(status)) continue;
        for (j = 0; j < packageCount; ++j) {
            if (packages[j] == info.Location.Package) { seen = 1; break; }
        }
        if (!seen && packageCount < 32U) packages[packageCount++] = info.Location.Package;
    }
    report->PackageCount = packageCount;
}

static void ScanTpmMmio(EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* rb, TPM_DEBUG_REPORT* report)
{
    UINT32 locality;
    UINT32 value;
    EFI_STATUS status;
    if (rb == 0) return;

    for (locality = 0; locality < TPM_LOCALITY_COUNT; ++locality) {
        UINT64 base = TPM_TIS_BASE + ((UINT64)locality * TPM_LOCALITY_STRIDE);
        TPM_LOCALITY_REPORT* item = &report->Localities[locality];
        TPM_LOCALITY_STATUS_REPORT* statusItem = &report->LocalityStatuses[locality];
        UINT8 access = 0xFFU;
        UINT8 rid = 0xFFU;
        UINT32 successfulReads = 0U;

        status = MemRead8(rb, base + 0x0000U, &access);
        statusItem->AccessStatus = status;
        if (locality == 0U) report->TisAccessReadStatus = status;
        if (!EFI_ERROR(status)) ++successfulReads;
        item->Access = access;

        value = 0xFFFFFFFFU;
        status = MemRead32(rb, base + 0x0018U, &value);
        statusItem->StatusStatus = status;
        if (locality == 0U) report->TisRegisterReadStatus = status;
        if (!EFI_ERROR(status)) ++successfulReads;
        item->Status = value;

        value = 0xFFFFFFFFU;
        status = MemRead32(rb, base + 0x0F00U, &value);
        statusItem->DidVidStatus = status;
        if (!EFI_ERROR(status)) ++successfulReads;
        item->DidVid = value;

        value = 0xFFFFFFFFU;
        status = MemRead32(rb, base + 0x0030U, &value);
        statusItem->InterfaceIdStatus = status;
        if (!EFI_ERROR(status)) ++successfulReads;
        item->InterfaceId = value;

        status = MemRead8(rb, base + 0x0F04U, &rid);
        statusItem->RidStatus = status;
        if (!EFI_ERROR(status)) ++successfulReads;
        item->Rid = rid;

        /* v3 semantics: a locality is transaction-readable only when every bounded
         * MMIO read completed successfully.  Returned all-ones values are still not
         * considered a TPM response. */
        if (successfulReads == 5U) report->LocalityReadableMask |= (1U << locality);
        if ((item->DidVid != 0U && item->DidVid != 0xFFFFFFFFU) ||
            (item->InterfaceId != 0U && item->InterfaceId != 0xFFFFFFFFU) ||
            item->Access != 0xFFU) {
            report->LocalityRespondingMask |= (1U << locality);
        }
    }

    report->TisAccess = report->Localities[0].Access;
    report->TisRid = report->Localities[0].Rid;
    report->TisStatus = report->Localities[0].Status;
    report->TisDidVid = report->Localities[0].DidVid;
    report->PtpInterfaceId = report->Localities[0].InterfaceId;

    if ((report->LocalityReadableMask & 1U) != 0U) report->Flags |= FLAG_TIS_READABLE;
    if ((report->TisAccess & 0x80U) != 0U && report->TisAccess != 0xFFU) report->Flags |= FLAG_TIS_ACCESS_VALID;
    if (report->TisDidVid != 0U && report->TisDidVid != 0xFFFFFFFFU) report->Flags |= FLAG_TIS_DID_VID_VALID;
    if (report->PtpInterfaceId != 0U && report->PtpInterfaceId != 0xFFFFFFFFU) report->Flags |= FLAG_PTP_INTERFACE_VALID;

    value = 0xFFFFFFFFU;
    if (!EFI_ERROR(MemRead32(rb, TPM_TIS_BASE + 0x0014U, &value))) report->TisInterfaceCapability = value;

    if (report->Tpm2ControlArea != 0ULL) {
        value = 0xFFFFFFFFU;
        report->Tpm2ControlReadStatus = MemRead32(rb, report->Tpm2ControlArea, &value);
        if (!EFI_ERROR(report->Tpm2ControlReadStatus)) {
            report->Tpm2ControlValue = value;
            report->Flags |= FLAG_TPM2_CONTROL_READABLE;
        }
    }
}

static void ScanTcg(EFI_BOOT_SERVICES* bs, TPM_DEBUG_REPORT* report, int allowCapability)
{
    EFI_TCG2_PROTOCOL* tcg2 = 0;
    void* tcg1 = 0;
    EFI_TCG2_BOOT_SERVICE_CAPABILITY cap;
    UINT8* p = (UINT8*)&cap;
    UINTN i;

    report->Tcg2LocateStatus = bs->LocateProtocol(&gTcg2ProtocolGuid, 0, (void**)&tcg2);
    if (!EFI_ERROR(report->Tcg2LocateStatus) && tcg2 != 0) {
        report->Flags |= FLAG_TCG2_PROTOCOL;
        if (!allowCapability) {
            /* The broken-TPM path is exactly what this driver is diagnosing.  Do not call
             * into the platform TCG2 implementation until a physical TPM interface was
             * observed and DXE reached ReadyToBoot. */
            report->Flags |= FLAG_TCG2_CAPABILITY_SKIPPED;
            report->Tcg2CapabilityStatus = EFI_NOT_READY;
        } else {
            for (i = 0; i < sizeof(cap); ++i) p[i] = 0;
            cap.Size = (UINT8)sizeof(cap);
            report->Tcg2CapabilityStatus = tcg2->GetCapability(tcg2, &cap);
            if (!EFI_ERROR(report->Tcg2CapabilityStatus)) {
                report->Flags |= FLAG_TCG2_CAPABILITY_OK;
                report->Tcg2PresentFlag = cap.TPMPresentFlag;
                report->Tcg2StructureMajor = cap.StructureVersion.Major;
                report->Tcg2StructureMinor = cap.StructureVersion.Minor;
                report->Tcg2ProtocolMajor = cap.ProtocolVersion.Major;
                report->Tcg2ProtocolMinor = cap.ProtocolVersion.Minor;
                report->Tcg2HashAlgorithmBitmap = cap.HashAlgorithmBitmap;
                report->Tcg2SupportedEventLogs = cap.SupportedEventLogs;
                report->Tcg2MaxCommandSize = cap.MaxCommandSize;
                report->Tcg2MaxResponseSize = cap.MaxResponseSize;
                report->Tcg2ManufacturerId = cap.ManufacturerID;
                report->Tcg2NumberOfPcrBanks = cap.NumberOfPCRBanks;
                report->Tcg2ActivePcrBanks = cap.ActivePcrBanks;
                if (cap.TPMPresentFlag != 0) report->Flags |= FLAG_TCG2_TPM_PRESENT;
            }
        }
    }

    report->Tcg1LocateStatus = bs->LocateProtocol(&gTcg1ProtocolGuid, 0, &tcg1);
    if (!EFI_ERROR(report->Tcg1LocateStatus) && tcg1 != 0) report->Flags |= FLAG_TCG1_PROTOCOL;
}

static void ChooseReason(TPM_DEBUG_REPORT* report)
{
    UINT32 f = report->Flags;
    if ((f & FLAG_TCG2_CAPABILITY_SKIPPED) != 0) {
        report->Reason = REASON_TCG2_CAPABILITY_DEFERRED;
    } else if ((f & FLAG_TCG2_PROTOCOL) != 0 && (f & FLAG_TCG2_CAPABILITY_OK) == 0) {
        report->Reason = REASON_TCG2_CAPABILITY_FAILED;
    } else if ((f & FLAG_TCG2_TPM_PRESENT) != 0) {
        report->Reason = REASON_FIRMWARE_SEES_TPM2;
    } else if ((f & FLAG_TCG2_PROTOCOL) != 0 &&
               (f & FLAG_TCG2_CAPABILITY_OK) != 0 &&
               (f & (FLAG_TIS_DID_VID_VALID | FLAG_PTP_INTERFACE_VALID)) != 0) {
        report->Reason = REASON_TCG2_ABSENT_BUT_INTERFACE_VALID;
    } else if ((f & FLAG_TCG2_PROTOCOL) != 0) {
        report->Reason = REASON_TCG2_PROTOCOL_TPM_ABSENT;
    } else if ((f & (FLAG_TIS_DID_VID_VALID | FLAG_PTP_INTERFACE_VALID)) != 0 && (f & FLAG_ACPI_TPM2) != 0) {
        report->Reason = REASON_TPM_RESPONDS_TCG2_MISSING;
    } else if ((f & FLAG_ACPI_TPM2) != 0) {
        report->Reason = REASON_ACPI_TPM2_BUT_NO_TPM_RESPONSE;
    } else if ((f & (FLAG_TIS_DID_VID_VALID | FLAG_PTP_INTERFACE_VALID)) != 0) {
        report->Reason = REASON_TPM_RESPONDS_ACPI_TPM2_MISSING;
    } else if ((report->AcpiObjectFlags & ACPI_OBJ_STA_STATIC) != 0U &&
               (report->AcpiStaValue & 1U) == 0U) {
        report->Reason = REASON_ACPI_DEVICE_DISABLED;
    } else if ((f & FLAG_TCG1_PROTOCOL) != 0 || (f & FLAG_ACPI_TCPA) != 0) {
        report->Reason = REASON_LEGACY_TCG_ONLY;
    } else if ((f & FLAG_LPC_PRESENT) == 0U) {
        report->Reason = REASON_PCI_ROOT_BRIDGE_UNAVAILABLE;
    } else {
        report->Reason = REASON_NO_TPM_RESPONSE;
    }
}

static EFI_STATUS CollectAndStoreReport(EFI_SYSTEM_TABLE* SystemTable, int readyToBoot)
{
    TPM_DEBUG_REPORT report;
    UINT8* bytes = (UINT8*)&report;
    UINTN i;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL* rb;
    EFI_STATUS setStatus;
    int hardwareInterfaceValid;

    if (SystemTable == 0 || SystemTable->BootServices == 0 || SystemTable->RuntimeServices == 0) return (1ULL << 63) | 2ULL;
    for (i = 0; i < sizeof(report); ++i) bytes[i] = 0;
    report.Signature = REPORT_SIGNATURE;
    report.Version = REPORT_VERSION;
    report.Size = (UINT16)sizeof(report);
    report.FirmwareRevision = SystemTable->FirmwareRevision;
    report.AcpiStatus = EFI_NOT_READY;
    report.Tcg2CapabilityStatus = EFI_NOT_READY;
    report.TisAccessReadStatus = EFI_NOT_READY;
    report.TisRegisterReadStatus = EFI_NOT_READY;
    report.Tpm2ControlReadStatus = EFI_NOT_READY;
    report.MpServicesLocateStatus = EFI_NOT_READY;
    report.MpGetNumberStatus = EFI_NOT_READY;
    report.RcbaGcsReadStatus = EFI_NOT_READY;
    report.RcbaFunctionDisableReadStatus = EFI_NOT_READY;
    report.RcbaSpiBfprReadStatus = EFI_NOT_READY;
    report.RcbaSpiHsfsHsfcReadStatus = EFI_NOT_READY;
    report.ChosenRootBridgeIndex = 0xFFFFFFFFU;
    for (i = 0; i < ROOT_BRIDGE_REPORT_COUNT; ++i) {
        report.RootBridges[i].SegmentNumber = 0xFFFFFFFFU;
        report.RootBridges[i].BusMin = 0xFFFFFFFFU;
        report.RootBridges[i].BusMax = 0xFFFFFFFFU;
        report.RootBridges[i].LpcVendorDevice = 0xFFFFFFFFU;
        report.RootBridges[i].HandleProtocolStatus = EFI_NOT_READY;
        report.RootBridges[i].ConfigurationStatus = EFI_NOT_READY;
        report.RootBridges[i].LpcReadStatus = EFI_NOT_READY;
    }
    for (i = 0; i < TPM_LOCALITY_COUNT; ++i) {
        report.LocalityStatuses[i].AccessStatus = EFI_NOT_READY;
        report.LocalityStatuses[i].StatusStatus = EFI_NOT_READY;
        report.LocalityStatuses[i].DidVidStatus = EFI_NOT_READY;
        report.LocalityStatuses[i].InterfaceIdStatus = EFI_NOT_READY;
        report.LocalityStatuses[i].RidStatus = EFI_NOT_READY;
    }
    if (readyToBoot) report.Flags |= FLAG_REPORT_READY_TO_BOOT;

    ScanMpServices(SystemTable->BootServices, &report);

    /* SAFE profile: preserve the v2 operation order exactly for hardware-facing work.
     * Deeper v3 probes are reintroduced only after a stable dual-socket baseline. */
    rb = ScanRootBridges(SystemTable->BootServices, &report);
    ScanTpmMmio(rb, &report);
    hardwareInterfaceValid = (report.Flags & (FLAG_TIS_DID_VID_VALID | FLAG_PTP_INTERFACE_VALID)) != 0;

    /* Locate TCG protocols only after the raw interface probe, matching v2. */
    ScanTcg(SystemTable->BootServices, &report, readyToBoot && hardwareInterfaceValid);

    /* Raw ACPI table walking remains last, as in v2.  The SAFE build intentionally
     * does not attempt a TPM2 ControlArea read discovered during this later scan. */
    if (readyToBoot) {
        for (i = 0; i < SystemTable->NumberOfTableEntries; ++i) {
            EFI_CONFIGURATION_TABLE* item = &SystemTable->ConfigurationTable[i];
            if (GuidEqual(&item->VendorGuid, &gAcpi20TableGuid) || GuidEqual(&item->VendorGuid, &gAcpi10TableGuid)) {
                ScanAcpiRoot(item->VendorTable, &report);
                if ((report.Flags & FLAG_ACPI_PRESENT) != 0) break;
            }
        }
    }

    ChooseReason(&report);
    report.ReportCrc32 = 0U;
    report.ReportCrc32 = Crc32(&report, sizeof(report));

    /* SAFE profile: keep the report volatile.  There is no reason to rewrite SPI-backed
     * NVRAM on every boot merely to pass a same-boot diagnostic report to the OS. */
    setStatus = SystemTable->RuntimeServices->SetVariable(
        gReportVariableName,
        &gReportVendorGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        sizeof(report),
        &report);
    return setStatus;
}

static void EFIAPI TpmDebugReadyToBoot(EFI_EVENT Event, void* Context)
{
    (void)Event;
    (void)CollectAndStoreReport((EFI_SYSTEM_TABLE*)Context, 1);
}

EFI_STATUS EFIAPI TpmDebugEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    EFI_EVENT readyEvent = 0;
    EFI_STATUS eventStatus;
    (void)ImageHandle;
    (void)gRelocationAnchor;

    if (SystemTable == 0 || SystemTable->BootServices == 0 || SystemTable->RuntimeServices == 0) {
        return EFI_SUCCESS;
    }
    if (SystemTable->BootServices->Hdr.HeaderSize < sizeof(EFI_BOOT_SERVICES)) {
        return EFI_SUCCESS;
    }

    /* Boot safety is more important than an early sample.  This driver performs no
     * TPM, ACPI, PCI/MMIO or variable operation during DXE dispatch.  It only
     * registers a ReadyToBoot callback and returns.  If CreateEventEx is absent or
     * registration fails, remain inert rather than probing early. */
    if (SystemTable->BootServices->CreateEventEx == 0) {
        return EFI_SUCCESS;
    }
    eventStatus = SystemTable->BootServices->CreateEventEx(
        EVT_NOTIFY_SIGNAL,
        TPL_CALLBACK,
        TpmDebugReadyToBoot,
        SystemTable,
        &gReadyToBootEventGuid,
        &readyEvent);
    (void)eventStatus;
    return EFI_SUCCESS;
}

