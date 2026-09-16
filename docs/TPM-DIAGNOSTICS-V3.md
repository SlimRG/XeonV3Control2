# TPM diagnostics v3

Purpose: determine why a discrete TPM does not answer through the X99/C610 TPM path, especially when behaviour differs between one-CPU and two-CPU boots.

## What v3 adds

- Uses a conservative v2-equivalent root-bridge scan to locate the first Wellsburg LPC function and records the safely obtained segment/D31:F0/status values. The SAFE build does not invoke root-bridge `Configuration()`.
- Identifies which root bridge contains the Wellsburg LPC function used for the TPM probe.
- Keeps the RCBA fields in the report ABI, but the SAFE build does not read RCBA/SPI MMIO during `ReadyToBoot`.
- Captures `EFI_STATUS` independently for every locality 0-4 read: ACCESS, STS, DID_VID, InterfaceId and RID.
- Separates "the MMIO transaction succeeded" from "a TPM actually responded".
- Restores the proven v2 probe order; SAFE mode records TPM2 Control Area metadata but does not add a new Control Area MMIO read.
- Shows inferred AMI X99 TPM `_HID` and `_STA` policy separately from raw/static AML parsing. AML is never executed by the debug driver.
- Keeps report-v1/v2 compatibility in the Windows reader.

## Read-only guarantee

The DXE module performs reads and protocol discovery only. It does not:

- request or seize TPM locality;
- send TPM commands;
- write TIS/PTP registers;
- write PCI configuration space;
- write LPC decode registers;
- write RCBA or SPI controller registers;
- modify flash descriptor or PCH soft straps.

There are **no persistent writes** in the SAFE build. Its CRC-protected report is written only to the volatile runtime variable `XeonV3TpmDebugReportSafe`; the old non-volatile `XeonV3TpmDebugReport` entry, if present from an earlier build, is left untouched.

## Capture procedure on the current dual-CPU system

CPU removal is not part of the diagnostic procedure. Boot the existing assembly with the SAFE driver, open the TPM page, and preserve the complete report. For subsequent tests, change only one firmware setting or one BIOS image variable at a time and compare the resulting report. A previously captured one-CPU report may be used as an optional historical reference, but no new one-CPU boot is required.

Compare:

| Layer | SAFE v3 fields | Meaning of a difference |
| --- | --- | --- |
| Topology | package/enabled CPU counts | Confirms that firmware still exposes the same CPU topology |
| UEFI host bridge | Root Bridge count, safely touched segment/D31:F0/status fields | Different host/PCH enumeration or wrong Wellsburg bridge selection |
| LPC/PCH | RCBA base value, LPC decode registers | Platform init changed the PCH decode state |
| ACPI policy | TCMF/TTPF/DTPT/TTDP/AMDT/TPMF/TPMM/FTPM, inferred HID/STA/STR | Firmware policy changed or device was intentionally hidden |
| TPM transport endpoint | L0-L4 values + per-read `EFI_STATUS` | Distinguishes host-access failure from a decoded path with no responding device |
| Firmware TPM stack | TCG2, TPM2/TCPA, Control Area | Shows whether DXE promoted the physical TPM into firmware/ACPI services |

### Interpretation shortcuts

- `EFI_STATUS == EFI_SUCCESS` for the locality reads + all returned values `FF/FFFFFFFF` + responding mask `0`: host MMIO access completed, but no TPM answered on that path.
- MMIO read failures: investigate root-bridge/PCH decode first.
- Stable LPC/ACPI state with persistent all-ones TPM registers: investigate transport selection, reset, clock and board pin routing.
- TPM values become valid but TCG2/TPM2 publication stays absent: the remaining problem is firmware TPM stack/ACPI publication, not the physical transport.

### Safety changes after the B1/reboot incident

The previous v3 build added three operations that were not present in the proven v2 path: calling `EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.Configuration()` on root bridges, late-DXE RCBA/SPI MMIO reads, and a larger **non-volatile** report write on every boot. The SAFE build removes all three variables at once: no `Configuration()` callback, no RCBA MMIO probe, and no NVRAM write. This is intentionally conservative; deeper PCH probing will only be reintroduced one operation at a time after a stable boot baseline is confirmed.

## Deliberate limitation

The public C610/X99 documentation establishes that TPM can use LPC or dedicated SPI TPM signalling, but it does not provide a safe public mapping for the soft-strap selector needed here. v3 therefore records raw relevant state instead of guessing or mutating undocumented strap bits.
