# TPM Debug DXE

`TpmDebugDxe.c` is a freestanding x64 UEFI boot-service driver used only for passive diagnostics. It never requests TPM locality, submits TPM commands, or changes LPC/PCI decode, flash strap, RCBA/SPI, TPM, or protection registers.

The driver is packaged to match the native AMI X99 DXE conventions observed in the reference firmware image:

- PE32+ EFI boot-service driver with `ImageBase=0`, `SectionAlignment=FileAlignment=0x20`, DLL characteristic and no imports;
- deterministic timestamp and relocation directory;
- PI DXE FFS with the native fixed `0xAA` data-checksum convention;
- AMI/Tiano LZMA GUID-defined encapsulation (`ee4e5898-3914-4259-9d6e-dc7bd79403cf`);
- DXE DEPEX on Variable Architectural Protocol, Variable Write Architectural Protocol and PCI Root Bridge I/O.

The entry point is intentionally inert: it only registers the UEFI `ReadyToBoot` callback and immediately returns `EFI_SUCCESS`. All diagnostics run from that callback, after normal DXE initialization has converged.

## Report version 3

The CRC32-protected version-3 report is a strict append-only extension of the version-2 layout. The Windows reader still accepts report versions 1 and 2.

The report contains:

- TCG2 and legacy TCG protocol presence; TCG2 `GetCapability` is called only if the raw TPM interface already looks valid;
- ACPI TPM2/TCPA counts and FADT -> DSDT/X_DSDT analysis;
- the AML TPM `Device`, its ACPI path, static `_STA`, `_CRS`, `_CID`, `_UID`, and `_DSM` presence without executing AML methods;
- static `_CRS` resource-template MMIO/IRQ decoding where the AML uses supported standard descriptors;
- UEFI MP Services processor/enabled/package counts;
- the bounded root-bridge sequence needed to find the first Wellsburg LPC function: segment number, D31:F0 ID and per-operation `EFI_STATUS`; the SAFE build deliberately does **not** call the firmware `Configuration()` callback on root bridges;
- the selected Wellsburg LPC identity and read-only decode registers;
- RCBA snapshot fields remain in the report layout for compatibility, but the SAFE build leaves them unavailable rather than issuing late-DXE RCBA MMIO reads;
- read-only TPM TIS/PTP registers for localities 0 through 4 (`0xFED40000` through `0xFED44000`), including the `EFI_STATUS` of ACCESS, STS, DID_VID, InterfaceId and RID reads separately;
- TPM2 ACPI table/control-area metadata when present; SAFE mode does not perform a newly discovered Control Area MMIO read.

The v3 `LocalityReadableMask` has deliberately strict semantics: a bit is set only when all five bounded MMIO transactions for that locality completed successfully. A successful PCI Root Bridge read returning all ones is **not** considered a TPM response; that is represented separately by `LocalityRespondingMask`.

The SAFE build intentionally restores the proven v2 hardware-operation order. ACPI is parsed after the raw TPM/TCG probes, so a newly discovered TPM2 Control Area is recorded but not MMIO-read in the same boot.

The application may infer the active `_HID`/`_STA` branch from the known AMI X99 DSDT policy names (`TCMF`, `TTDP`, `TPMF`) when those values were decoded statically. Such values are explicitly labelled as an inference: the diagnostic driver does not execute AML.

The SAFE build stores the report in the **volatile** runtime UEFI variable `XeonV3TpmDebugReportSafe`, vendor GUID `77c232c4-f56c-4f1c-9759-47e64f5b3921`. It therefore does not rewrite SPI-backed NVRAM on every boot. The Windows reader checks this SAFE variable first and retains read compatibility with the older `XeonV3TpmDebugReport` variable. Image-side TPM evidence and PCH straps are derived only from bytes in the opened BIOS image.

`build_driver.py` requires LLVM `clang` and `lld-link` on `PATH`. It validates PE/COFF layout, DEPEX, FFS header/checksum, LZMA round-trip and exact section boundaries before replacing the embedded `XeonV3TpmDebug.ffs`.

## Diagnosis on a fixed dual-CPU assembly

Removing a processor is **not** required by this build. On systems where the current CPU assembly cannot be changed, capture the SAFE report from the existing two-package configuration and compare future reports only after one controlled firmware/configuration change at a time. If a historical one-package report already exists, it remains useful as optional reference data. Compare fields in this order:

1. CPU package count and enabled processors.
2. Root bridge count, the safely touched bridge segments/D31:F0 IDs, and the selected Wellsburg bridge.
3. LPC RCBA base value and PCI decode registers.
4. ACPI policy values (`TCMF`, `TTPF`, `DTPT`, `TTDP`, `AMDT`, `TPMF`, `TPMM`, `FTPM`) and inferred `_HID`/`_STA`/`_STR`.
5. Per-locality TIS/PTP register values **and their individual `EFI_STATUS` values**.
6. TCG2/TCPA/TPM2 publication state.

A change before the TPM-register step points toward platform/PCH initialization or routing. Identical platform state with a change only in TPM register responses points more strongly toward electrical/reset/clock/pin routing. Identical all-ones register values with successful MMIO transactions means the host access completed but no TPM device responded on that decoded path.

The driver intentionally does not guess the undocumented C610/X99 soft-strap bit selecting LPC versus SPI TPM transport. Raw image straps remain visible in the application for controlled comparison.

## AMI X99 FFS compatibility invariants

`EFI_FFS_FILE_HEADER.Size` ends exactly at the final GUID-defined section. Firmware-volume 8-byte alignment is not part of `FileSize`; external alignment bytes remain at the FV erase value (`0xFF` in the reference image). The LZMA-expanded stream is `PE32 -> UI -> VERSION` and ends exactly at the VERSION section. This avoids zero-filled pseudo-section headers that older AMI dispatchers may reject.
