# TPM diagnostic B1 recovery / SAFE baseline

## What changed

The unstable diagnostic v3 added late-DXE operations that were not present in the previously booting v2 path:

1. calls to `EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.Configuration()` while enumerating root bridges;
2. RCBA/SPI MMIO reads at `ReadyToBoot`;
3. a 1232-byte **non-volatile** UEFI variable update on every boot.

AMI checkpoint `B1` is a late boot checkpoint (`Runtime Set Virtual Address MAP End`). A stop there after repeated resets is consistent with a problem introduced before/around the runtime transition, but the code alone does not prove which one of the three operations was the trigger.

## Recovery first

Do not remove a processor. The SAFE diagnostic does not require a one-CPU boot.

If the machine no longer reaches firmware setup or the OS, restore the exact last-known-good full SPI image using the board's supported recovery mechanism or an external programmer. Prefer the same machine's previous full dump/image so board-specific descriptor/ME/GbE/NVRAM data are preserved. Do not substitute a generic vendor image unless those regions are intentionally being rebuilt.

After the known-good image boots normally, create a fresh image from that exact baseline and only then insert the SAFE TPM diagnostic driver.

## SAFE profile

The SAFE build keeps the v3 report ABI but restores the v2 hardware-operation order and removes the new risky operations:

- no root-bridge `Configuration()` calls;
- no RCBA/SPI MMIO snapshot;
- no TPM writes or commands;
- no PCI/LPC writes;
- no persistent UEFI-variable write;
- report is stored only in volatile runtime variable `XeonV3TpmDebugReportSafe`;
- Windows reader checks the SAFE variable first and still understands older v1-v3 reports.

Further PCH probes must be added back one operation at a time only after this baseline is confirmed to boot repeatedly on the fixed dual-CPU assembly.
