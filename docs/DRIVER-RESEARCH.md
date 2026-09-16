# BIOS access on X99 / Windows 11
Research and static inspection: 2026-09-05.

## Result
The supplied ThrottleStop driver is pinned at runtime by exact SHA-256 and Windows Authenticode validation before each load. WinVerifyTrust receives the already-open read handle that is kept non-writable/non-deletable through the service lifetime; the release build additionally pins the TechPowerUp signer certificate SHA-256. The supplied ThrottleStop driver has more than an MSR interface. Its physical-memory and PCI operations provide the primitives needed to implement the C610/X99 SPI controller's hardware read sequence. This is a technically viable route without authoring/signing a new kernel driver. It is not a general-purpose BIOS API provided by ThrottleStop.

The implementation was validated on 2026-09-05 on HUANANZHI X99-F8D PLUS V1.0, LPC 8086:8D44. Two independent 8 MiB BIOS-region reads matched by SHA-256; the saved image passed structural checks and the temporary driver service/file were removed. This qualifies this tested configuration, not every X99 board or Windows policy. Unit tests additionally use a register emulator.

The current provider is **full-SPI-first**. It reads the Wellsburg region map and FRAP permissions, validates the Intel Flash Descriptor, derives total flash capacity from the descriptor component-density fields, and attempts to read the complete SPI address space. If a mapped region or an unmapped address range is blocked by the controller, the result is explicitly `PartialSpi`; unreadable bytes are represented as `FF` only for analysis and the UI warns that the file is not a complete programming backup. If the descriptor itself cannot be read/validated but BIOS access remains available, the provider falls back to a verified `BiosRegion` dump. Two matching reads, metadata/scope equality, structural validation and an on-disk hash check are required before a dump reaches the ordinary image loader.

## Supported hardware scope
Product support is limited to Windows 11 x64 on **LGA2011-3 / X99 boards**. Other file formats/platforms may be analyzable, without a compatibility guarantee. The hardware reader is narrower: Intel family 6 model 3F/4F (Haswell-E/EP or Broadwell-E/EP), Intel LPC IDs 8086:8D40, 8D44, 8D47, enabled RCBA and BIOS read permission. It decodes Wellsburg FREG0..FREG4 (Descriptor/BIOS/ME/GbE/PDR) and respects FRAP read permissions. Wellsburg FREG/PR address fields carry FLA[24:12] (13 bits), while hardware-sequencing FADDR carries FLA[24:0]; this implementation therefore caps controller reads at 32 MiB. Descriptor component-density decoding supports the Wellsburg-era one/two-component layout. Some boards sold as X99 have a different PCH; the hardware reader refuses unknown IDs.

The current machine reports HUANANZHI X99-F8D PLUS V1.0. Hardware reading has now passed on this specific platform; see VALIDATION.md for evidence.

## Static evidence for the supplied binary
The exact driver SHA-256 and signer-certificate SHA-256 are stored only in `third_party/ThrottleStop/integrity.json`. Authenticode provenance was reviewed as TechPowerUp LLC.

The PE import table contains HalGetBusDataByOffset, HalSetBusDataByOffset, MmMapIoSpace and MmUnmapIoSpace. Dispatch starts at RVA 1EF0; a byte table at 2524 indexes a target table at 24F4. Static inspection with LLVM objdump gives:

| IOCTL | Target RVA | Operation | Used |
| --- | --- | --- | --- |
| 80006448 | 202B -> 1CB0 | RDMSR | No |
| 8000644C | 203D -> 1C10 | WRMSR | No |
| 80006498 | 2184 | Read 1/2/4/8 bytes at a physical address | SPI status/data only |
| 8000649C | 2271 | Write 1/2/4/8 bytes at a physical address | Restricted SPI hardware-sequencing registers |
| 800064A0 | 2365 | PCI configuration read | LPC ID and RCBA only |
| 800064A4 | 2405 | PCI configuration write | BIOS_CNTL.BIOSWE only during direct BIOS-region flashing |

Physical read input is an 8-byte address; output size selects width. Physical write input is address followed by the width-sized value. PCI read input packs bus, device, function and register offset into 8 bytes. Successful dispatch returns the requested output length. These are private, binary-specific observations, not a vendor-supported SDK.

## SPI implementation boundaries
The [CHIPSEC C610 configuration](https://github.com/chipsec/chipsec/blob/1.13.16/chipsec/cfg/8086/pch_c61x.xml) identifies the Wellsburg IDs. Its [register definitions](https://github.com/chipsec/chipsec/blob/1.13.16/chipsec/cfg/8086/common.xml) and [SPI implementation](https://github.com/chipsec/chipsec/blob/1.13.16/chipsec/hal/spi.py) corroborate RCBA + 3800, HSFS +04, HSFC +06, FADDR +08, FDATA +10, FRAP +50 and FREG1 +58.

The runtime transport is capability-restricted. Reading permits controller status, FRAP, FREG0..FREG4, PR0..PR4 and FDATA plus LPC identity/RCBA. Direct BIOS-region flashing additionally permits only the hardware-sequencing FADDR/FDATA/HSFS/HSFC writes needed for FCYCLE=2 (write) and FCYCLE=3 (block erase), after board/image/protection preflight. The only PCI configuration write exposed is a read-modify-write of BIOS_CNTL.BIOSWE (bit 0); BLE and SMM_BWP are preserved, and BIOSWE is restored to its original state after the operation. Descriptor, ME, GbE and PDR writes remain forbidden.

The reader first attempts all descriptor-defined SPI content. `FullSpi` is emitted only when the descriptor is valid, component density yields a supported flash size, all mapped regions are readable and every byte of the resulting SPI address space was obtained. A permission/access failure yields `PartialSpi` rather than silently claiming a full backup; descriptor failure yields a BIOS-region fallback when possible.

Intel ME remains outside the application's modification scope. The reader may include ME when the chipset permits read access so that a system dump can be as complete as possible, but an ME-only read restriction is retained only in internal `PartialSpi` metadata and is not presented to the user as a BIOS-management problem. The application never writes or patches the ME region.

PRx, FRAP and lock-changing operations are not implemented. BIOS-region erase/program is implemented only through the restricted hardware-sequencing path described above; BIOS_CNTL access is limited to temporary BIOSWE control. Cancel is honored between completed cycles. A busy controller, invalid descriptor, access denial or timeout aborts the dump. Do not run competing firmware utilities during a read; the application mutex only coordinates its own instances.

## Signed alternatives investigated
| Candidate | Finding |
| --- | --- |
| ThrottleStop supplied binary | Already signed; PCI/MMIO primitives verified statically. Loaded successfully on the tested machine; loading elsewhere remains dependent on Windows policy. |
| Intel FPT | Must match the ME/PCH generation and OEM package. No universally compatible, current signed Windows 11 package for these X99 boards was established. |
| AMI AFU | Official vendor tool for Aptio, including Windows. A board/firmware-compatible OEM package and its driver must be validated; an AFU backup is not automatically a full SPI image. |
| CHIPSEC Windows driver | Useful reference and lab tooling; documented Windows installation requires a driver-signing/test-mode workflow. It does not solve the requirement for a universally accepted production-signed driver. |
| flashrom | Official documentation says Windows has no internal-programmer support. External programmers are a separate hardware workflow. |

[AMI AFU product description](https://www.ami.com/resources/ami-firmware-utility-afu-a-secure-update-utility-for-aptio-v-uefi-bios-firmware/) describes firmware-mediated updates; the [download terms](https://www.ami.com/resources/ami-firmware-update-utility-afu-utility-for-aptio-v-aptio-4-and-amibios-scriptable-cli-utility-for-dos-and-windows/) govern reuse.
[CHIPSEC Windows installation](https://chipsec.github.io/installation/InstallWindows.html) documents signing limitations.
[flashrom platform support](https://flashrom.org/) describes its Windows limitation.

A signed driver is not necessarily permitted by Windows 11. The [Microsoft vulnerable-driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) can reject signed binaries. This app never changes HVCI, Secure Boot, blocklists, BCD or Code Integrity policy.

## SMBIOS is not a dump
[GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable) can retrieve SMBIOS/ACPI metadata; that is not the SPI BIOS image. XeonV3Control does not use live SMBIOS/ACPI metadata as BIOS/baseboard identity input after acquisition: analysis and all subsequent firmware operations use only the captured or loaded image bytes.

## Hardware validation procedure
Run the published app as administrator and choose System BIOS. Record the service result and, if Windows rejects it, the matching Code Integrity event. Require two matching reads with identical scope/region metadata and SHA-256. For `FullSpi`, verify Descriptor/BIOS/ME/GbE/PDR boundaries as applicable and confirm the file size matches descriptor component density; for `PartialSpi`, verify the UI names blocked regions and does not present the file as a complete backup; for `BiosRegion`, verify the fallback is explicit. Verify that the temporary service is removed after normal completion/cancellation. A sudden process termination can leave a demand-start service. On the next hardware read, the app only reclaims XeonV3Bios_<GUID> services whose SCM configuration still matches the expected kernel-driver type, demand-start mode and exact app-owned binary path; unrelated or mismatched services are left untouched.

Future writing, if implemented, must be introduced as a separate reviewed capability with exact board/image/scope matching, a verified backup, a concrete preview and explicit user confirmation immediately before flashing, plus verification by reading back. No write API is exposed by the current product.


## Supplied X99 UEFI-driver corpus and update policy

The supplied `drivers.tar.zst` was treated as a research corpus, not as a trusted “latest driver” repository. It contains 25,087 FFS files (11,589 DXE, 10,554 PEIM, 2,944 SMM) and 941 unique GUIDs, but it does not carry sufficient board/BIOS provenance to prove that two files with the same GUID are interchangeable. The update catalog therefore uses exact source SHA-256 -> exact candidate SHA-256 transitions and keeps reviewed candidate bytes embedded in Core.

The Intel RAID GUID `91B4D9C1-141C-4824-8D02-3C298E36EB3F` demonstrates why GUID-only replacement is unsafe: the corpus contains both RST and RSTe branches under that identity. Reviewed exact candidates are RST `14.8.0.2377` (`9AE78E96A20D5A95EA616C51B2A4CF93CFE42FAA13FB94F19F3982D2AEAC8872`) and RSTe `5.5.5.1005` (`975764C0A94A14DD476A53CEF2B999555CD49E43FDC4B29D1AB153577F215CB7`). RSTe `4.6.0.1018` and `5.5.5.1005` have the same FFS GUID/type/attributes, x64 EFI boot-service executable class and the same dependency-expression SHA-256; the newer FFS is larger (104,067 vs 76,167 bytes). The larger size is handled by physical FV planning rather than treated as an automatic rejection.

The managed physical strategies follow PI/UEFITool safety constraints without invoking or embedding UEFITool/UBU. FFS files stay 8-byte aligned; PAD is regenerated as real PI PAD FFS when needed; FV erase polarity and FFS checksums/state are respected; a VTF remains pinned to the FV end. UEFITool's historical need to rebase XIP PEI files during FV rebuild is handled by a deliberately narrow managed subset: only a pure PEIM containing a direct uncompressed PE32/PE32+ image in a full Intel SPI image may move, and only when its current physical `ImageBase`, XIP RVA/raw layout and complete base-relocation table prove the exact delta. IA32 `HIGHLOW` and x64 `DIR64` relocations are supported; TE, SEC/PEI core, combined PEIM/DXE, compressed/guided/nested PEI and unsupported/ambiguous relocations remain `RequiresRebase`. No external firmware process, DLL, Python helper, UBU, MMTool or UEFITool is used at runtime.

Current restricted classes remain non-automatic: Intel/Atheros/Killer LAN require hardware/controller-family authorization; AMI NVMe/NvmeInt13/NvmeDynamicSetup require stack/bundle authorization; Realtek UNDI, Marvell 9172, ASMedia ASM106x and generic OEM RAID modules have no proven exact upgrade chain in this corpus. The previously suspected GUID `5BBA83E5-F027-4CA7-BFD0-16358CC9E123` is identified by corpus UI metadata as `IccOverClocking`, not GOP, and is intentionally excluded from the update catalog. The UI therefore shows the total detected driver inventory separately from the smaller exact-policy subset; only `Ready/CanApply` exact transitions expose an Update action.
