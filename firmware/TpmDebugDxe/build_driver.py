#!/usr/bin/env python3
"""Build the X99/AMI-compatible freestanding x64 TPM diagnostic DXE driver and PI FFS wrapper."""
from __future__ import annotations

import argparse
import hashlib
import lzma
import shutil
import struct
import subprocess
import uuid
from pathlib import Path

FILE_GUID = uuid.UUID("9f0ebf4b-c7c8-4ed3-9eae-0ccecd34345a")
LZMA_GUID = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf")
PCI_ROOT_BRIDGE_IO_GUID = uuid.UUID("2f707ebb-4a1a-11d4-9a38-0090273fc14d")
VARIABLE_ARCH_GUID = uuid.UUID("1e5668e2-8481-11d4-bcf1-0080c73c8881")
VARIABLE_WRITE_ARCH_GUID = uuid.UUID("6441f818-6362-4e44-b570-7dba31dd2453")

FFS_DRIVER = 0x07
FFS_ATTRIB_NONE = 0x00
FFS_FIXED_CHECKSUM = 0xAA
FFS_DATA_VALID_PHYSICAL_ERASE_FF = 0xF8
SECTION_GUID_DEFINED = 0x02
SECTION_PE32 = 0x10
SECTION_DXE_DEPEX = 0x13
SECTION_VERSION = 0x14
SECTION_UI = 0x15
GUIDED_PROCESSING_REQUIRED = 0x0001
GUIDED_DATA_OFFSET = 24

DEP_PUSH = 0x02
DEP_AND = 0x03
DEP_END = 0x08

PE32_PLUS = 0x20B
PE_MACHINE_X64 = 0x8664
PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
PE_CHARACTERISTIC_EXECUTABLE = 0x0002
PE_CHARACTERISTIC_LARGE_ADDRESS_AWARE = 0x0020
PE_CHARACTERISTIC_DLL = 0x2000
PE_EXPECTED_CHARACTERISTICS = (
    PE_CHARACTERISTIC_EXECUTABLE | PE_CHARACTERISTIC_LARGE_ADDRESS_AWARE | PE_CHARACTERISTIC_DLL
)
PE_NATIVE_ALIGNMENT = 0x20


def u24(value: int) -> bytes:
    if not 0 <= value < 0xFFFFFF:
        raise ValueError(f"value does not fit a normal PI 24-bit size: {value}")
    return value.to_bytes(3, "little")


def align(data: bytearray, boundary: int) -> None:
    data.extend(b"\x00" * ((-len(data)) % boundary))


def section(kind: int, payload: bytes) -> bytes:
    size = 4 + len(payload)
    return u24(size) + bytes([kind]) + payload


def build_depex() -> bytes:
    # Do not dispatch at DXE-core start.  Wait for the same standard architectural
    # services this AMI X99 firmware uses before its own variable/PCI-dependent DXE modules.
    payload = bytearray()
    for guid in (VARIABLE_ARCH_GUID, VARIABLE_WRITE_ARCH_GUID, PCI_ROOT_BRIDGE_IO_GUID):
        payload.append(DEP_PUSH)
        payload += guid.bytes_le
    payload += bytes([DEP_AND, DEP_AND, DEP_END])
    return section(SECTION_DXE_DEPEX, bytes(payload))


def lzma_alone(payload: bytes) -> bytes:
    filters = [{
        "id": lzma.FILTER_LZMA1,
        "dict_size": 1 << 24,
        "lc": 3,
        "lp": 0,
        "pb": 2,
        "mode": lzma.MODE_NORMAL,
        "nice_len": 64,
        "mf": lzma.MF_BT4,
    }]
    encoded = bytearray(lzma.compress(payload, format=lzma.FORMAT_ALONE, filters=filters))
    if len(encoded) < 13 or encoded[0] != 0x5D or encoded[1:5] != (1 << 24).to_bytes(4, "little"):
        raise ValueError("unexpected LZMA-alone properties")
    # Python writes the unknown-size marker. AMI's native guided sections in this
    # firmware family carry the exact uncompressed size, so normalize to that form.
    encoded[5:13] = len(payload).to_bytes(8, "little")
    if lzma.decompress(bytes(encoded), format=lzma.FORMAT_ALONE) != payload:
        raise ValueError("LZMA guided payload failed round-trip validation")
    return bytes(encoded)


def build_ffs(pe: bytes) -> bytes:
    inner = bytearray()
    inner += section(SECTION_PE32, pe)
    align(inner, 4)
    inner += section(SECTION_UI, "XeonV3 TPM Debug\0".encode("utf-16le"))
    align(inner, 4)
    inner += section(SECTION_VERSION, b"\x00\x00" + "3.0\0".encode("utf-16le"))

    guided_payload = bytearray()
    guided_payload += LZMA_GUID.bytes_le
    guided_payload += GUIDED_DATA_OFFSET.to_bytes(2, "little")
    guided_payload += GUIDED_PROCESSING_REQUIRED.to_bytes(2, "little")
    guided_payload += lzma_alone(bytes(inner))

    body = bytearray()
    body += build_depex()
    align(body, 4)
    body += section(SECTION_GUID_DEFINED, bytes(guided_payload))

    # PI FFS FileSize ends at the last section byte.  8-byte alignment belongs
    # to the firmware-volume file stream and must remain erase-byte padding
    # outside the file.  Including zero padding in FileSize leaves a fake
    # zero-sized section header that old AMI DXE dispatchers may reject.
    total = 24 + len(body)
    if total >= 0xFFFFFF:
        raise ValueError("FFS wrapper unexpectedly requires EFI_FFS_FILE_HEADER2")

    header = bytearray(24)
    header[0:16] = FILE_GUID.bytes_le
    header[17] = FFS_FIXED_CHECKSUM
    header[18] = FFS_DRIVER
    header[19] = FFS_ATTRIB_NONE
    header[20:23] = u24(total)
    header[23] = FFS_DATA_VALID_PHYSICAL_ERASE_FF

    image = header + body
    image[16] = 0
    header_sum = sum(value for index, value in enumerate(image[:24]) if index not in (17, 23))
    image[16] = (-header_sum) & 0xFF
    validate_ffs(image, pe)
    return bytes(image)


def iter_sections(stream: bytes):
    offset = 0
    while offset <= len(stream) - 4:
        size = int.from_bytes(stream[offset:offset + 3], "little")
        if size == 0:
            return
        if size < 4 or offset + size > len(stream):
            raise ValueError("invalid FFS section stream")
        yield offset, size, stream[offset + 3], stream[offset + 4:offset + size]
        offset = (offset + size + 3) & ~3


def validate_depex(payload: bytes) -> None:
    expected = bytearray()
    for guid in (VARIABLE_ARCH_GUID, VARIABLE_WRITE_ARCH_GUID, PCI_ROOT_BRIDGE_IO_GUID):
        expected.append(DEP_PUSH)
        expected += guid.bytes_le
    expected += bytes([DEP_AND, DEP_AND, DEP_END])
    if payload != expected:
        raise ValueError("DXE DEPEX does not match the fail-safe architectural dependency set")


def validate_ffs(ffs: bytes | bytearray, pe: bytes) -> None:
    if len(ffs) < 24 or int.from_bytes(ffs[20:23], "little") != len(ffs):
        raise ValueError("invalid FFS size")
    if uuid.UUID(bytes_le=bytes(ffs[:16])) != FILE_GUID or ffs[18] != FFS_DRIVER:
        raise ValueError("invalid FFS identity")
    if ffs[19] != FFS_ATTRIB_NONE or ffs[17] != FFS_FIXED_CHECKSUM:
        raise ValueError("FFS attributes/checksum do not match native X99 file convention")
    if sum(value for index, value in enumerate(ffs[:24]) if index not in (17, 23)) & 0xFF:
        raise ValueError("invalid FFS header checksum")

    seen_depex = False
    seen_guided = False
    last_outer_end = 0
    for section_offset, section_size, kind, payload in iter_sections(bytes(ffs[24:])):
        last_outer_end = section_offset + section_size
        if kind == SECTION_DXE_DEPEX:
            if seen_depex:
                raise ValueError("duplicate DXE DEPEX")
            validate_depex(payload)
            seen_depex = True
        elif kind == SECTION_GUID_DEFINED:
            if seen_guided or len(payload) < GUIDED_DATA_OFFSET - 4:
                raise ValueError("invalid/duplicate guided section")
            definition = uuid.UUID(bytes_le=payload[:16])
            data_offset = int.from_bytes(payload[16:18], "little")
            attributes = int.from_bytes(payload[18:20], "little")
            if definition != LZMA_GUID or data_offset != GUIDED_DATA_OFFSET or attributes != GUIDED_PROCESSING_REQUIRED:
                raise ValueError("guided section does not match native AMI LZMA convention")
            # payload begins after the common 4-byte section header, so DataOffset=24 -> payload offset 20.
            expanded = lzma.decompress(payload[data_offset - 4:], format=lzma.FORMAT_ALONE)
            seen_pe = False
            seen_ui = False
            seen_version = False
            last_inner_end = 0
            for inner_offset, inner_size, inner_kind, inner_payload in iter_sections(expanded):
                last_inner_end = inner_offset + inner_size
                if inner_kind == SECTION_PE32:
                    if seen_pe or inner_payload != pe:
                        raise ValueError("PE32 section mismatch")
                    seen_pe = True
                elif inner_kind == SECTION_UI:
                    if seen_ui or inner_payload != "XeonV3 TPM Debug\0".encode("utf-16le"):
                        raise ValueError("unexpected UI section")
                    seen_ui = True
                elif inner_kind == SECTION_VERSION:
                    expected_version = b"\x00\x00" + "3.0\0".encode("utf-16le")
                    if seen_version or inner_payload != expected_version:
                        raise ValueError("unexpected VERSION section")
                    seen_version = True
            if not seen_pe or not seen_ui or not seen_version:
                raise ValueError("PE32/UI/VERSION section set incomplete")
            if last_inner_end != len(expanded):
                raise ValueError("encapsulated section stream contains trailing bytes")
            seen_guided = True
    if not seen_depex or not seen_guided:
        raise ValueError("required DEPEX/guided section missing")
    if last_outer_end != len(ffs) - 24:
        raise ValueError("FFS file contains trailing bytes after its last section")


def validate_native_ami_pe(pe: bytes) -> None:
    if len(pe) < 0x100 or pe[:2] != b"MZ":
        raise ValueError("linked output is not PE/COFF")
    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe_offset > len(pe) - 24 or pe[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    coff = pe_offset + 4
    machine, _, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", pe, coff)
    optional = coff + 20
    if optional > len(pe) - optional_size or optional_size < 0xF0:
        raise ValueError("invalid PE optional header")
    if struct.unpack_from("<H", pe, optional)[0] != PE32_PLUS or machine != PE_MACHINE_X64:
        raise ValueError("debug driver must be x64 PE32+")
    image_base = struct.unpack_from("<Q", pe, optional + 24)[0]
    section_alignment = struct.unpack_from("<I", pe, optional + 32)[0]
    file_alignment = struct.unpack_from("<I", pe, optional + 36)[0]
    os_version = struct.unpack_from("<HH", pe, optional + 40)
    subsystem_version = struct.unpack_from("<HH", pe, optional + 48)
    subsystem = struct.unpack_from("<H", pe, optional + 68)[0]
    dll_characteristics = struct.unpack_from("<H", pe, optional + 70)[0]
    import_rva, import_size = struct.unpack_from("<II", pe, optional + 112 + 8)
    reloc_rva, reloc_size = struct.unpack_from("<II", pe, optional + 112 + 8 * 5)
    if timestamp != 0:
        raise ValueError("PE timestamp must be deterministic")
    if characteristics != PE_EXPECTED_CHARACTERISTICS:
        raise ValueError(f"unexpected PE characteristics 0x{characteristics:04X}")
    if image_base != 0 or section_alignment != PE_NATIVE_ALIGNMENT or file_alignment != PE_NATIVE_ALIGNMENT:
        raise ValueError("PE layout does not match native AMI X99 DXE convention")
    if os_version != (0, 0) or subsystem_version != (0, 0):
        raise ValueError("PE OS/subsystem version must be 0.0 for X99 AMI compatibility")
    if subsystem != PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or dll_characteristics != 0:
        raise ValueError("unexpected EFI subsystem/DLL characteristics")
    if import_rva != 0 or import_size != 0:
        raise ValueError("freestanding DXE driver unexpectedly imports external symbols")
    if reloc_rva == 0 or reloc_size == 0:
        raise ValueError("DXE image has no base relocations")


def command(*args: str) -> None:
    subprocess.run(args, check=True)


def main() -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--lld-link", dest="lld", default=shutil.which("lld-link") or "lld-link")
    parser.add_argument("--output-dir", type=Path, default=here / "out")
    parser.add_argument(
        "--ffs-output",
        type=Path,
        default=here.parent.parent / "src" / "XeonV3Control.Core" / "Firmware" / "TpmDebug" / "XeonV3TpmDebug.ffs",
    )
    args = parser.parse_args()

    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = here / "TpmDebugDxe.c"
    obj = out / "TpmDebugDxe.obj"
    efi = out / "TpmDebugDxe.efi"

    command(
        args.clang,
        "--target=x86_64-pc-windows-msvc",
        "-ffreestanding",
        "-fshort-wchar",
        "-mno-red-zone",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-c",
        str(source),
        "-o",
        str(obj),
    )
    command(
        args.lld,
        "/subsystem:efi_boot_service_driver,0.0",
        "/entry:TpmDebugEntry",
        "/nodefaultlib",
        "/machine:x64",
        "/dll",
        "/driver",
        "/base:0",
        "/align:32",
        "/filealign:32",
        "/dynamicbase:no",
        "/nxcompat:no",
        "/highentropyva:no",
        "/timestamp:0",
        f"/out:{efi}",
        str(obj),
    )

    pe = efi.read_bytes()
    validate_native_ami_pe(pe)
    ffs = build_ffs(pe)
    args.ffs_output.parent.mkdir(parents=True, exist_ok=True)
    args.ffs_output.write_bytes(ffs)

    print(f"EFI: {efi} ({len(pe)} bytes, SHA-256 {hashlib.sha256(pe).hexdigest().upper()})")
    print(f"FFS: {args.ffs_output} ({len(ffs)} bytes, SHA-256 {hashlib.sha256(ffs).hexdigest().upper()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
