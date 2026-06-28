"""
parse_arm64_pe_coff.py

Standalone Python script to parse the PE/COFF header embedded in an ARM64
Linux kernel boot executable Image. The PE signature is at file offset 0x40
(res5 field in ARM64 Image header).

Usage:
    python parse_arm64_pe_coff.py <path-to-Image>

Output:
    JSON with ImageBase, AddressOfEntryPoint, BaseOfCode, SizeOfImage, etc.
"""

import struct
import sys
import json


# ARM64 Image header fields
IMAGE_HEADER_SIZE = 64
PE_SIGNATURE_OFFSET = 0x40  # res5 in ARM64 Image header


def parse_pe_coff(data):
    """Parse PE/COFF header from ARM64 Image binary."""
    result = {}

    # PE signature at res5 offset
    pe_off = PE_SIGNATURE_OFFSET
    if len(data) < pe_off + 4:
        return {"error": "File too small for PE signature"}

    sig = data[pe_off:pe_off + 4]
    if sig != b"PE\x00\x00":
        return {"error": f"No PE signature at offset 0x{pe_off:X} (found: {sig.hex()})"}

    result["pe_signature"] = "valid"

    # COFF File Header (20 bytes)
    coff_off = pe_off + 4
    machine = struct.unpack_from("<H", data, coff_off)[0]
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    size_of_opt_header = struct.unpack_from("<H", data, coff_off + 16)[0]

    result["machine"] = f"0x{machine:04X}"
    machine_names = {0xAA64: "ARM64", 0x014C: "x86", 0x8664: "x64"}
    result["machine_name"] = machine_names.get(machine, "unknown")
    result["num_sections"] = num_sections
    result["size_of_optional_header"] = size_of_opt_header

    # Optional Header
    opt_off = coff_off + 20
    if len(data) < opt_off + size_of_opt_header:
        return {"error": "File too small for optional header"}

    magic = struct.unpack_from("<H", data, opt_off)[0]
    result["optional_header_magic"] = f"0x{magic:04X}"
    if magic == 0x020B:
        result["pe_format"] = "PE32+ (64-bit)"
        pe32_plus = True
    elif magic == 0x010B:
        result["pe_format"] = "PE32 (32-bit)"
        pe32_plus = False
    else:
        result["pe_format"] = "unknown"
        pe32_plus = False

    # AddressOfEntryPoint (offset 16 in optional header)
    entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    result["address_of_entry_point"] = f"0x{entry_rva:X}"

    # BaseOfCode (offset 20)
    base_of_code = struct.unpack_from("<I", data, opt_off + 20)[0]
    result["base_of_code"] = f"0x{base_of_code:X}"

    if pe32_plus:
        # ImageBase (offset 24, 8 bytes for PE32+)
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        result["image_base"] = f"0x{image_base:X}"
        # SizeOfImage (offset 56)
        size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
    else:
        # ImageBase (offset 28, 4 bytes for PE32)
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        result["image_base"] = f"0x{image_base:X}"
        # SizeOfImage (offset 56)
        size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]

    result["size_of_image"] = f"0x{size_of_image:X}"

    # SectionAlignment and FileAlignment
    section_align = struct.unpack_from("<I", data, opt_off + 32)[0]
    file_align = struct.unpack_from("<I", data, opt_off + 36)[0]
    result["section_alignment"] = f"0x{section_align:X}"
    result["file_alignment"] = f"0x{file_align:X}"

    return result


def parse_arm64_header(data):
    """Parse ARM64 Image header (first 64 bytes)."""
    if len(data) < 64:
        return {"error": "File too small"}

    hdr = {}
    hdr["code0"] = f"0x{struct.unpack_from('<I', data, 0x00)[0]:08X}"
    hdr["code1"] = f"0x{struct.unpack_from('<I', data, 0x04)[0]:08X}"
    hdr["text_offset"] = struct.unpack_from("<Q", data, 0x08)[0]
    hdr["image_size"] = struct.unpack_from("<Q", data, 0x10)[0]
    hdr["flags"] = f"0x{struct.unpack_from('<Q', data, 0x18)[0]:X}"
    magic = struct.unpack_from("<I", data, 0x38)[0]
    magic_str = struct.pack("<I", magic).decode("ascii", errors="replace")
    hdr["magic"] = f"0x{magic:08X}"
    hdr["magic_ascii"] = magic_str
    hdr["res5_pe_offset"] = f"0x{struct.unpack_from('<I', data, 0x3C)[0]:X}"

    hdr["format_status"] = "compatible" if magic == 0x644D5241 else "incompatible"
    return hdr


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_arm64_pe_coff.py <path-to-Image>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()

    result = {
        "file_size": len(data),
        "arm64_header": parse_arm64_header(data),
        "pe_coff": parse_pe_coff(data)
    }

    print(json.dumps(result, indent=2))
