# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import struct
from pathlib import Path

from .models import FunctionCandidate

ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
SECTION_HEADER_SIZE = 64
PAYLOAD_OFFSET = 0x1000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_synthetic_elf(
    image: bytes,
    base: int,
    entry: int,
    functions: list[FunctionCandidate],
    output: Path,
) -> None:
    names = b"\x00"
    symbol_names: list[int] = []
    for index, function in enumerate(functions):
        name = function.name or f"sub_{function.address:x}"
        symbol_names.append(len(names))
        names += name.encode("utf-8", "replace") + b"\x00"

    symbols = bytearray(24)  # Required null symbol.
    for function, name_offset in zip(functions, symbol_names):
        symbols.extend(
            struct.pack(
                "<IBBHQQ",
                name_offset,
                0x12,  # STB_GLOBAL | STT_FUNC
                0,
                1,  # .image
                function.address,
                0,
            )
        )

    section_names = b"\x00.image\x00.symtab\x00.strtab\x00.shstrtab\x00"
    image_offset = PAYLOAD_OFFSET
    symtab_offset = _align(image_offset + len(image), 8)
    strtab_offset = symtab_offset + len(symbols)
    shstrtab_offset = strtab_offset + len(names)
    section_offset = _align(shstrtab_offset + len(section_names), 8)

    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,  # ET_EXEC
        183,  # EM_AARCH64
        1,
        entry,
        ELF_HEADER_SIZE,
        section_offset,
        0,
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        1,
        SECTION_HEADER_SIZE,
        5,
        4,
    )
    program = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        7,  # RWX: permissions are refined later in IDA
        image_offset,
        base,
        base,
        len(image),
        len(image),
        0x1000,
    )

    sections = bytearray(SECTION_HEADER_SIZE)
    sections.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            1,
            1,  # SHT_PROGBITS
            0x7,
            base,
            image_offset,
            len(image),
            0,
            0,
            4,
            0,
        )
    )
    sections.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            8,
            2,  # SHT_SYMTAB
            0,
            0,
            symtab_offset,
            len(symbols),
            3,
            1,
            8,
            24,
        )
    )
    sections.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            16,
            3,  # SHT_STRTAB
            0,
            0,
            strtab_offset,
            len(names),
            0,
            0,
            1,
            0,
        )
    )
    sections.extend(
        struct.pack(
            "<IIQQQQIIQQ",
            24,
            3,
            0,
            0,
            shstrtab_offset,
            len(section_names),
            0,
            0,
            1,
            0,
        )
    )

    blob = bytearray(header + program)
    blob.extend(bytes(image_offset - len(blob)))
    blob.extend(image)
    blob.extend(bytes(symtab_offset - len(blob)))
    blob.extend(symbols)
    blob.extend(names)
    blob.extend(section_names)
    blob.extend(bytes(section_offset - len(blob)))
    blob.extend(sections)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(blob)
