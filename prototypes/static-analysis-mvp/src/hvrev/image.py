# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from pathlib import Path

from .models import Artifact, ImageHeader

ARM64_IMAGE_MAGIC = 0x644D5241
HEADER_SIZE = 64

SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x04\x22\x4d\x18", "lz4-frame"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"070701", "cpio-newc"),
    (b"070702", "cpio-newc-crc"),
)


def parse_header(data: bytes) -> ImageHeader:
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Image is too small for an ARM64 header ({len(data)} bytes)")
    code0, code1 = struct.unpack_from("<II", data, 0)
    text_offset, image_size, flags = struct.unpack_from("<QQQ", data, 8)
    magic = struct.unpack_from("<I", data, 56)[0]
    return ImageHeader(
        code0=code0,
        code1=code1,
        text_offset=text_offset,
        image_size=image_size,
        flags=flags,
        magic=magic,
        valid_magic=magic == ARM64_IMAGE_MAGIC,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = Counter(block)
    total = len(block)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def entropy_map(data: bytes, block_size: int = 0x10000) -> list[dict[str, float | int]]:
    result = []
    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]
        result.append(
            {"offset": offset, "size": len(block), "entropy": round(entropy(block), 4)}
        )
    return result


def extract_ascii_strings(
    data: bytes, min_length: int = 5, limit: int = 20_000
) -> list[tuple[int, str]]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    values: list[tuple[int, str]] = []
    for match in pattern.finditer(data):
        values.append((match.start(), match.group().decode("ascii", "replace")))
        if len(values) >= limit:
            break
    return values


def _scan_all(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def scan_artifacts(data: bytes, header: ImageHeader) -> list[Artifact]:
    artifacts: list[Artifact] = []
    declared_end = header.image_size if header.image_size else len(data)
    if declared_end < len(data):
        artifacts.append(
            Artifact(
                kind="appended-data",
                offset=declared_end,
                size=len(data) - declared_end,
                description="Bytes beyond the Image header's declared image_size",
                confidence="confirmed",
            )
        )

    for signature, name in SIGNATURES:
        for offset in _scan_all(data, signature):
            artifacts.append(
                Artifact(
                    kind="embedded-signature",
                    offset=offset,
                    description=name,
                    confidence="confirmed",
                )
            )

    # Flattened device tree magic is big-endian. Validate total size before accepting it.
    for offset in _scan_all(data, b"\xd0\x0d\xfe\xed"):
        size = None
        confidence = "inferred"
        if offset + 8 <= len(data):
            candidate_size = struct.unpack_from(">I", data, offset + 4)[0]
            if 40 <= candidate_size <= len(data) - offset:
                size = candidate_size
                confidence = "confirmed"
        artifacts.append(
            Artifact(
                kind="device-tree-blob",
                offset=offset,
                size=size,
                description="Flattened Device Tree candidate",
                confidence=confidence,
            )
        )

    strings = extract_ascii_strings(data)
    keywords = {
        "EL2": "virtualization-string",
        "HYPERVISOR": "virtualization-string",
        "VTTBR": "virtualization-string",
        "HKIP": "security-string",
        "GIC": "interrupt-string",
        "SMMU": "iommu-string",
        "VMID": "virtualization-string",
    }
    for offset, value in strings:
        upper = value.upper()
        matched = next((kind for word, kind in keywords.items() if word in upper), None)
        if matched:
            artifacts.append(
                Artifact(
                    kind=matched,
                    offset=offset,
                    size=len(value),
                    description=value[:240],
                    confidence="confirmed",
                )
            )
    return sorted(artifacts, key=lambda item: (item.offset, item.kind))


def build_manifest(path: Path, data: bytes, header: ImageHeader) -> dict:
    return {
        "schema_version": 1,
        "input": {
            "name": path.name,
            "size": len(data),
            "sha256": sha256_bytes(data),
            "format": "arm64-boot-executable-image",
            "endianness": "little",
        },
        "header": header.to_dict(),
        "entropy": entropy_map(data),
        "assumptions": [
            "Payload is analyzed as a freestanding ARMv8-A EL2 hypervisor.",
            "Linux kernel internal metadata is not assumed to exist.",
            "Business-domain labels are hypotheses until supported by binary evidence.",
        ],
        "constraints": {
            "only_input": "Image",
            "known": [
                "ARM64 boot executable Image format",
                "little-endian encoding",
                "EL2 hypervisor business background",
            ],
            "unavailable": [
                "symbols and debug information",
                "source code, headers, SDK and BSP",
                "external DTB, configuration and boot logs",
                "target hardware and dynamic execution",
                "platform manuals and internal specifications",
                "matching source repositories",
                "cross compiler and binary comparison tools",
                "IDA MCP and non-IDA reverse-engineering tools",
            ],
            "external_analysis_tool": "IDA",
            "validation_mode": "static-only",
            "deliverable": "static-recovery-repository",
        },
        "non_claims": [
            "The recovered repository is not claimed to match the original source.",
            "Generated C or assembly is not claimed to compile or run.",
            "Static analysis alone is not claimed to prove security.",
        ],
    }
