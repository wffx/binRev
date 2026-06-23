# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from typing import Iterable

from .knowledge import SYSREG_BY_ENCODING
from .models import ArchitecturalEvent, BaseCandidate, FunctionCandidate, SysRegUse


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def words(data: bytes) -> Iterable[tuple[int, int]]:
    usable = len(data) - (len(data) % 4)
    for offset in range(0, usable, 4):
        yield offset, struct.unpack_from("<I", data, offset)[0]


def branch_target(insn: int, pc: int) -> tuple[str, int] | None:
    opcode = insn & 0xFC000000
    if opcode not in (0x14000000, 0x94000000):
        return None
    displacement = sign_extend(insn & 0x03FFFFFF, 26) << 2
    return ("bl" if opcode == 0x94000000 else "b", pc + displacement)


def adrp_target(insn: int, pc: int) -> tuple[int, int] | None:
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    immediate = sign_extend((immhi << 2) | immlo, 21) << 12
    return insn & 0x1F, (pc & ~0xFFF) + immediate


def add_immediate(insn: int) -> tuple[int, int, int] | None:
    if (insn & 0x7F000000) != 0x11000000:
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    immediate = (insn >> 10) & 0xFFF
    if insn & (1 << 22):
        immediate <<= 12
    return rd, rn, immediate


def ldr_literal_target(insn: int, pc: int) -> int | None:
    if (insn & 0x3B000000) != 0x18000000:
        return None
    immediate = sign_extend((insn >> 5) & 0x7FFFF, 19) << 2
    return pc + immediate


def decode_sysreg(insn: int, address: int, offset: int) -> SysRegUse | None:
    masked = insn & 0xFFF00000
    if masked == 0xD5300000:
        direction = "read"
    elif masked == 0xD5100000:
        direction = "write"
    else:
        return None
    encoding = (insn >> 5) & 0xFFFF
    register = SYSREG_BY_ENCODING.get(encoding)
    if not register:
        return None
    return SysRegUse(
        address=address,
        offset=offset,
        instruction=insn,
        direction=direction,
        register=register.name,
        rt=insn & 0x1F,
        subsystem=register.subsystem,
    )


def _candidate_bases_from_pointers(data: bytes) -> list[int]:
    counts: Counter[int] = Counter()
    size = len(data)
    for offset in range(0, len(data) - 7, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        if value < 0x10000 or value & 0x3:
            continue
        # A pointer into this image implies base ~= pointer - an in-image offset.
        # Bucket to the common 2 MiB load alignment to keep the search bounded.
        for guessed_offset in (0, offset, offset & ~0xFFF):
            base = (value - guessed_offset) & ~0x1FFFFF
            if base <= value < base + size + 0x200000:
                counts[base] += 1
    defaults = [0, 0x40000000, 0x40080000, 0x80000000, 0x80080000]
    values = defaults + [base for base, _ in counts.most_common(16)]
    return list(dict.fromkeys(value for value in values if value >= 0))


def score_base(data: bytes, base: int) -> BaseCandidate:
    pointer_hits = 0
    pointer_total = 0
    for offset in range(0, len(data) - 7, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        if value >= 0x10000 and not (value & 0x3):
            pointer_total += 1
            if base <= value < base + len(data):
                pointer_hits += 1

    adrp_total = 0
    adrp_closed = 0
    for offset, insn in words(data):
        decoded = adrp_target(insn, base + offset)
        if not decoded:
            continue
        adrp_total += 1
        target = decoded[1]
        if base <= target < base + len(data):
            adrp_closed += 1

    pointer_ratio = pointer_hits / max(pointer_total, 1)
    adrp_ratio = adrp_closed / max(adrp_total, 1)
    score = round(pointer_ratio * 65.0 + adrp_ratio * 35.0, 4)
    notes = []
    if pointer_hits:
        notes.append(f"{pointer_hits} absolute pointer(s) land inside the image")
    if adrp_closed:
        notes.append(f"{adrp_closed}/{adrp_total} ADRP target(s) land inside the image")
    return BaseCandidate(
        base=base,
        score=score,
        pointer_hits=pointer_hits,
        pointer_total=pointer_total,
        adrp_closed=adrp_closed,
        adrp_total=adrp_total,
        notes=notes,
    )


def infer_bases(data: bytes, explicit: int | None = None) -> list[BaseCandidate]:
    bases = [explicit] if explicit is not None else _candidate_bases_from_pointers(data)
    scored = [score_base(data, base) for base in bases]
    return sorted(scored, key=lambda item: (item.score, item.pointer_hits), reverse=True)


def scan_sysregs(data: bytes, base: int) -> list[SysRegUse]:
    found = []
    for offset, insn in words(data):
        decoded = decode_sysreg(insn, base + offset, offset)
        if decoded:
            found.append(decoded)
    return found


def scan_architectural_events(data: bytes, base: int) -> list[ArchitecturalEvent]:
    exact = {
        0xD69F03E0: ("exception-return", "context", "ERET"),
        0xD503207F: ("wait-for-interrupt", "scheduler", "WFI"),
        0xD503205F: ("wait-for-event", "scheduler", "WFE"),
        0xD5033FDF: ("instruction-barrier", "memory", "ISB SY"),
        0xD5033F9F: ("data-sync-barrier", "memory", "DSB SY"),
        0xD5033FBF: ("data-memory-barrier", "memory", "DMB SY"),
    }
    events: list[ArchitecturalEvent] = []
    for offset, insn in words(data):
        if insn in exact:
            kind, subsystem, detail = exact[insn]
        elif (insn & 0xFFE0001F) == 0xD4000002:
            immediate = (insn >> 5) & 0xFFFF
            kind, subsystem, detail = (
                "hypervisor-call",
                "lifecycle",
                f"HVC #{immediate}",
            )
        elif (insn & 0xFFE0001F) == 0xD4000003:
            immediate = (insn >> 5) & 0xFFFF
            kind, subsystem, detail = (
                "secure-monitor-call",
                "smccc",
                f"SMC #{immediate}",
            )
        else:
            continue
        events.append(
            ArchitecturalEvent(
                address=base + offset,
                offset=offset,
                instruction=insn,
                kind=kind,
                subsystem=subsystem,
                detail=detail,
            )
        )
    return events


def _looks_executable(insn: int) -> bool:
    if insn in (0, 0xFFFFFFFF):
        return False
    if branch_target(insn, 0) or adrp_target(insn, 0) or decode_sysreg(insn, 0, 0):
        return True
    top = insn >> 25
    return top not in (0, 0x7F)


def vector_table_candidates(data: bytes, base: int) -> list[tuple[int, float]]:
    candidates = []
    for table_offset in range(0, len(data) - 0x800 + 1, 0x800):
        active_slots = 0
        executable_slots = 0
        branch_slots = 0
        for slot in range(16):
            start = table_offset + slot * 0x80
            slot_words = [
                struct.unpack_from("<I", data, start + index * 4)[0]
                for index in range(4)
            ]
            if any(slot_words):
                active_slots += 1
            if any(_looks_executable(item) for item in slot_words):
                executable_slots += 1
            if branch_target(slot_words[0], base + start):
                branch_slots += 1
        if active_slots >= 8 and executable_slots >= 8:
            score = active_slots + executable_slots + branch_slots * 2
            candidates.append((table_offset, score))
    return sorted(candidates, key=lambda item: item[1], reverse=True)[:8]


def discover_functions(
    data: bytes, base: int, entry_offset: int = 0
) -> list[FunctionCandidate]:
    candidates: dict[int, FunctionCandidate] = {}

    def add(offset: int, source: str, confidence: str, evidence: str) -> None:
        if offset < 0 or offset >= len(data) or offset & 0x3:
            return
        current = candidates.get(offset)
        if not current:
            candidates[offset] = FunctionCandidate(
                address=base + offset,
                offset=offset,
                source=source,
                confidence=confidence,
                evidence=[evidence],
            )
        elif evidence not in current.evidence:
            current.evidence.append(evidence)

    add(entry_offset, "image-entry", "confirmed", "ARM64 Image entry point")
    for offset, insn in words(data):
        decoded = branch_target(insn, base + offset)
        if not decoded:
            continue
        kind, target = decoded
        target_offset = target - base
        if kind == "bl":
            add(target_offset, "direct-call", "inferred", f"BL from 0x{base + offset:x}")

    for table_offset, score in vector_table_candidates(data, base):
        add(
            table_offset,
            "exception-vector",
            "inferred",
            f"2 KiB-aligned vector table score {score:.1f}",
        )
        for slot in range(16):
            start = table_offset + slot * 0x80
            insn = struct.unpack_from("<I", data, start)[0]
            decoded = branch_target(insn, base + start)
            if decoded:
                add(
                    decoded[1] - base,
                    "vector-handler",
                    "inferred",
                    f"Vector slot {slot} branch",
                )
    return sorted(candidates.values(), key=lambda item: item.offset)


def classify_functions(
    functions: list[FunctionCandidate], sysregs: list[SysRegUse], window: int = 0x200
) -> None:
    uses_by_page: dict[int, list[SysRegUse]] = defaultdict(list)
    for use in sysregs:
        uses_by_page[use.offset // window].append(use)
    for function in functions:
        nearby = []
        for page in range(max(0, function.offset // window - 1), function.offset // window + 2):
            nearby.extend(uses_by_page.get(page, []))
        nearby = [item for item in nearby if abs(item.offset - function.offset) <= window]
        if not nearby:
            continue
        counts = Counter(item.subsystem for item in nearby)
        function.subsystem = counts.most_common(1)[0][0]
        register_names = sorted({item.register for item in nearby})
        function.evidence.append("nearby sysregs: " + ", ".join(register_names))
        function.name = f"sub_{function.subsystem}_{function.address:x}"
