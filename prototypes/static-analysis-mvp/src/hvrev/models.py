# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ImageHeader:
    code0: int
    code1: int
    text_offset: int
    image_size: int
    flags: int
    magic: int
    valid_magic: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Artifact:
    kind: str
    offset: int
    size: int | None = None
    description: str = ""
    confidence: str = "inferred"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BaseCandidate:
    base: int
    score: float
    pointer_hits: int
    pointer_total: int
    adrp_closed: int
    adrp_total: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["base_hex"] = f"0x{self.base:x}"
        return value


@dataclass(slots=True)
class FunctionCandidate:
    address: int
    offset: int
    source: str
    confidence: str
    subsystem: str = "unknown"
    name: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["address_hex"] = f"0x{self.address:x}"
        value["offset_hex"] = f"0x{self.offset:x}"
        return value


@dataclass(slots=True)
class SysRegUse:
    address: int
    offset: int
    instruction: int
    direction: str
    register: str
    rt: int
    subsystem: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["address_hex"] = f"0x{self.address:x}"
        value["instruction_hex"] = f"0x{self.instruction:08x}"
        return value


@dataclass(slots=True)
class ArchitecturalEvent:
    address: int
    offset: int
    instruction: int
    kind: str
    subsystem: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["address_hex"] = f"0x{self.address:x}"
        value["instruction_hex"] = f"0x{self.instruction:08x}"
        return value


@dataclass(slots=True)
class AnalysisResult:
    base: int
    entry: int
    functions: list[FunctionCandidate]
    sysregs: list[SysRegUse]
    events: list[ArchitecturalEvent]
    artifacts: list[Artifact]
    base_candidates: list[BaseCandidate]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": self.base,
            "base_hex": f"0x{self.base:x}",
            "entry": self.entry,
            "entry_hex": f"0x{self.entry:x}",
            "functions": [item.to_dict() for item in self.functions],
            "sysregs": [item.to_dict() for item in self.sysregs],
            "events": [item.to_dict() for item in self.events],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "base_candidates": [item.to_dict() for item in self.base_candidates],
            "metrics": self.metrics,
        }
