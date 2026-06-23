# Prototype test suite.
from __future__ import annotations

import struct
import unittest

from hvrev.aarch64 import (
    branch_target,
    decode_sysreg,
    discover_functions,
    infer_bases,
    scan_architectural_events,
    scan_sysregs,
)
from hvrev.knowledge import SYSREGS


def system_instruction(name: str, read: bool, rt: int = 0) -> int:
    register = next(item for item in SYSREGS if item.name == name)
    base = 0xD5200000 if read else 0xD5000000
    return base | (register.encoding << 5) | rt


class AArch64Tests(unittest.TestCase):
    def test_branch_decode(self) -> None:
        decoded = branch_target(0x94000010, 0x80000000)
        self.assertEqual(decoded, ("bl", 0x80000040))

    def test_sysreg_decode(self) -> None:
        insn = system_instruction("VTTBR_EL2", False, 3)
        decoded = decode_sysreg(insn, 0x80000100, 0x100)
        self.assertIsNotNone(decoded)
        assert decoded
        self.assertEqual(decoded.register, "VTTBR_EL2")
        self.assertEqual(decoded.direction, "write")
        self.assertEqual(decoded.rt, 3)

    def test_discovery_and_explicit_base(self) -> None:
        data = bytearray(0x200)
        struct.pack_into("<I", data, 0x40, 0x94000030)  # BL from 0x40 to 0x100.
        struct.pack_into("<I", data, 0x80, system_instruction("HCR_EL2", True))
        bases = infer_bases(bytes(data), 0x80000000)
        self.assertEqual(bases[0].base, 0x80000000)
        functions = discover_functions(bytes(data), 0x80000000)
        self.assertIn(0x100, [item.offset for item in functions])
        uses = scan_sysregs(bytes(data), 0x80000000)
        self.assertEqual(uses[0].register, "HCR_EL2")

    def test_architectural_events(self) -> None:
        data = struct.pack("<III", 0xD4000002, 0xD5033F9F, 0xD69F03E0)
        events = scan_architectural_events(data, 0x80000000)
        self.assertEqual(
            [item.kind for item in events],
            ["hypervisor-call", "data-sync-barrier", "exception-return"],
        )


if __name__ == "__main__":
    unittest.main()
