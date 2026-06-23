# Prototype test suite.
from __future__ import annotations

import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from hvrev.image import ARM64_IMAGE_MAGIC
from hvrev.knowledge import SYSREGS
from hvrev.pipeline import run_pipeline


def sysreg(name: str, read: bool = False, rt: int = 0) -> int:
    register = next(item for item in SYSREGS if item.name == name)
    return (0xD5200000 if read else 0xD5000000) | (register.encoding << 5) | rt


def make_sample(path: Path, base: int) -> None:
    data = bytearray(0x2000)
    struct.pack_into("<I", data, 0, 0x14000010)
    struct.pack_into("<QQQ", data, 8, 0, len(data), 0)
    struct.pack_into("<I", data, 56, ARM64_IMAGE_MAGIC)
    struct.pack_into("<I", data, 0x40, 0x94000030)  # calls 0x100
    struct.pack_into("<I", data, 0x80, sysreg("HCR_EL2", False, 0))
    struct.pack_into("<I", data, 0x84, sysreg("VTCR_EL2", False, 1))
    struct.pack_into("<I", data, 0x88, sysreg("VTTBR_EL2", False, 2))
    struct.pack_into("<I", data, 0x100, 0xD503201F)  # nop
    struct.pack_into("<I", data, 0x104, 0xD5033F9F)  # dsb sy
    struct.pack_into("<I", data, 0x108, 0xD65F03C0)  # ret
    struct.pack_into("<Q", data, 0x300, base + 0x100)
    path.write_bytes(data)


class PipelineTests(unittest.TestCase):
    def test_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "Image"
            output = root / "recovered"
            make_sample(image, 0x80000000)
            result = run_pipeline(image, output, 0x80000000)
            self.assertEqual(result.base, 0x80000000)
            self.assertTrue((output / "Makefile").is_file())
            self.assertTrue((output / "RECOVERY_STATUS.md").is_file())
            self.assertTrue(
                (output / ".recovery/reports/security-invariants.json").is_file()
            )
            elf = output / ".recovery/synthetic-hypervisor.elf"
            self.assertEqual(elf.read_bytes()[:4], b"\x7fELF")
            manifest = json.loads(
                (output / ".recovery/image-manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["header"]["valid_magic"])
            self.assertEqual(
                manifest["constraints"]["external_analysis_tool"], "IDA"
            )
            self.assertEqual(
                manifest["constraints"]["validation_mode"], "static-only"
            )
            connection = sqlite3.connect(output / ".recovery/analysis.sqlite")
            try:
                count = connection.execute("SELECT COUNT(*) FROM sysreg_use").fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(count, 3)
            self.assertEqual(len(result.events), 1)


if __name__ == "__main__":
    unittest.main()
