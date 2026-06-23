# Prototype test suite.
from __future__ import annotations

import struct
import unittest

from hvrev.image import ARM64_IMAGE_MAGIC, parse_header, scan_artifacts


class ImageTests(unittest.TestCase):
    def test_parse_arm64_header(self) -> None:
        data = bytearray(128)
        struct.pack_into("<IIQQQ", data, 0, 0x14000010, 0, 0x80000, 128, 3)
        struct.pack_into("<I", data, 56, ARM64_IMAGE_MAGIC)
        header = parse_header(data)
        self.assertTrue(header.valid_magic)
        self.assertEqual(header.text_offset, 0x80000)
        self.assertEqual(header.image_size, 128)

    def test_detect_appended_dtb(self) -> None:
        data = bytearray(256)
        struct.pack_into("<IIQQQ", data, 0, 0, 0, 0, 128, 0)
        struct.pack_into("<I", data, 56, ARM64_IMAGE_MAGIC)
        data[128:136] = b"\xd0\x0d\xfe\xed" + struct.pack(">I", 64)
        artifacts = scan_artifacts(bytes(data), parse_header(data))
        kinds = [item.kind for item in artifacts]
        self.assertIn("appended-data", kinds)
        self.assertIn("device-tree-blob", kinds)


if __name__ == "__main__":
    unittest.main()
