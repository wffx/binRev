# Prototype test suite.
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hvrev.database import initialize
from hvrev.ida import build_action_plan, import_snapshot


class IDAIntegrationTests(unittest.TestCase):
    def test_import_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot.json"
            database = root / "analysis.sqlite"
            snapshot.write_text(
                json.dumps(
                    {
                        "ida": {
                            "version": "9.0",
                            "processor": "ARM",
                            "min_ea": 0x80000000,
                            "max_ea": 0x80001000,
                        },
                        "segments": [
                            {
                                "start": 0x80000000,
                                "end": 0x80001000,
                                "name": ".image",
                                "perm": 7,
                                "bitness": 2,
                            }
                        ],
                        "functions": [
                            {
                                "address": 0x80000000,
                                "end": 0x80000040,
                                "name": "sub_80000000",
                                "prototype": None,
                                "comment": None,
                                "blocks": [],
                                "pseudocode": "void f(void) {}",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = import_snapshot(snapshot, database)
            self.assertEqual(result["functions"], 1)
            connection = sqlite3.connect(database)
            try:
                count = connection.execute("SELECT COUNT(*) FROM ida_function").fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(count, 1)

    def test_build_review_action_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis.json"
            output = root / "actions.json"
            analysis.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "address_hex": "0x80000000",
                                "name": "hyp_entry",
                                "confidence": "confirmed",
                                "evidence": ["Image entry"],
                            },
                            {
                                "address_hex": "0x80000100",
                                "name": "maybe_vm",
                                "confidence": "inferred",
                                "evidence": [],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = build_action_plan(analysis, output)
            self.assertEqual(result["actions"], 3)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(document["review_required"])


if __name__ == "__main__":
    unittest.main()
