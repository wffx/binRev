# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .database import initialize


def _require(document: dict[str, Any], key: str, kind: type) -> Any:
    value = document.get(key)
    if not isinstance(value, kind):
        raise ValueError(f"IDA snapshot field {key!r} must be {kind.__name__}")
    return value


def import_snapshot(snapshot_path: Path, database_path: Path) -> dict[str, Any]:
    document = json.loads(snapshot_path.read_text(encoding="utf-8"))
    ida = _require(document, "ida", dict)
    segments = _require(document, "segments", list)
    functions = _require(document, "functions", list)
    initialize(database_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO ida_snapshot(
                    source_path, ida_version, processor, min_ea, max_ea, document_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(snapshot_path.resolve()),
                    ida.get("version"),
                    ida.get("processor"),
                    ida.get("min_ea"),
                    ida.get("max_ea"),
                    json.dumps(document),
                ),
            )
            snapshot_id = int(cursor.lastrowid)
            connection.executemany(
                """
                INSERT INTO ida_segment(
                    snapshot_id, start_address, end_address, name, permissions, bitness
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        snapshot_id,
                        item["start"],
                        item["end"],
                        item.get("name"),
                        item.get("perm"),
                        item.get("bitness"),
                    )
                    for item in segments
                ],
            )
            connection.executemany(
                """
                INSERT INTO ida_function(
                    snapshot_id, address, end_address, name, prototype, comment,
                    block_count, pseudocode_available
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        snapshot_id,
                        item["address"],
                        item["end"],
                        item.get("name"),
                        item.get("prototype"),
                        item.get("comment"),
                        len(item.get("blocks", [])),
                        int(bool(item.get("pseudocode"))),
                    )
                    for item in functions
                ],
            )
    return {
        "snapshot_id": snapshot_id,
        "segments": len(segments),
        "functions": len(functions),
        "processor": ida.get("processor"),
    }


def build_action_plan(analysis_path: Path, output_path: Path) -> dict[str, Any]:
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    actions: list[dict[str, Any]] = []
    for function in analysis.get("functions", []):
        if function.get("confidence") != "confirmed":
            continue
        address = function["address_hex"]
        actions.append({"action": "create_function", "address": address})
        if function.get("name"):
            actions.append(
                {"action": "rename", "address": address, "name": function["name"]}
            )
        evidence = "; ".join(function.get("evidence", []))
        actions.append(
            {
                "action": "function_comment",
                "address": address,
                "comment": f"[confirmed by hvrev] {evidence}",
            }
        )
    document = {
        "schema_version": 1,
        "transaction": "hvrev-confirmed-function-import",
        "actor": "hvrev-rule-engine",
        "review_required": True,
        "actions": actions,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return {"output": str(output_path.resolve()), "actions": len(actions)}
