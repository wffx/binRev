# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .models import AnalysisResult

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS artifact (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    file_offset INTEGER NOT NULL,
    size INTEGER,
    description TEXT NOT NULL,
    confidence TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS base_candidate (
    id INTEGER PRIMARY KEY,
    base_address INTEGER NOT NULL,
    score REAL NOT NULL,
    pointer_hits INTEGER NOT NULL,
    pointer_total INTEGER NOT NULL,
    adrp_closed INTEGER NOT NULL,
    adrp_total INTEGER NOT NULL,
    selected INTEGER NOT NULL DEFAULT 0,
    notes_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS function_candidate (
    id INTEGER PRIMARY KEY,
    address INTEGER NOT NULL UNIQUE,
    file_offset INTEGER NOT NULL,
    name TEXT,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sysreg_use (
    id INTEGER PRIMARY KEY,
    address INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    instruction INTEGER NOT NULL,
    direction TEXT NOT NULL,
    register_name TEXT NOT NULL,
    rt INTEGER NOT NULL,
    subsystem TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS architectural_event (
    id INTEGER PRIMARY KEY,
    address INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    instruction INTEGER NOT NULL,
    kind TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decision (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS analysis_run (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tool_version TEXT NOT NULL,
    base_address INTEGER NOT NULL,
    metrics_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ida_snapshot (
    id INTEGER PRIMARY KEY,
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_path TEXT NOT NULL,
    ida_version TEXT,
    processor TEXT,
    min_ea INTEGER,
    max_ea INTEGER,
    document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ida_function (
    snapshot_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    end_address INTEGER NOT NULL,
    name TEXT,
    prototype TEXT,
    comment TEXT,
    block_count INTEGER NOT NULL,
    pseudocode_available INTEGER NOT NULL,
    PRIMARY KEY(snapshot_id, address),
    FOREIGN KEY(snapshot_id) REFERENCES ida_snapshot(id)
);
CREATE TABLE IF NOT EXISTS ida_segment (
    snapshot_id INTEGER NOT NULL,
    start_address INTEGER NOT NULL,
    end_address INTEGER NOT NULL,
    name TEXT,
    permissions INTEGER,
    bitness INTEGER,
    PRIMARY KEY(snapshot_id, start_address),
    FOREIGN KEY(snapshot_id) REFERENCES ida_snapshot(id)
);
"""


def initialize(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.executescript(SCHEMA)


def store_analysis(path: Path, result: AnalysisResult, tool_version: str) -> None:
    initialize(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            for table in (
                "artifact",
                "base_candidate",
                "function_candidate",
                "sysreg_use",
                "architectural_event",
            ):
                connection.execute(f"DELETE FROM {table}")
            connection.executemany(
                """
                INSERT INTO artifact(
                    kind, file_offset, size, description, confidence, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.kind,
                        item.offset,
                        item.size,
                        item.description,
                        item.confidence,
                        json.dumps(item.metadata, sort_keys=True),
                    )
                    for item in result.artifacts
                ],
            )
            connection.executemany(
                """
                INSERT INTO base_candidate(
                    base_address, score, pointer_hits, pointer_total,
                    adrp_closed, adrp_total, selected, notes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.base,
                        item.score,
                        item.pointer_hits,
                        item.pointer_total,
                        item.adrp_closed,
                        item.adrp_total,
                        int(item.base == result.base),
                        json.dumps(item.notes),
                    )
                    for item in result.base_candidates
                ],
            )
            connection.executemany(
                """
                INSERT INTO function_candidate(
                    address, file_offset, name, source, confidence, subsystem, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.address,
                        item.offset,
                        item.name,
                        item.source,
                        item.confidence,
                        item.subsystem,
                        json.dumps(item.evidence),
                    )
                    for item in result.functions
                ],
            )
            connection.executemany(
                """
                INSERT INTO sysreg_use(
                    address, file_offset, instruction, direction, register_name, rt, subsystem
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.address,
                        item.offset,
                        item.instruction,
                        item.direction,
                        item.register,
                        item.rt,
                        item.subsystem,
                    )
                    for item in result.sysregs
                ],
            )
            connection.executemany(
                """
                INSERT INTO architectural_event(
                    address, file_offset, instruction, kind, subsystem, detail
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.address,
                        item.offset,
                        item.instruction,
                        item.kind,
                        item.subsystem,
                        item.detail,
                    )
                    for item in result.events
                ],
            )
            connection.execute(
                """
                INSERT INTO analysis_run(tool_version, base_address, metrics_json)
                VALUES (?, ?, ?)
                """,
                (tool_version, result.base, json.dumps(result.metrics, sort_keys=True)),
            )
