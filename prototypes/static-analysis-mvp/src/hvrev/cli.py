# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ida import build_action_plan, import_snapshot
from .pipeline import run_pipeline


def parse_integer(value: str) -> int:
    return int(value, 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hvrev",
        description="Recover static evidence and a repository scaffold from an ARM64 EL2 Image",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    pipeline = subparsers.add_parser("pipeline", help="Run the complete static MVP pipeline")
    pipeline.add_argument("image", type=Path)
    pipeline.add_argument("-o", "--output", type=Path, required=True)
    pipeline.add_argument(
        "--base",
        type=parse_integer,
        help="Confirmed load base (decimal or 0x-prefixed); otherwise candidates are scored",
    )

    ida_import = subparsers.add_parser(
        "ida-import", help="Import an IDAPython snapshot into analysis.sqlite"
    )
    ida_import.add_argument("snapshot", type=Path)
    ida_import.add_argument("--database", type=Path, required=True)

    ida_plan = subparsers.add_parser(
        "ida-plan", help="Create a review-required IDA action transaction"
    )
    ida_plan.add_argument("analysis", type=Path)
    ida_plan.add_argument("-o", "--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "pipeline":
            result = run_pipeline(args.image, args.output, args.base)
            print(
                json.dumps(
                    {
                        "output": str(args.output.resolve()),
                        "base": f"0x{result.base:x}",
                        "functions": len(result.functions),
                        "sysreg_uses": len(result.sysregs),
                        "architectural_events": len(result.events),
                        "warning": result.metrics.get("warning"),
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "ida-import":
            print(json.dumps(import_snapshot(args.snapshot, args.database), indent=2))
            return 0
        if args.command == "ida-plan":
            print(json.dumps(build_action_plan(args.analysis, args.output), indent=2))
            return 0
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"hvrev: error: {error}", file=sys.stderr)
        return 1
    return 1
