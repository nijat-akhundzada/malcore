from __future__ import annotations

import argparse
import json
import os
import sys

from .runner import analyze_file, analyzer_names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malcore-analyze",
        description="Run MALCORE static analyzers for a file and emit JSON.",
    )
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument(
        "--analyzer",
        choices=["auto", "all"] + analyzer_names(),
        default="auto",
        help="Analyzer selection mode",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument(
        "--archive-password",
        default=os.getenv("MALCORE_ARCHIVE_PASSWORD", ""),
        help="Password to use when extracting encrypted archives",
    )
    parser.add_argument(
        "--archive-max-depth",
        default=int(os.getenv("MALCORE_ARCHIVE_MAX_DEPTH", "2")),
        type=int,
        help="Maximum nested archive recursion depth",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = analyze_file(
            args.file,
            selected=args.analyzer,
            archive_password=args.archive_password or None,
            archive_max_depth=args.archive_max_depth,
        )
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(result, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
