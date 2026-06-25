from __future__ import annotations

import argparse
import json
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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = analyze_file(args.file, selected=args.analyzer)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(result, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
