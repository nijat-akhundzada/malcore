from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result

try:
    import yara
except ImportError:  # pragma: no cover - exercised by environments without yara-python
    yara = None  # type: ignore[assignment]


DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
YARA_TIMEOUT_SECONDS = 20
MAX_MATCHES = 100
MAX_STRING_MATCHES = 50

RULE_RE = re.compile(
    r"\brule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*(?P<tags>[^{]+))?\s*{(?P<body>.*?)}",
    re.DOTALL,
)
META_BLOCK_RE = re.compile(r"\bmeta\s*:\s*(?P<meta>.*?)(?:\bstrings\s*:|\bcondition\s*:)", re.DOTALL)
META_ASSIGN_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>\"(?:\\.|[^\"])*\"|-?\d+|true|false)",
    re.IGNORECASE,
)


@dataclass
class RuleBundle:
    source: str
    paths: list[Path]
    metadata: dict[str, dict[str, Any]]


class YARAAnalyzer(Analyzer):
    name = "yara"
    category = "signature"

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or Path(os.getenv("MALCORE_YARA_RULES_DIR", DEFAULT_RULES_DIR))

    def supports(self, context: FileContext) -> bool:
        return _runtime_available() and _rule_paths(self.rules_dir)

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            if context.extension == ".yar" or context.extension == ".yara":
                return unsupported_result(self, context)

        result = base_result(self, context)
        result["metadata"]["rules_dir"] = str(self.rules_dir)
        result["metadata"]["runtime"] = _runtime_name()
        result["metadata"]["matches"] = []

        bundle = _load_rule_bundle(self.rules_dir)
        result["metadata"]["rule_count"] = len(bundle.metadata)
        result["metadata"]["rule_files"] = [str(path) for path in bundle.paths]

        if not bundle.paths:
            result["errors"].append("no YARA rules found")
            return result

        matches, errors = _scan_with_yara_python(context, bundle)
        if matches is None:
            matches, errors = _scan_with_yara_cli(context, bundle)

        result["errors"].extend(errors)
        result["metadata"]["matches"] = matches[:MAX_MATCHES]

        for match in result["metadata"]["matches"]:
            result["findings"].append(
                finding(
                    "yara_match",
                    match["severity"],
                    match["description"],
                    rule=match["rule"],
                    namespace=match.get("namespace"),
                    tags=match.get("tags", []),
                )
            )

        return result


def _runtime_available() -> bool:
    return yara is not None or shutil.which("yara") is not None


def _runtime_name() -> str | None:
    if yara is not None:
        return "yara-python"
    if shutil.which("yara") is not None:
        return "yara-cli"
    return None


def _rule_paths(rules_dir: Path) -> list[Path]:
    if not rules_dir.exists() or not rules_dir.is_dir():
        return []

    return sorted(
        path
        for path in rules_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yar", ".yara"}
    )


def _load_rule_bundle(rules_dir: Path) -> RuleBundle:
    paths = _rule_paths(rules_dir)
    chunks = []

    for path in paths:
        chunks.append(f"\n// BEGIN {path.name}\n")
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        chunks.append(f"\n// END {path.name}\n")

    source = "\n".join(chunks)
    return RuleBundle(
        source=source,
        paths=paths,
        metadata=_parse_rule_metadata(source),
    )


def _scan_with_yara_python(context: FileContext, bundle: RuleBundle) -> tuple[list[dict], list[str]] | tuple[None, list[str]]:
    if yara is None:
        return None, []

    try:
        rules = yara.compile(source=bundle.source)
        raw_matches = rules.match(str(context.path), timeout=YARA_TIMEOUT_SECONDS)
    except Exception as exc:
        return [], [f"YARA scan failed: {exc}"]

    matches = [
        _normalize_python_match(match, bundle.metadata)
        for match in raw_matches[:MAX_MATCHES]
    ]
    return matches, []


def _scan_with_yara_cli(context: FileContext, bundle: RuleBundle) -> tuple[list[dict], list[str]]:
    yara_path = shutil.which("yara")
    if not yara_path:
        return [], ["YARA runtime is not installed"]

    with tempfile.NamedTemporaryFile("w", suffix=".yar", encoding="utf-8", delete=False) as rule_file:
        rule_file.write(bundle.source)
        rule_file_path = rule_file.name

    try:
        completed = subprocess.run(
            [yara_path, "-w", rule_file_path, str(context.path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=YARA_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return [], ["YARA scan timed out"]
    finally:
        Path(rule_file_path).unlink(missing_ok=True)

    if completed.returncode not in {0, 1}:
        message = (completed.stderr or completed.stdout or "YARA scan failed").strip()
        return [], [message]

    matches = []
    for line in completed.stdout.splitlines():
        rule = _rule_from_cli_line(line)
        if not rule:
            continue
        matches.append(_match_from_rule_name(rule, bundle.metadata))
        if len(matches) >= MAX_MATCHES:
            break

    return matches, []


def _normalize_python_match(match: Any, metadata_by_rule: dict[str, dict[str, Any]]) -> dict:
    rule = str(getattr(match, "rule", ""))
    metadata = dict(metadata_by_rule.get(rule, {}))
    metadata.update(dict(getattr(match, "meta", {}) or {}))

    return {
        "rule": rule,
        "namespace": _to_str(getattr(match, "namespace", None)),
        "tags": list(getattr(match, "tags", []) or []),
        "meta": metadata,
        "severity": _severity_from_meta(metadata),
        "description": _description_from_meta(rule, metadata),
        "strings": _string_matches(match),
    }


def _match_from_rule_name(rule: str, metadata_by_rule: dict[str, dict[str, Any]]) -> dict:
    metadata = dict(metadata_by_rule.get(rule, {}))
    return {
        "rule": rule,
        "namespace": None,
        "tags": metadata.pop("_tags", []),
        "meta": metadata,
        "severity": _severity_from_meta(metadata),
        "description": _description_from_meta(rule, metadata),
        "strings": [],
    }


def _string_matches(match: Any) -> list[dict]:
    values = []

    for item in getattr(match, "strings", []) or []:
        if isinstance(item, tuple) and len(item) >= 3:
            offset, identifier, data = item[:3]
            values.append(
                {
                    "identifier": _to_str(identifier),
                    "offset": offset,
                    "data": _safe_string_data(data),
                }
            )
            continue

        identifier = _to_str(getattr(item, "identifier", None))
        for instance in getattr(item, "instances", []) or []:
            values.append(
                {
                    "identifier": identifier,
                    "offset": getattr(instance, "offset", None),
                    "data": _safe_string_data(getattr(instance, "matched_data", None)),
                }
            )

        if len(values) >= MAX_STRING_MATCHES:
            break

    return values[:MAX_STRING_MATCHES]


def _parse_rule_metadata(source: str) -> dict[str, dict[str, Any]]:
    metadata_by_rule = {}

    for match in RULE_RE.finditer(source):
        name = match.group("name")
        tags = (match.group("tags") or "").split()
        body = match.group("body")
        metadata = {"_tags": tags}

        meta_match = META_BLOCK_RE.search(body)
        if meta_match:
            for assignment in META_ASSIGN_RE.finditer(meta_match.group("meta")):
                metadata[assignment.group("key")] = _parse_meta_value(assignment.group("value"))

        metadata_by_rule[name] = metadata

    return metadata_by_rule


def _parse_meta_value(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace(r"\"", '"')
    try:
        return int(value)
    except ValueError:
        return value


def _rule_from_cli_line(line: str) -> str | None:
    parts = line.strip().split()
    if not parts:
        return None

    rule = parts[0]
    if ":" in rule:
        rule = rule.split(":", 1)[1]
    return rule


def _severity_from_meta(metadata: dict[str, Any]) -> str:
    severity = str(metadata.get("severity") or metadata.get("risk") or "high").lower()
    if severity in {"low", "medium", "high", "critical"}:
        return severity
    return "high"


def _description_from_meta(rule: str, metadata: dict[str, Any]) -> str:
    return str(metadata.get("description") or f"YARA rule matched: {rule}")


def _safe_string_data(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value[:80].hex()
    return str(value)[:160]


def _to_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
