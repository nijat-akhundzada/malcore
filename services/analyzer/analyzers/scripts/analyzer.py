from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Pattern

from ..core import Analyzer, FileContext, base_result, finding, read_text_safely, unique, unsupported_result
from ..iocs.extractor import extract_iocs_from_text


BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")


@dataclass(frozen=True)
class ScriptPattern:
    finding_type: str
    severity: str
    description: str
    regex: Pattern[str]
    languages: set[str]


class ScriptAnalyzer(Analyzer):
    name = "scripts"
    category = "script"

    script_extensions = {".ps1", ".js", ".vbs", ".bat", ".cmd", ".py", ".sh"}

    suspicious_patterns = [
        ScriptPattern(
            "script_dynamic_execution",
            "high",
            "PowerShell Invoke-Expression or iex dynamic execution",
            re.compile(r"\b(?:Invoke-Expression|iex)\b", re.IGNORECASE),
            {".ps1"},
        ),
        ScriptPattern(
            "script_dynamic_execution",
            "high",
            "JavaScript eval dynamic execution",
            re.compile(r"\beval\s*\(", re.IGNORECASE),
            {".js"},
        ),
        ScriptPattern(
            "script_dynamic_execution",
            "medium",
            "JavaScript Function constructor dynamic execution",
            re.compile(r"\b(?:window\s*\.\s*)?Function\s*\(", re.IGNORECASE),
            {".js"},
        ),
        ScriptPattern(
            "script_process_execution",
            "high",
            "JavaScript child_process exec-style command execution",
            re.compile(r"(?:child_process\s*\.\s*)?\bexec(?:Sync|File)?\s*\(", re.IGNORECASE),
            {".js"},
        ),
        ScriptPattern(
            "script_encoded_command",
            "high",
            "PowerShell encoded command flag",
            re.compile(r"(?:-|/)(?:e|en|enc|encodedcommand)\b", re.IGNORECASE),
            {".ps1"},
        ),
        ScriptPattern(
            "script_base64_decode",
            "medium",
            "PowerShell Base64 decoding routine",
            re.compile(r"\bFromBase64String\s*\(", re.IGNORECASE),
            {".ps1"},
        ),
        ScriptPattern(
            "script_base64_decode",
            "medium",
            "JavaScript Base64 decoding routine",
            re.compile(r"\b(?:atob|Buffer\s*\.\s*from)\s*\(", re.IGNORECASE),
            {".js"},
        ),
        ScriptPattern(
            "script_download",
            "medium",
            "Script downloads remote content",
            re.compile(r"\b(?:DownloadString|DownloadFile|fetch|XMLHttpRequest)\b", re.IGNORECASE),
            {".ps1", ".js"},
        ),
        ScriptPattern(
            "script_downloader_command",
            "medium",
            "Command-line downloader usage",
            re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE),
            {".ps1", ".js", ".bat", ".cmd", ".sh"},
        ),
        ScriptPattern(
            "script_windows_automation",
            "medium",
            "Windows Script Host or COM automation",
            re.compile(r"\b(?:WScript\.Shell|CreateObject)\b", re.IGNORECASE),
            {".ps1", ".js", ".vbs"},
        ),
    ]

    def supports(self, context: FileContext) -> bool:
        return context.extension in self.script_extensions or context.is_text_like

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        text = read_text_safely(context.path)
        base64_candidates = _extract_base64_candidates(text)

        result["metadata"]["line_count"] = len(text.splitlines())
        result["metadata"]["script_extension"] = context.extension
        result["metadata"]["base64_candidate_count"] = len(base64_candidates)
        result["iocs"] = extract_iocs_from_text(text)
        result["iocs"]["base64"] = base64_candidates

        _add_url_findings(result)
        _add_base64_findings(result, base64_candidates)
        _add_pattern_findings(result, context.extension, text)

        return result


def _add_url_findings(result: dict) -> None:
    urls = result["iocs"]["urls"]
    if urls:
        result["findings"].append(
            finding(
                "script_url",
                "low",
                "Script contains URL references",
                count=len(urls),
            )
        )


def _add_base64_findings(result: dict, candidates: list[dict]) -> None:
    if not candidates:
        return

    result["findings"].append(
        finding(
            "script_base64_blob",
            "medium",
            "Script contains Base64-looking encoded data",
            count=len(candidates),
        )
    )


def _add_pattern_findings(result: dict, extension: str, text: str) -> None:
    for pattern in ScriptAnalyzer.suspicious_patterns:
        if extension and extension not in pattern.languages:
            continue

        for match in pattern.regex.finditer(text):
            result["findings"].append(
                finding(
                    pattern.finding_type,
                    pattern.severity,
                    pattern.description,
                    pattern=match.group(0),
                    line=_line_number(text, match.start()),
                )
            )


def _extract_base64_candidates(text: str) -> list[dict]:
    candidates = []
    seen = set()

    for match in BASE64_RE.finditer(text):
        value = match.group(0)
        normalized = value + "=" * (-len(value) % 4)
        if normalized in seen:
            continue

        try:
            decoded = base64.b64decode(normalized, validate=True)
        except Exception:
            continue

        if len(decoded) < 8:
            continue

        seen.add(normalized)
        candidates.append(
            {
                "value": _truncate(value, 80),
                "length": len(value),
                "decoded_size": len(decoded),
                "line": _line_number(text, match.start()),
            }
        )

        if len(candidates) >= 25:
            break

    return candidates


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _truncate(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."
