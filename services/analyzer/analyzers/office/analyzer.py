from __future__ import annotations

import zipfile
from typing import Any

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result

try:
    from oletools import olevba
except ImportError:  # pragma: no cover - exercised by environments without optional dependency
    olevba = None  # type: ignore[assignment]


OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
LEGACY_EXTENSIONS = {".doc", ".xls", ".ppt"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
OFFICE_EXTENSIONS = LEGACY_EXTENSIONS | OOXML_EXTENSIONS


class OfficeAnalyzer(Analyzer):
    name = "office"
    category = "office"

    office_extensions = OFFICE_EXTENSIONS

    def supports(self, context: FileContext) -> bool:
        return context.extension in self.office_extensions or context.sample.startswith(OLE_MAGIC)

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        metadata = result["metadata"]
        metadata["legacy_ole"] = context.sample.startswith(OLE_MAGIC)
        metadata["ooxml"] = context.extension in OOXML_EXTENSIONS
        metadata["macro_enabled_extension"] = context.extension in MACRO_EXTENSIONS
        metadata["has_macros"] = False
        metadata["macro_count"] = 0
        metadata["macro_modules"] = []
        metadata["suspicious_keywords"] = []

        if context.extension in OOXML_EXTENSIONS:
            _analyze_ooxml_container(context, result)

        if olevba is None:
            result["errors"].append("oletools is not installed; install services/analyzer/requirements.txt")
            if metadata["legacy_ole"]:
                result["findings"].append(
                    finding(
                        "legacy_office_document",
                        "low",
                        "Legacy OLE Office file needs oletools macro inspection",
                    )
                )
            return result

        _analyze_with_oletools(context, result)
        return result


def _analyze_ooxml_container(context: FileContext, result: dict) -> None:
    try:
        with zipfile.ZipFile(context.path) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        result["findings"].append(finding("invalid_ooxml", "medium", "Office extension is not a valid ZIP container"))
        return

    metadata = result["metadata"]
    lower_names = [name.lower() for name in names]
    has_vba_project = any(name.endswith("vbaproject.bin") for name in lower_names)

    metadata["entry_count"] = len(names)
    metadata["has_vba_project"] = has_vba_project
    metadata["external_relationships"] = [
        name for name in names if name.lower().endswith(".rels")
    ][:50]

    if has_vba_project:
        _flag_macro_presence(result, "Office OOXML document contains a VBA project")


def _analyze_with_oletools(context: FileContext, result: dict) -> None:
    try:
        parser = olevba.VBA_Parser(str(context.path))
    except Exception as exc:
        result["errors"].append(f"oletools failed to open Office file: {exc}")
        return

    try:
        has_macros = bool(parser.detect_vba_macros())
        result["metadata"]["has_macros"] = result["metadata"]["has_macros"] or has_macros

        if has_macros:
            _flag_macro_presence(result, "Office document contains VBA macros")
            _extract_macro_metadata(parser, result)
            _extract_suspicious_keywords(parser, result)
    except Exception as exc:
        result["errors"].append(f"oletools macro analysis failed: {exc}")
    finally:
        close = getattr(parser, "close", None)
        if callable(close):
            close()


def _extract_macro_metadata(parser: Any, result: dict) -> None:
    modules = []

    try:
        macros = list(parser.extract_macros())
    except Exception as exc:
        result["errors"].append(f"oletools macro extraction failed: {exc}")
        return

    for macro in macros:
        filename, stream_path, vba_filename, code = _normalize_macro_tuple(macro)
        modules.append(
            {
                "filename": filename,
                "stream_path": stream_path,
                "vba_filename": vba_filename,
                "code_size": len(code),
            }
        )

    result["metadata"]["macro_count"] = len(modules)
    result["metadata"]["macro_modules"] = modules[:50]


def _extract_suspicious_keywords(parser: Any, result: dict) -> None:
    try:
        analysis_items = list(parser.analyze_macros())
    except Exception as exc:
        result["errors"].append(f"oletools suspicious keyword analysis failed: {exc}")
        return

    for item in analysis_items:
        item_type, keyword, description = _normalize_analysis_item(item)
        if not keyword:
            continue

        result["metadata"]["suspicious_keywords"].append(
            {
                "type": item_type,
                "keyword": keyword,
                "description": description,
            }
        )

        if item_type.lower() in {"autoexec", "suspicious"}:
            result["findings"].append(
                finding(
                    "office_suspicious_keyword",
                    _keyword_severity(item_type),
                    description or "Suspicious Office macro keyword",
                    keyword=keyword,
                    keyword_type=item_type,
                )
            )


def _flag_macro_presence(result: dict, description: str) -> None:
    metadata = result["metadata"]
    metadata["has_macros"] = True

    if any(item["type"] == "office_macros" for item in result["findings"]):
        return

    result["findings"].append(finding("office_macros", "high", description))


def _normalize_macro_tuple(macro: Any) -> tuple[str | None, str | None, str | None, str]:
    values = list(macro) if isinstance(macro, tuple) else [None, None, None, ""]
    values += [None] * (4 - len(values))
    filename, stream_path, vba_filename, code = values[:4]
    return _to_str(filename), _to_str(stream_path), _to_str(vba_filename), _to_str(code) or ""


def _normalize_analysis_item(item: Any) -> tuple[str, str, str]:
    values = list(item) if isinstance(item, tuple) else ["", "", ""]
    values += [""] * (3 - len(values))
    item_type, keyword, description = values[:3]
    return _to_str(item_type) or "", _to_str(keyword) or "", _to_str(description) or ""


def _keyword_severity(item_type: str) -> str:
    if item_type.lower() == "autoexec":
        return "high"
    return "medium"


def _to_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
