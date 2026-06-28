from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from .archive.analyzer import ArchiveAnalyzer
from .core import Analyzer, FileContext
from .iocs.analyzer import IOCAnalyzer
from .iocs.extractor import merge_iocs
from .office.analyzer import OfficeAnalyzer
from .pe.analyzer import PEAnalyzer
from .scripts.analyzer import ScriptAnalyzer
from .yara.analyzer import YARAAnalyzer


ANALYZERS: List[Analyzer] = [
    PEAnalyzer(),
    ScriptAnalyzer(),
    OfficeAnalyzer(),
    ArchiveAnalyzer(),
    IOCAnalyzer(),
    YARAAnalyzer(),
]


def analyzer_names() -> List[str]:
    return [analyzer.name for analyzer in ANALYZERS]


def analyze_file(
    path: str,
    selected: str = "auto",
    archive_password: str | None = None,
    archive_max_depth: int = 2,
) -> dict:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"file does not exist: {path}")
    if not target.is_file():
        raise ValueError(f"path is not a file: {path}")

    context = FileContext(
        target,
        archive_password=archive_password,
        max_archive_depth=archive_max_depth,
    )
    analyzers = _select_analyzers(context, selected)
    results = [analyzer.analyze(context) for analyzer in analyzers]

    return {
        "schema_version": "malcore.analyzer.v1",
        "file": {
            "path": str(target),
            "name": context.name,
            "extension": context.extension,
            "size_bytes": context.size,
            "mime_type": context.mime_type,
            "sha256": context.sha256(),
        },
        "mode": selected,
        "analyzers": [analyzer.name for analyzer in analyzers],
        "iocs": merge_iocs([result.get("iocs", {}) for result in results]),
        "results": results,
    }


def _select_analyzers(context: FileContext, selected: str) -> Iterable[Analyzer]:
    if selected == "auto":
        supported = [analyzer for analyzer in ANALYZERS if analyzer.supports(context)]
        return supported or ANALYZERS

    if selected == "all":
        return ANALYZERS

    for analyzer in ANALYZERS:
        if analyzer.name == selected:
            return [analyzer]

    names = ", ".join(["auto", "all"] + analyzer_names())
    raise ValueError(f"unknown analyzer {selected!r}; expected one of: {names}")
