from __future__ import annotations

import hashlib
import mimetypes
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


JSONDict = Dict[str, Any]


class Analyzer(ABC):
    name: str
    category: str

    @abstractmethod
    def supports(self, context: "FileContext") -> bool:
        """Return true when this analyzer can inspect the file."""

    @abstractmethod
    def analyze(self, context: "FileContext") -> JSONDict:
        """Return a JSON-serializable analysis result."""


class FileContext:
    def __init__(self, path: Path, sample_size: int = 4096) -> None:
        self.path = path
        self.name = path.name
        self.extension = path.suffix.lower()
        self.size = path.stat().st_size
        self.sample = path.read_bytes()[:sample_size]
        self.mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    @property
    def is_text_like(self) -> bool:
        if b"\x00" in self.sample:
            return False

        if not self.sample:
            return True

        printable = sum(1 for byte in self.sample if byte in b"\n\r\t" or 32 <= byte <= 126)
        return printable / len(self.sample) > 0.85

    def sha256(self) -> str:
        digest = hashlib.sha256()
        with self.path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def base_result(analyzer: Analyzer, context: FileContext, supported: bool = True) -> JSONDict:
    return {
        "analyzer": analyzer.name,
        "category": analyzer.category,
        "supported": supported,
        "file": {
            "name": context.name,
            "extension": context.extension,
            "size_bytes": context.size,
            "mime_type": context.mime_type,
        },
        "metadata": {},
        "findings": [],
        "iocs": [],
        "errors": [],
    }


def unsupported_result(analyzer: Analyzer, context: FileContext) -> JSONDict:
    result = base_result(analyzer, context, supported=False)
    result["errors"].append("file type is not supported by this analyzer")
    return result


def finding(kind: str, severity: str, description: str, **extra: Any) -> JSONDict:
    item: JSONDict = {
        "type": kind,
        "severity": severity,
        "description": description,
    }
    item.update(extra)
    return item


def read_text_safely(path: Path, max_bytes: int = 1024 * 1024) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def unique(items: List[str], limit: int = 100) -> List[str]:
    seen = set()
    values: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        values.append(item)
        if len(values) >= limit:
            break
    return values
