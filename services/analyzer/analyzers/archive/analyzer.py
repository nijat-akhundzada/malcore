from __future__ import annotations

import tarfile
import zipfile
from pathlib import PurePosixPath

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result


class ArchiveAnalyzer(Analyzer):
    name = "archive"
    category = "archive"

    archive_extensions = {".zip", ".jar", ".war", ".docx", ".xlsx", ".pptx", ".tar", ".tgz", ".gz", ".bz2"}

    def supports(self, context: FileContext) -> bool:
        return context.extension in self.archive_extensions or zipfile.is_zipfile(context.path) or tarfile.is_tarfile(context.path)

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)

        if zipfile.is_zipfile(context.path):
            self._analyze_zip(context, result)
        elif tarfile.is_tarfile(context.path):
            self._analyze_tar(context, result)
        else:
            result["findings"].append(finding("unsupported_archive_container", "low", "archive extension is not ZIP or TAR"))

        return result

    def _analyze_zip(self, context: FileContext, result: dict) -> None:
        with zipfile.ZipFile(context.path) as archive:
            infos = archive.infolist()

        result["metadata"]["format"] = "zip"
        result["metadata"]["entry_count"] = len(infos)
        result["metadata"]["total_uncompressed_size"] = sum(info.file_size for info in infos)
        result["metadata"]["encrypted_entries"] = sum(1 for info in infos if info.flag_bits & 0x1)

        suspicious_paths = [info.filename for info in infos if _is_suspicious_archive_path(info.filename)]
        if suspicious_paths:
            result["findings"].append(
                finding("archive_path_traversal", "high", "archive contains absolute or traversal paths", paths=suspicious_paths[:20])
            )

        nested_archives = [
            info.filename
            for info in infos
            if info.filename.lower().endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"))
        ]
        if nested_archives:
            result["findings"].append(finding("nested_archive", "low", "archive contains nested archives", paths=nested_archives[:20]))

    def _analyze_tar(self, context: FileContext, result: dict) -> None:
        with tarfile.open(context.path) as archive:
            members = archive.getmembers()

        result["metadata"]["format"] = "tar"
        result["metadata"]["entry_count"] = len(members)
        result["metadata"]["total_uncompressed_size"] = sum(member.size for member in members)

        suspicious_paths = [member.name for member in members if _is_suspicious_archive_path(member.name)]
        if suspicious_paths:
            result["findings"].append(
                finding("archive_path_traversal", "high", "archive contains absolute or traversal paths", paths=suspicious_paths[:20])
            )


def _is_suspicious_archive_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return normalized.startswith("/") or any(part == ".." for part in path.parts)
