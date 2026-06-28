from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result


RAR_MAGIC = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")
SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"

MAX_ARCHIVE_ENTRIES = 1000
MAX_EXTRACTED_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_FILE_BYTES = 25 * 1024 * 1024
MAX_RECORDED_FILES = 100
MAX_NESTED_RESULTS = 20
SEVEN_ZIP_TIMEOUT_SECONDS = 30


class ArchiveAnalyzer(Analyzer):
    name = "archive"
    category = "archive"

    archive_extensions = {".zip", ".rar", ".7z", ".jar", ".war", ".tar", ".tgz", ".gz", ".bz2"}

    def supports(self, context: FileContext) -> bool:
        return (
            context.extension in self.archive_extensions
            or zipfile.is_zipfile(context.path)
            or tarfile.is_tarfile(context.path)
            or _has_archive_magic(context.sample)
        )

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        _initialize_metadata(context, result)

        try:
            if zipfile.is_zipfile(context.path):
                _analyze_zip(context, result)
            elif tarfile.is_tarfile(context.path):
                _analyze_tar(context, result)
            elif _is_seven_zip_or_rar(context):
                _analyze_with_7z(context, result)
            else:
                result["findings"].append(
                    finding("unsupported_archive_container", "low", "archive format is not ZIP, RAR, or 7z")
                )
        except Exception as exc:
            result["errors"].append(f"archive analysis failed: {exc}")

        return result


def _initialize_metadata(context: FileContext, result: dict) -> None:
    result["metadata"].update(
        {
            "format": None,
            "recursion_depth": context.archive_depth,
            "max_recursion_depth": context.max_archive_depth,
            "password_supplied": bool(context.archive_password),
            "entry_count": 0,
            "total_uncompressed_size": 0,
            "encrypted_entries": 0,
            "extracted_file_count": 0,
            "extracted_files": [],
            "nested_archives": [],
            "nested_results": [],
            "skipped_entries": [],
        }
    )


def _analyze_zip(context: FileContext, result: dict) -> None:
    with zipfile.ZipFile(context.path) as archive:
        infos = archive.infolist()

        metadata = result["metadata"]
        metadata["format"] = "zip"
        metadata["entry_count"] = len(infos)
        metadata["total_uncompressed_size"] = sum(info.file_size for info in infos)
        metadata["encrypted_entries"] = sum(1 for info in infos if info.flag_bits & 0x1)

        suspicious_paths = [info.filename for info in infos if _is_suspicious_archive_path(info.filename)]
        _add_common_findings(result, suspicious_paths)

        if metadata["encrypted_entries"] and not context.archive_password:
            result["findings"].append(
                finding(
                    "archive_password_required",
                    "medium",
                    "Archive contains encrypted entries and no password was supplied",
                )
            )

        with tempfile.TemporaryDirectory(prefix="malcore-archive-") as tmp:
            _extract_zip_entries(context, result, archive, infos, Path(tmp))


def _extract_zip_entries(
    context: FileContext,
    result: dict,
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    extract_root: Path,
) -> None:
    password = context.archive_password.encode("utf-8") if context.archive_password else None
    extracted_bytes = 0

    for info in infos:
        if info.is_dir():
            continue

        if _is_suspicious_archive_path(info.filename):
            _record_skipped(result, info.filename, "unsafe path")
            continue

        if _limit_reached(result, info.filename, info.file_size, extracted_bytes):
            continue

        target_path = _safe_extract_path(extract_root, info.filename)
        if target_path is None:
            _record_skipped(result, info.filename, "unsafe path")
            continue

        target_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with archive.open(info, pwd=password) as source, target_path.open("wb") as target:
                copied = _copy_limited(source, target, info.file_size, MAX_EXTRACTED_FILE_BYTES)
        except RuntimeError as exc:
            _add_password_failure(result, info.filename, exc)
            continue
        except ValueError:
            target_path.unlink(missing_ok=True)
            _record_skipped(result, info.filename, "extraction limit exceeded")
            _add_limit_finding(result, "archive extraction limit exceeded")
            continue

        target_path.chmod(0o600)
        extracted_bytes += copied
        _record_extracted_file(result, info.filename, copied)

        if _is_nested_archive_name(info.filename):
            _analyze_nested_archive(context, result, target_path, info.filename)


def _analyze_tar(context: FileContext, result: dict) -> None:
    with tarfile.open(context.path) as archive:
        members = archive.getmembers()

        metadata = result["metadata"]
        metadata["format"] = "tar"
        metadata["entry_count"] = len(members)
        metadata["total_uncompressed_size"] = sum(member.size for member in members if member.isfile())

        suspicious_paths = [member.name for member in members if _is_suspicious_archive_path(member.name)]
        _add_common_findings(result, suspicious_paths)

        with tempfile.TemporaryDirectory(prefix="malcore-archive-") as tmp:
            _extract_tar_members(context, result, archive, members, Path(tmp))


def _extract_tar_members(
    context: FileContext,
    result: dict,
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    extract_root: Path,
) -> None:
    extracted_bytes = 0

    for member in members:
        if not member.isfile():
            continue

        if _is_suspicious_archive_path(member.name):
            _record_skipped(result, member.name, "unsafe path")
            continue

        if _limit_reached(result, member.name, member.size, extracted_bytes):
            continue

        target_path = _safe_extract_path(extract_root, member.name)
        if target_path is None:
            _record_skipped(result, member.name, "unsafe path")
            continue

        source = archive.extractfile(member)
        if source is None:
            _record_skipped(result, member.name, "unreadable entry")
            continue

        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with source, target_path.open("wb") as target:
                copied = _copy_limited(source, target, member.size, MAX_EXTRACTED_FILE_BYTES)
        except ValueError:
            target_path.unlink(missing_ok=True)
            _record_skipped(result, member.name, "extraction limit exceeded")
            _add_limit_finding(result, "archive extraction limit exceeded")
            continue

        target_path.chmod(0o600)
        extracted_bytes += copied
        _record_extracted_file(result, member.name, copied)

        if _is_nested_archive_name(member.name):
            _analyze_nested_archive(context, result, target_path, member.name)


def _analyze_with_7z(context: FileContext, result: dict) -> None:
    seven_zip = shutil.which("7z")
    if not seven_zip:
        result["errors"].append("7z is not installed; RAR and 7z archives cannot be extracted")
        result["findings"].append(
            finding("archive_tool_missing", "low", "7z is required to inspect RAR and 7z archives")
        )
        return

    list_result = _run_7z(context, ["l", "-slt"], seven_zip)
    if list_result.returncode != 0:
        _add_7z_failure(result, list_result)
        return

    entries = _parse_7z_listing(list_result.stdout, context.path)
    metadata = result["metadata"]
    metadata["format"] = context.extension.lstrip(".") or "7z"
    metadata["entry_count"] = len(entries)
    metadata["total_uncompressed_size"] = sum(entry["size"] for entry in entries)

    suspicious_paths = [entry["path"] for entry in entries if _is_suspicious_archive_path(entry["path"])]
    _add_common_findings(result, suspicious_paths)
    if suspicious_paths:
        for item in suspicious_paths:
            _record_skipped(result, item, "unsafe path")
        return

    if _exceeds_collection_limits(result, entries):
        return

    with tempfile.TemporaryDirectory(prefix="malcore-archive-") as tmp:
        extract_root = Path(tmp)
        extract_result = _run_7z(context, ["x", "-y", f"-o{extract_root}"], seven_zip)
        if extract_result.returncode != 0:
            _add_7z_failure(result, extract_result)
            return

        for path in extract_root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(extract_root).as_posix()
            size = path.stat().st_size
            _record_extracted_file(result, relative, size)
            if _is_nested_archive_name(relative):
                _analyze_nested_archive(context, result, path, relative)


def _run_7z(context: FileContext, args: list[str], seven_zip: str) -> subprocess.CompletedProcess[str]:
    command = [seven_zip, *args, "-bd"]
    if context.archive_password:
        command.append(f"-p{context.archive_password}")
    command.append(str(context.path))

    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=SEVEN_ZIP_TIMEOUT_SECONDS,
    )


def _parse_7z_listing(output: str, archive_path: Path) -> list[dict]:
    entries = []
    current: dict[str, str] = {}
    archive_name = archive_path.name

    for line in output.splitlines() + [""]:
        if not line.strip():
            if current:
                item = _entry_from_7z_record(current, archive_name)
                if item:
                    entries.append(item)
                current = {}
            continue

        if " = " not in line:
            continue

        key, value = line.split(" = ", 1)
        current[key] = value

    return entries


def _entry_from_7z_record(record: dict[str, str], archive_name: str) -> dict | None:
    name = record.get("Path", "")
    if not name or name == archive_name:
        return None

    folder = record.get("Folder", "-") == "+"
    if folder:
        return None

    try:
        size = int(record.get("Size", "0") or "0")
    except ValueError:
        size = 0

    return {"path": name, "size": size}


def _add_common_findings(result: dict, suspicious_paths: list[str]) -> None:
    if suspicious_paths:
        result["findings"].append(
            finding(
                "archive_path_traversal",
                "high",
                "archive contains absolute or traversal paths",
                paths=suspicious_paths[:20],
            )
        )


def _limit_reached(result: dict, name: str, size: int, extracted_bytes: int) -> bool:
    if result["metadata"]["extracted_file_count"] >= MAX_ARCHIVE_ENTRIES:
        _record_skipped(result, name, "entry count limit exceeded")
        _add_limit_finding(result, "archive entry count limit exceeded")
        return True

    if size > MAX_EXTRACTED_FILE_BYTES:
        _record_skipped(result, name, "file size limit exceeded")
        _add_limit_finding(result, "archive file size limit exceeded")
        return True

    if extracted_bytes + size > MAX_EXTRACTED_BYTES:
        _record_skipped(result, name, "total extracted size limit exceeded")
        _add_limit_finding(result, "archive total extracted size limit exceeded")
        return True

    return False


def _exceeds_collection_limits(result: dict, entries: list[dict]) -> bool:
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        _add_limit_finding(result, "archive entry count limit exceeded")
        return True

    if any(entry["size"] > MAX_EXTRACTED_FILE_BYTES for entry in entries):
        _add_limit_finding(result, "archive file size limit exceeded")
        return True

    if sum(entry["size"] for entry in entries) > MAX_EXTRACTED_BYTES:
        _add_limit_finding(result, "archive total extracted size limit exceeded")
        return True

    return False


def _add_limit_finding(result: dict, description: str) -> None:
    if any(item["type"] == "archive_limit_exceeded" for item in result["findings"]):
        return

    result["findings"].append(finding("archive_limit_exceeded", "medium", description))


def _add_password_failure(result: dict, name: str, exc: Exception) -> None:
    if "password required" in str(exc).lower() or "encrypted" in str(exc).lower():
        result["findings"].append(
            finding(
                "archive_password_required",
                "medium",
                "Archive entry is encrypted and requires a password",
                path=name,
            )
        )
        return

    result["findings"].append(
        finding(
            "archive_password_failed",
            "medium",
            "Archive password was rejected or the entry could not be decrypted",
            path=name,
        )
    )


def _add_7z_failure(result: dict, completed: subprocess.CompletedProcess[str]) -> None:
    message = (completed.stderr or completed.stdout or "7z failed").strip()
    lowered = message.lower()
    if "password" in lowered or "encrypted" in lowered:
        result["findings"].append(
            finding(
                "archive_password_required",
                "medium",
                "Archive requires a valid password",
            )
        )
    else:
        result["errors"].append(f"7z failed: {message}")


def _record_extracted_file(result: dict, name: str, size: int) -> None:
    metadata = result["metadata"]
    metadata["extracted_file_count"] += 1
    if len(metadata["extracted_files"]) >= MAX_RECORDED_FILES:
        return

    metadata["extracted_files"].append(
        {
            "path": name,
            "size": size,
            "nested_archive": _is_nested_archive_name(name),
        }
    )


def _record_skipped(result: dict, name: str, reason: str) -> None:
    skipped = result["metadata"]["skipped_entries"]
    if len(skipped) >= MAX_RECORDED_FILES:
        return

    skipped.append({"path": name, "reason": reason})


def _analyze_nested_archive(context: FileContext, result: dict, nested_path: Path, display_name: str) -> None:
    metadata = result["metadata"]
    metadata["nested_archives"].append(
        {
            "path": display_name,
            "depth": context.archive_depth + 1,
        }
    )

    if context.archive_depth >= context.max_archive_depth:
        result["findings"].append(
            finding(
                "archive_recursion_limit",
                "medium",
                "nested archive recursion limit reached",
                path=display_name,
                max_depth=context.max_archive_depth,
            )
        )
        return

    if len(metadata["nested_results"]) >= MAX_NESTED_RESULTS:
        _add_limit_finding(result, "nested archive result limit exceeded")
        return

    nested_context = FileContext(
        nested_path,
        archive_password=context.archive_password,
        archive_depth=context.archive_depth + 1,
        max_archive_depth=context.max_archive_depth,
    )
    nested_result = ArchiveAnalyzer().analyze(nested_context)
    metadata["nested_results"].append(
        {
            "path": display_name,
            "findings": nested_result["findings"],
            "metadata": {
                "format": nested_result["metadata"].get("format"),
                "entry_count": nested_result["metadata"].get("entry_count"),
                "extracted_file_count": nested_result["metadata"].get("extracted_file_count"),
                "encrypted_entries": nested_result["metadata"].get("encrypted_entries"),
            },
        }
    )


def _copy_limited(source, target, expected_size: int, limit: int) -> int:
    copied = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break

        copied += len(chunk)
        if copied > limit or copied > expected_size > limit:
            raise ValueError("archive entry exceeds extraction limit")

        target.write(chunk)

    return copied


def _safe_extract_path(root: Path, name: str) -> Path | None:
    if _is_suspicious_archive_path(name):
        return None

    target = (root / name.replace("\\", "/")).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None

    return target


def _is_suspicious_archive_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return normalized.startswith("/") or any(part == ".." for part in path.parts)


def _is_nested_archive_name(name: str) -> bool:
    return name.lower().endswith((".zip", ".rar", ".7z", ".tar", ".tgz", ".gz", ".bz2"))


def _has_archive_magic(sample: bytes) -> bool:
    return sample.startswith(SEVEN_ZIP_MAGIC) or any(sample.startswith(magic) for magic in RAR_MAGIC)


def _is_seven_zip_or_rar(context: FileContext) -> bool:
    return context.extension in {".7z", ".rar"} or _has_archive_magic(context.sample)
