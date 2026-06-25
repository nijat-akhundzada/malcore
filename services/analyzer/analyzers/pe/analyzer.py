from __future__ import annotations

from typing import Any

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result

try:
    import pefile
except ImportError:  # pragma: no cover - exercised by environments without optional dependency
    pefile = None  # type: ignore[assignment]


class PEAnalyzer(Analyzer):
    name = "pe"
    category = "pe"

    def supports(self, context: FileContext) -> bool:
        return context.extension in {".exe", ".dll"} or context.sample.startswith(b"MZ")

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        if pefile is None:
            result["errors"].append("pefile is not installed; install services/analyzer/requirements.txt")
            return result

        try:
            pe = pefile.PE(str(context.path), fast_load=False)
        except Exception as exc:
            result["errors"].append(f"failed to parse PE file: {exc}")
            result["findings"].append(finding("invalid_pe", "medium", "pefile could not parse the file"))
            return result

        try:
            _populate_headers(pe, result["metadata"])
            result["metadata"]["imports"] = _extract_imports(pe)
            result["metadata"]["sections"] = _extract_sections(pe)
            _add_findings(result)
        finally:
            close = getattr(pe, "close", None)
            if callable(close):
                close()

        return result


def _populate_headers(pe: Any, metadata: dict) -> None:
    file_header = pe.FILE_HEADER
    optional_header = getattr(pe, "OPTIONAL_HEADER", None)

    metadata["machine"] = _lookup_constant(getattr(pefile, "MACHINE_TYPE", {}), file_header.Machine)
    metadata["number_of_sections"] = file_header.NumberOfSections
    metadata["timestamp"] = file_header.TimeDateStamp
    metadata["characteristics"] = hex(file_header.Characteristics)
    metadata["is_dll"] = bool(file_header.Characteristics & 0x2000)

    if optional_header is None:
        return

    metadata["entry_point"] = getattr(optional_header, "AddressOfEntryPoint", None)
    metadata["image_base"] = getattr(optional_header, "ImageBase", None)
    metadata["subsystem"] = _lookup_constant(
        getattr(pefile, "SUBSYSTEM_TYPE", {}),
        getattr(optional_header, "Subsystem", None),
    )


def _extract_imports(pe: Any) -> list[dict]:
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]],
        )
    except Exception:
        return []

    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        functions = []
        for imported in getattr(entry, "imports", []) or []:
            functions.append(
                {
                    "name": _decode(imported.name),
                    "ordinal": getattr(imported, "ordinal", None),
                    "address": getattr(imported, "address", None),
                }
            )

        imports.append(
            {
                "dll": _decode(getattr(entry, "dll", None)),
                "functions": functions,
            }
        )

    return imports


def _extract_sections(pe: Any) -> list[dict]:
    sections = []

    for section in getattr(pe, "sections", []) or []:
        entropy = float(section.get_entropy())
        sections.append(
            {
                "name": _decode(section.Name).rstrip("\x00"),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 4),
                "characteristics": hex(section.Characteristics),
            }
        )

    return sections


def _add_findings(result: dict) -> None:
    sections = result["metadata"].get("sections", [])
    imports = result["metadata"].get("imports", [])

    for section in sections:
        if section["entropy"] >= 7.2:
            result["findings"].append(
                finding(
                    "high_entropy_section",
                    "medium",
                    "PE section has high entropy and may be packed or encrypted",
                    section=section["name"],
                    entropy=section["entropy"],
                )
            )

    if not imports:
        result["findings"].append(finding("missing_imports", "low", "PE file has no parsed import table"))


def _decode(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _lookup_constant(mapping: dict, value: Any) -> str | None:
    if value is None:
        return None
    return mapping.get(value, hex(value) if isinstance(value, int) else str(value))
