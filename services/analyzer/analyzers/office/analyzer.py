from __future__ import annotations

import zipfile

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result


OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")


class OfficeAnalyzer(Analyzer):
    name = "office"
    category = "office"

    office_extensions = {".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}

    def supports(self, context: FileContext) -> bool:
        return context.extension in self.office_extensions or context.sample.startswith(OLE_MAGIC)

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        metadata = result["metadata"]
        metadata["legacy_ole"] = context.sample.startswith(OLE_MAGIC)

        if context.extension in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
            self._analyze_ooxml(context, result)
        elif metadata["legacy_ole"]:
            result["findings"].append(
                finding("legacy_office_document", "low", "legacy OLE Office file needs oletools-based macro inspection")
            )

        return result

    def _analyze_ooxml(self, context: FileContext, result: dict) -> None:
        try:
            with zipfile.ZipFile(context.path) as archive:
                names = archive.namelist()
        except zipfile.BadZipFile:
            result["findings"].append(finding("invalid_ooxml", "medium", "Office extension is not a valid ZIP container"))
            return

        result["metadata"]["entry_count"] = len(names)
        result["metadata"]["has_vba_project"] = any(name.lower().endswith("vbaproject.bin") for name in names)
        result["metadata"]["external_relationships"] = [
            name for name in names if name.lower().endswith(".rels")
        ][:50]

        if result["metadata"]["has_vba_project"]:
            result["findings"].append(finding("office_macros", "high", "Office document contains a VBA project"))
