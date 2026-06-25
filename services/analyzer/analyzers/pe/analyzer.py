from __future__ import annotations

import struct

from ..core import Analyzer, FileContext, base_result, finding, unsupported_result


class PEAnalyzer(Analyzer):
    name = "pe"
    category = "pe"

    def supports(self, context: FileContext) -> bool:
        return context.extension in {".exe", ".dll"} or context.sample.startswith(b"MZ")

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        metadata = result["metadata"]
        data = context.path.read_bytes()[:4096]

        metadata["mz_header"] = data.startswith(b"MZ")
        if not metadata["mz_header"]:
            result["findings"].append(finding("invalid_pe", "medium", "file does not start with MZ header"))
            return result

        if len(data) < 0x40:
            result["findings"].append(finding("truncated_pe", "medium", "file is too small to contain a PE header"))
            return result

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        metadata["pe_header_offset"] = pe_offset

        if pe_offset + 8 > len(data):
            result["findings"].append(finding("truncated_pe", "medium", "PE header offset points beyond sampled bytes"))
            return result

        metadata["pe_signature"] = data[pe_offset : pe_offset + 4].hex()
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            result["findings"].append(finding("invalid_pe_signature", "medium", "PE signature was not found"))
            return result

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        metadata["machine"] = hex(machine)
        metadata["number_of_sections"] = number_of_sections

        if number_of_sections == 0:
            result["findings"].append(finding("no_sections", "high", "PE file declares zero sections"))

        return result
