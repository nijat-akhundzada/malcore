from __future__ import annotations

from ..core import Analyzer, FileContext, base_result, finding
from .extractor import MAX_IOC_SCAN_BYTES, extract_iocs_from_file, ioc_count


class IOCAnalyzer(Analyzer):
    name = "ioc"
    category = "indicator"

    def supports(self, context: FileContext) -> bool:
        return True

    def analyze(self, context: FileContext) -> dict:
        result = base_result(self, context)
        iocs = extract_iocs_from_file(context.path)

        result["iocs"] = iocs
        result["metadata"]["scan_limit_bytes"] = MAX_IOC_SCAN_BYTES
        result["metadata"]["truncated"] = context.size > MAX_IOC_SCAN_BYTES
        result["metadata"]["counts"] = {key: len(values) for key, values in iocs.items()}

        total = ioc_count(iocs)
        if total:
            result["findings"].append(
                finding(
                    "ioc_detected",
                    "low",
                    "File contains network indicators of compromise",
                    count=total,
                )
            )

        return result
