from __future__ import annotations

import re

from ..core import Analyzer, FileContext, base_result, finding, read_text_safely, unique, unsupported_result


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)


class ScriptAnalyzer(Analyzer):
    name = "scripts"
    category = "script"

    script_extensions = {".ps1", ".js", ".vbs", ".bat", ".cmd", ".py", ".sh"}

    suspicious_patterns = {
        "encodedcommand": "PowerShell encoded command usage",
        "invoke-expression": "PowerShell Invoke-Expression usage",
        "frombase64string": "Base64 decoding routine",
        "wscript.shell": "Windows Script Host shell automation",
        "createobject": "COM object creation",
        "schtasks": "Scheduled task creation or modification",
        "reg add": "Registry modification",
        "downloadstring": "Remote script download",
        "curl ": "Command-line downloader usage",
        "wget ": "Command-line downloader usage",
    }

    def supports(self, context: FileContext) -> bool:
        return context.extension in self.script_extensions or context.is_text_like

    def analyze(self, context: FileContext) -> dict:
        if not self.supports(context):
            return unsupported_result(self, context)

        result = base_result(self, context)
        text = read_text_safely(context.path)
        lowered = text.lower()

        result["metadata"]["line_count"] = len(text.splitlines())
        result["metadata"]["script_extension"] = context.extension
        result["iocs"] = {
            "urls": unique(URL_RE.findall(text)),
            "ips": unique(IP_RE.findall(text)),
            "domains": unique(DOMAIN_RE.findall(text)),
        }

        for pattern, description in self.suspicious_patterns.items():
            if pattern in lowered:
                result["findings"].append(finding("suspicious_script_pattern", "medium", description, pattern=pattern))

        return result
