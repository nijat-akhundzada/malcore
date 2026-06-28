import base64
import tempfile
import unittest
from pathlib import Path

from analyzers.core import FileContext
from analyzers.scripts.analyzer import ScriptAnalyzer


class ScriptAnalyzerTests(unittest.TestCase):
    def test_powershell_detects_urls_base64_and_dynamic_execution(self):
        encoded = base64.b64encode("Write-Host hello".encode("utf-16le")).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.ps1"
            sample.write_text(
                "\n".join(
                    [
                        "$url = 'https://example.com/payload.ps1'",
                        f"powershell.exe -EncodedCommand {encoded}",
                        f"Invoke-Expression ([Convert]::FromBase64String('{encoded}'))",
                    ]
                ),
                encoding="utf-8",
            )

            result = ScriptAnalyzer().analyze(FileContext(sample))

        finding_types = {item["type"] for item in result["findings"]}
        self.assertIn("https://example.com/payload.ps1", result["iocs"]["urls"])
        self.assertGreaterEqual(result["metadata"]["base64_candidate_count"], 1)
        self.assertIn("script_url", finding_types)
        self.assertIn("script_base64_blob", finding_types)
        self.assertIn("script_dynamic_execution", finding_types)
        self.assertIn("script_encoded_command", finding_types)
        self.assertIn("script_base64_decode", finding_types)

    def test_javascript_detects_urls_base64_eval_and_exec(self):
        encoded = base64.b64encode(b"console.log('hello from encoded script');").decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.js"
            sample.write_text(
                "\n".join(
                    [
                        "const url = 'http://example.test/payload.js';",
                        "const child_process = require('child_process');",
                        f"eval(atob('{encoded}'));",
                        "child_process.exec('whoami');",
                    ]
                ),
                encoding="utf-8",
            )

            result = ScriptAnalyzer().analyze(FileContext(sample))

        finding_types = {item["type"] for item in result["findings"]}
        self.assertIn("http://example.test/payload.js", result["iocs"]["urls"])
        self.assertGreaterEqual(result["metadata"]["base64_candidate_count"], 1)
        self.assertIn("script_url", finding_types)
        self.assertIn("script_base64_blob", finding_types)
        self.assertIn("script_dynamic_execution", finding_types)
        self.assertIn("script_process_execution", finding_types)
        self.assertIn("script_base64_decode", finding_types)


if __name__ == "__main__":
    unittest.main()
