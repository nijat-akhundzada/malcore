import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from analyzers.core import FileContext
from analyzers.office.analyzer import OLE_MAGIC, OfficeAnalyzer


class FakeVBAParser:
    closed = False

    def __init__(self, path):
        self.path = path

    def detect_vba_macros(self):
        return True

    def extract_macros(self):
        return [
            (
                "VBA/Project",
                "Macros",
                "Module1.bas",
                "Sub AutoOpen()\nShell \"calc.exe\"\nEnd Sub",
            )
        ]

    def analyze_macros(self):
        return [
            ("AutoExec", "AutoOpen", "Runs when the document is opened"),
            ("Suspicious", "Shell", "May run an executable file"),
        ]

    def close(self):
        self.closed = True


class OfficeAnalyzerTests(unittest.TestCase):
    def test_ooxml_vba_project_flags_macro_presence(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.docx"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("[Content_Types].xml", "<Types />")
                archive.writestr("word/vbaProject.bin", b"macro bytes")

            with patch("analyzers.office.analyzer.olevba", None):
                result = OfficeAnalyzer().analyze(FileContext(sample))

        self.assertTrue(result["metadata"]["has_macros"])
        self.assertTrue(result["metadata"]["has_vba_project"])
        self.assertTrue(any(item["type"] == "office_macros" for item in result["findings"]))

    def test_oletools_macro_metadata_and_suspicious_keywords_are_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.xls"
            sample.write_bytes(OLE_MAGIC + b"\x00" * 128)

            fake_olevba = SimpleNamespace(VBA_Parser=FakeVBAParser)
            with patch("analyzers.office.analyzer.olevba", fake_olevba):
                result = OfficeAnalyzer().analyze(FileContext(sample))

        finding_types = {item["type"] for item in result["findings"]}
        self.assertTrue(result["metadata"]["has_macros"])
        self.assertEqual(result["metadata"]["macro_count"], 1)
        self.assertEqual(result["metadata"]["macro_modules"][0]["vba_filename"], "Module1.bas")
        self.assertEqual(result["metadata"]["suspicious_keywords"][0]["keyword"], "AutoOpen")
        self.assertIn("office_macros", finding_types)
        self.assertIn("office_suspicious_keyword", finding_types)


if __name__ == "__main__":
    unittest.main()
