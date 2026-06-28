import tempfile
import unittest
from pathlib import Path

from analyzers.core import FileContext
from analyzers.iocs.analyzer import IOCAnalyzer
from analyzers.iocs.extractor import extract_iocs_from_text


class IOCAnalyzerTests(unittest.TestCase):
    def test_extracts_urls_ips_and_domains(self):
        text = "\n".join(
            [
                "download from https://updates.example.com/payload.bin",
                "callback http://evil.test/a.js",
                "connect to 8.8.8.8 and 2001:4860:4860::8888",
                "ignore invalid 999.999.999.999 and local powershell.exe",
            ]
        )

        iocs = extract_iocs_from_text(text)

        self.assertIn("https://updates.example.com/payload.bin", iocs["urls"])
        self.assertIn("http://evil.test/a.js", iocs["urls"])
        self.assertIn("8.8.8.8", iocs["ips"])
        self.assertIn("2001:4860:4860::8888", iocs["ips"])
        self.assertIn("updates.example.com", iocs["domains"])
        self.assertIn("evil.test", iocs["domains"])
        self.assertNotIn("999.999.999.999", iocs["ips"])
        self.assertNotIn("powershell.exe", iocs["domains"])

    def test_ioc_analyzer_returns_ioc_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.txt"
            sample.write_text("stage from https://c2.example.net/dropper", encoding="utf-8")

            result = IOCAnalyzer().analyze(FileContext(sample))

        self.assertEqual(result["iocs"]["urls"], ["https://c2.example.net/dropper"])
        self.assertEqual(result["metadata"]["counts"]["urls"], 1)
        self.assertTrue(any(item["type"] == "ioc_detected" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
