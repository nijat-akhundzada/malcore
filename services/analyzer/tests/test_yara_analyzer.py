import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from analyzers.core import FileContext
from analyzers.yara.analyzer import YARAAnalyzer


class FakeCompiledRules:
    def match(self, path, timeout):
        return [
            SimpleNamespace(
                rule="Unit_Test_Rule",
                namespace="default",
                tags=["unit"],
                meta={
                    "description": "Unit test YARA hit",
                    "severity": "critical",
                },
                strings=[
                    (0, "$marker", b"MALCORE_TEST_MARKER"),
                ],
            )
        ]


class FakeYara:
    def compile(self, source):
        if "Unit_Test_Rule" not in source:
            raise AssertionError("rule source was not loaded")
        return FakeCompiledRules()


class YARAAnalyzerTests(unittest.TestCase):
    def test_yara_matches_are_returned_as_findings_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules_dir = root / "rules"
            rules_dir.mkdir()
            (rules_dir / "unit.yar").write_text(
                """
rule Unit_Test_Rule : unit
{
    meta:
        description = "Unit test YARA hit"
        severity = "critical"
    strings:
        $marker = "MALCORE_TEST_MARKER"
    condition:
        $marker
}
""",
                encoding="utf-8",
            )

            sample = root / "sample.bin"
            sample.write_bytes(b"MALCORE_TEST_MARKER")

            with patch("analyzers.yara.analyzer.yara", FakeYara()):
                result = YARAAnalyzer(rules_dir=rules_dir).analyze(FileContext(sample))

        self.assertEqual(result["metadata"]["rule_count"], 1)
        self.assertEqual(result["metadata"]["matches"][0]["rule"], "Unit_Test_Rule")
        self.assertEqual(result["metadata"]["matches"][0]["severity"], "critical")
        self.assertEqual(result["findings"][0]["type"], "yara_match")
        self.assertEqual(result["findings"][0]["severity"], "critical")

    def test_missing_rules_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            sample.write_bytes(b"hello")

            with patch("analyzers.yara.analyzer.yara", FakeYara()):
                result = YARAAnalyzer(rules_dir=Path(tmp) / "missing").analyze(FileContext(sample))

        self.assertIn("no YARA rules found", result["errors"])
        self.assertEqual(result["metadata"]["matches"], [])


if __name__ == "__main__":
    unittest.main()
