import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzers.core import FileContext
from analyzers.archive.analyzer import ArchiveAnalyzer


class ArchiveAnalyzerTests(unittest.TestCase):
    def test_zip_entries_are_extracted_and_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.zip"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("safe/readme.txt", "hello")

            result = ArchiveAnalyzer().analyze(FileContext(sample))

        self.assertEqual(result["metadata"]["format"], "zip")
        self.assertEqual(result["metadata"]["entry_count"], 1)
        self.assertEqual(result["metadata"]["extracted_file_count"], 1)
        self.assertEqual(result["metadata"]["extracted_files"][0]["path"], "safe/readme.txt")
        self.assertEqual(result["findings"], [])

    def test_zip_path_traversal_is_flagged_and_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "traversal.zip"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("../escape.txt", "bad")

            result = ArchiveAnalyzer().analyze(FileContext(sample))

        self.assertTrue(any(item["type"] == "archive_path_traversal" for item in result["findings"]))
        self.assertEqual(result["metadata"]["extracted_file_count"], 0)
        self.assertEqual(result["metadata"]["skipped_entries"][0]["reason"], "unsafe path")

    def test_nested_archive_respects_recursion_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "nested.zip"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("inner.txt", "hello")

            outer = Path(tmp) / "outer.zip"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.write(nested, "nested.zip")

            result = ArchiveAnalyzer().analyze(
                FileContext(
                    outer,
                    archive_depth=0,
                    max_archive_depth=0,
                )
            )

        self.assertEqual(result["metadata"]["nested_archives"][0]["path"], "nested.zip")
        self.assertTrue(any(item["type"] == "archive_recursion_limit" for item in result["findings"]))

    def test_archive_password_is_recorded_as_supplied_without_exposing_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.zip"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("safe.txt", "hello")

            result = ArchiveAnalyzer().analyze(FileContext(sample, archive_password="secret"))

        self.assertTrue(result["metadata"]["password_supplied"])
        self.assertNotIn("secret", str(result))


if __name__ == "__main__":
    unittest.main()
