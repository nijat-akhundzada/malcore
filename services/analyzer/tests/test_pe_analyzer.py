import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from analyzers.core import FileContext
from analyzers.pe.analyzer import PEAnalyzer


class FakeSection:
    Name = b".text\x00\x00\x00"
    VirtualAddress = 4096
    Misc_VirtualSize = 512
    SizeOfRawData = 1024
    Characteristics = 0x60000020

    def get_entropy(self):
        return 7.4


class FakePE:
    FILE_HEADER = SimpleNamespace(
        Machine=0x14C,
        NumberOfSections=1,
        TimeDateStamp=123456789,
        Characteristics=0x2102,
    )
    OPTIONAL_HEADER = SimpleNamespace(
        AddressOfEntryPoint=4096,
        ImageBase=4194304,
        Subsystem=3,
    )
    sections = [FakeSection()]
    DIRECTORY_ENTRY_IMPORT = [
        SimpleNamespace(
            dll=b"KERNEL32.dll",
            imports=[
                SimpleNamespace(name=b"CreateFileA", ordinal=None, address=4198400),
                SimpleNamespace(name=None, ordinal=12, address=4198404),
            ],
        )
    ]

    def __init__(self, path, fast_load=False):
        self.path = path
        self.fast_load = fast_load

    def parse_data_directories(self, directories):
        self.directories = directories

    def close(self):
        self.closed = True


class PEAnalyzerTests(unittest.TestCase):
    def test_pefile_metadata_is_returned_as_json_compatible_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(b"MZ" + b"\x00" * 128)
            context = FileContext(sample)

            fake_pefile = SimpleNamespace(
                PE=FakePE,
                DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_IMPORT": 1},
                MACHINE_TYPE={0x14C: "IMAGE_FILE_MACHINE_I386"},
                SUBSYSTEM_TYPE={3: "IMAGE_SUBSYSTEM_WINDOWS_CUI"},
            )

            with patch("analyzers.pe.analyzer.pefile", fake_pefile):
                result = PEAnalyzer().analyze(context)

        self.assertTrue(result["supported"])
        self.assertEqual(result["metadata"]["machine"], "IMAGE_FILE_MACHINE_I386")
        self.assertTrue(result["metadata"]["is_dll"])
        self.assertEqual(result["metadata"]["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(result["metadata"]["imports"][0]["functions"][0]["name"], "CreateFileA")
        self.assertEqual(result["metadata"]["sections"][0]["name"], ".text")
        self.assertEqual(result["metadata"]["sections"][0]["entropy"], 7.4)
        self.assertTrue(any(item["type"] == "high_entropy_section" for item in result["findings"]))


if __name__ == "__main__":
    unittest.main()
