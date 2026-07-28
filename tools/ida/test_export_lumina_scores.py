import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("export_lumina_scores.py")
SPEC = importlib.util.spec_from_file_location("export_lumina_scores", SCRIPT)
EXPORTER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(EXPORTER)


class FakeFunction:
    def __init__(self, address):
        self.start_ea = address


class FakeInfo:
    name = ""
    size = 0
    metadata = b""


class FakeLumina:
    func_info_t = FakeInfo

    @staticmethod
    def calc_func_metadata(info, function):
        if function.start_ea == 0x2000:
            return None
        info.name = "parsed_function"
        info.size = 42
        info.metadata = [0x03, 0x01, 0x41]
        return b"pattern"

    @staticmethod
    def score_metadata(info):
        return len(info.metadata) * 7


class FakeFunctions:
    @staticmethod
    def get_func(address):
        if address == 0x3000:
            return None
        return FakeFunction(address)


class FakeUtils:
    @staticmethod
    def Functions():
        return [0x1000, 0x2000, 0x3000]


class FakeKernel:
    @staticmethod
    def get_kernel_version():
        return "9.3-test"


class ExportLuminaScoresTests(unittest.TestCase):
    def test_metadata_bytes_accepts_bytes_and_iterables(self):
        self.assertEqual(EXPORTER.metadata_bytes(b"\x01\x02"), b"\x01\x02")
        self.assertEqual(EXPORTER.metadata_bytes([0, 255, 257]), b"\x00\xff\x01")

    def test_build_fixture_skips_unavailable_functions(self):
        fixture = EXPORTER.build_fixture(
            FakeLumina, FakeFunctions, FakeUtils, FakeKernel
        )
        self.assertEqual(fixture["format"], "lux-ida-lumina-score-fixture-v1")
        self.assertEqual(fixture["ida_version"], "9.3-test")
        self.assertEqual(
            fixture["functions"],
            [
                {
                    "address": "0x1000",
                    "name": "parsed_function",
                    "size": 42,
                    "metadata_hex": "030141",
                    "score": 21,
                }
            ],
        )

    def test_write_fixture_replaces_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "nested" / "scores.json"
            fixture = {"format": "test", "functions": []}
            EXPORTER.write_fixture(str(destination), fixture)
            self.assertEqual(json.loads(destination.read_text()), fixture)
            self.assertEqual(
                list(destination.parent.glob(".lux-lumina-scores-*")), []
            )

    def test_main_requires_one_output(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(EXPORTER.main([]), 2)


if __name__ == "__main__":
    unittest.main()
