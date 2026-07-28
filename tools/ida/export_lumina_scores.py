"""Export authoritative Lumina metadata scores from an open IDA database.

Run inside IDA 9.3 or newer:

    ida -A -S"/absolute/path/export_lumina_scores.py /tmp/ida-scores.json" sample.i64

Hex-Rays exposes score_metadata(), but does not publish its implementation.
The resulting JSON keeps the exact metadata bytes beside IDA's score so Lux
can compare its scorer against the real implementation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Any, Iterable


def metadata_bytes(metadata: Any) -> bytes:
    """Convert IDAPython's metadata_t/bytevec wrapper to immutable bytes."""
    try:
        return bytes(metadata)
    except (TypeError, ValueError):
        return bytes(int(value) & 0xFF for value in metadata)


def build_fixture(
    ida_lumina: Any,
    ida_funcs: Any,
    idautils: Any,
    ida_kernwin: Any,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for ea in idautils.Functions():
        function = ida_funcs.get_func(ea)
        if function is None:
            continue
        info = ida_lumina.func_info_t()
        pattern = ida_lumina.calc_func_metadata(info, function)
        if pattern is None:
            continue
        raw = metadata_bytes(info.metadata)
        records.append(
            {
                "address": f"0x{int(function.start_ea):X}",
                "name": str(info.name),
                "size": int(info.size),
                "metadata_hex": raw.hex(),
                "score": int(ida_lumina.score_metadata(info)),
            }
        )
    return {
        "format": "lux-ida-lumina-score-fixture-v1",
        "ida_version": str(ida_kernwin.get_kernel_version()),
        "functions": records,
    }


def write_fixture(path: str, fixture: dict[str, Any]) -> None:
    destination = os.path.abspath(path)
    directory = os.path.dirname(destination)
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".lux-lumina-scores-", suffix=".json", dir=directory, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(fixture, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(arguments: Iterable[str] | None = None) -> int:
    if arguments is None:
        try:
            import idc

            arguments = idc.ARGV[1:]
        except ImportError:
            arguments = sys.argv[1:]
    arguments = list(arguments)
    if len(arguments) != 1:
        print("usage: export_lumina_scores.py OUTPUT.json", file=sys.stderr)
        return 2

    import ida_funcs
    import ida_kernwin
    import ida_lumina
    import idautils

    fixture = build_fixture(ida_lumina, ida_funcs, idautils, ida_kernwin)
    write_fixture(arguments[0], fixture)
    print(f"exported {len(fixture['functions'])} Lumina score fixtures to {arguments[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
