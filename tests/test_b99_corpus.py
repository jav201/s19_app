"""Batch-99 HLR-152: synthetic corpus with an independent oracle.

TC-B99-01 (LLR-152.1) — the generator is deterministic.
TC-B99-02 (LLR-152.2) — every coverage class has at least one corpus file.
TC-B99-03 (LLR-152.3) — the independent reader imports nothing from
``s19_app`` and reproduces every manifest file's bytes exactly.
TC-B99-03b (LLR-152.3 hardening, review finding F4) — the HEX files' address
extents are pinned LITERALLY, written by hand from the Intel HEX spec, so
the manifest check cannot share a common-mode address-arithmetic bug with
the reader it verifies.
AT-B99-01 (US-141) — ``generate.py --check`` exits 0 on the committed corpus
and exits non-zero, naming the file, when one committed byte is tampered with.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from tests.support.independent_reader import read_hex, read_s19

ROOT = Path(__file__).resolve().parents[1]
GENERATE = ROOT / "tests" / "fixtures" / "synth" / "generate.py"
CORPUS = ROOT / "tests" / "fixtures" / "synth"
READER = ROOT / "tests" / "support" / "independent_reader.py"

#: Every coverage class LLR-152.2 requires, checked against the manifest.
REQUIRED_CLASSES = {
    "s19.s1",
    "s19.s2",
    "s19.s3",
    "s19.s0",
    "s19.s5",
    "s19.term.s7",
    "s19.term.s8",
    "s19.term.s9",
    "s19.s0_only",
    "hex.t00",
    "hex.t01",
    "hex.t02",
    "hex.t04",
    "hex.t05",
    "hex.64k_boundary",
    "hex.wrap",
    "mac.pair",
    "a2l.pair",
    "defect.s19_no_terminator",
    "defect.s19_wrong_s5",
    "defect.s19_after_terminator",
    "defect.hex_no_eof",
    "defect.hex_after_eof",
    "defect.s19_overlap_diff",
}


def _run_generator(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GENERATE), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(ROOT),
    )


def _load_manifest() -> dict:
    return json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))


def _dir_bytes(directory: Path) -> dict:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir()) if p.is_file()}


def _expand_runs(runs: dict) -> dict:
    data = {}
    for key, hex_bytes in runs.items():
        addr = int(key, 16)
        for i, b in enumerate(bytes.fromhex(hex_bytes)):
            data[addr + i] = b
    return data


def test_tc_b99_01_deterministic(tmp_path):
    """Two ``--out`` runs write byte-identical corpora (LLR-152.1)."""
    d1 = tmp_path / "run1"
    d2 = tmp_path / "run2"
    for out in (d1, d2):
        result = _run_generator("--out", str(out))
        assert result.returncode == 0, result.stderr
    b1 = _dir_bytes(d1)
    b2 = _dir_bytes(d2)
    assert len(b1) >= 15
    assert b1.keys() == b2.keys()
    differing = sorted(name for name in b1 if b1[name] != b2[name])
    assert differing == []


def test_tc_b99_02_coverage_classes():
    """Every LLR-152.2 coverage class names at least one manifest file."""
    manifest = _load_manifest()
    present = set()
    for entry in manifest["files"]:
        present.update(entry["class"])
    missing = sorted(REQUIRED_CLASSES - present)
    assert missing == []
    defects = [e for e in manifest["files"] if e["verdict"].startswith("defect:")]
    assert len(defects) == 6


def test_tc_b99_03_reader_independence_and_exact():
    """The reader imports nothing from s19_app and matches every manifest byte."""
    tree = ast.parse(READER.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert "s19_app" not in roots

    manifest = _load_manifest()
    checked = 0
    for entry in manifest["files"]:
        path = CORPUS / entry["name"]
        if entry["format"] == "s19":
            image = read_s19(path)
        elif entry["format"] == "hex":
            image = read_hex(path)
        else:
            continue
        checked += 1
        expected_header = (
            bytes.fromhex(entry["header"]) if entry["header"] is not None else None
        )
        expected_term = tuple(entry["terminator"]) if entry["terminator"] is not None else None
        assert image.data == _expand_runs(entry["data"]), entry["name"]
        assert image.header == expected_header, entry["name"]
        assert image.terminator == expected_term, entry["name"]
        assert image.s5_count == entry["s5_count"], entry["name"]
        assert image.eof_seen == entry["eof_seen"], entry["name"]
        assert image.records_after_end == entry["records_after_end"], entry["name"]
    assert checked == 14


#: Literal HEX address extents, written by hand from the Intel HEX spec:
#: type 02 sets the segment base (payload << 4) and the 16-bit offset wraps
#: mod 64 KiB; type 04 sets the linear base (payload << 16); a type 01 EOF
#: stops parsing. Deliberately NOT computed by ``generate.py``, so this pin
#: cannot share a common-mode address-arithmetic bug with the manifest
#: check it cross-verifies (review finding F4). Runs are (start, end_excl).
LITERAL_HEX_EXTENTS = {
    # upper=1: 0xFF00..0xFFFF lands at 0x1FF00..0x1FFFF (256 contiguous
    # bytes), then the 0x0000 record lands at 0x10000..0x1000F.
    "synth_hex_basic.hex": [(0x10000, 0x10010), (0x1FF00, 0x20000)],
    # seg = 0x1000 << 4 = 0x10000; the record at 0xFFF0 crosses the 64 KiB
    # wrap: 0xFFF0..0xFFFF -> 0x1FFF0..0x1FFFF, 0x0000..0x000F -> 0x10000..0x1000F.
    "synth_hex_seg.hex": [(0x10000, 0x10010), (0x1FFF0, 0x20000)],
    "synth_hex_no_eof.hex": [(0x100, 0x110)],
    # the record after the EOF never enters the image.
    "synth_hex_after_eof.hex": [(0x200, 0x208)],
}


def _extents(image) -> list:
    """Summary: collapse an image's address->byte map into sorted (start, end_excl) runs."""
    runs = []
    start = prev = None
    for addr in sorted(image.data):
        if start is None or addr != prev + 1:
            if start is not None:
                runs.append((start, prev + 1))
            start = addr
        prev = addr
    if start is not None:
        runs.append((start, prev + 1))
    return runs


def test_tc_b99_03b_hex_extents_literal():
    """HEX extents pinned literally from the spec (LLR-152.3 hardening, F4)."""
    for name, expected in LITERAL_HEX_EXTENTS.items():
        assert _extents(read_hex(CORPUS / name)) == expected, name


def test_at_b99_01_check_mode(tmp_path):
    """``--check`` passes on the committed corpus and names a tampered file."""
    ok = _run_generator("--check")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert re.search(r"checked \d+ files", ok.stdout)

    copy = tmp_path / "copy"
    shutil.copytree(CORPUS, copy)
    target = copy / "synth_s1.s19"
    text = target.read_text(encoding="ascii")
    flip_at = text.index("S1") + 8
    flipped = "0" if text[flip_at] != "0" else "1"
    target.write_text(text[:flip_at] + flipped + text[flip_at + 1 :], encoding="ascii")

    bad = _run_generator("--check", "--corpus", str(copy))
    assert bad.returncode == 1
    assert "synth_s1.s19" in bad.stdout + bad.stderr
