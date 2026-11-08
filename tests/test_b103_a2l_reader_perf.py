"""Batch-103 Inc 11 — the timing / memory arms (R-A2L-READ.52).

Run ALONE on cachyos-rtx (``-m serial_timing``, never under ``-n``), GC off,
the least of >= 15 in-process runs for time, and a fresh process per memory run
(the ``/proc/self/status`` ``VmHWM`` high-water mark) so the peak is the true
peak (``ru_maxrss`` is inherited across ``fork``/``exec`` from the timing runs).
The bounds are the requirement's numbers: time <= 1.5 x the e07fb00 median and
peak RSS <= 2 x e07fb00's peak, both measured on the same host (base medians
recorded in the RED transcript).

The base numbers (e07fb00, cachyos-rtx, E3 re-measure): case_06 parse 5.898 s /
535 MB; software_a 0.653 s / 95 MB; the 200,000-line string file 70.9 MB; the
4.8-million-word one-section file 114.0 MB (memory only — its time is not
bounded). The round-2 list form of ``_section_words`` (752.7 MB) and P2's
per-character alternation (1,005 MB) both trip the 2 x memory bound.
"""

from __future__ import annotations

import gc
import subprocess
import sys
import time
from pathlib import Path

import pytest

from s19_app.tui.a2l import parse_a2l_file

from tests.support.timing import report_margin, timing_bound

REPO_ROOT = Path(__file__).resolve().parent.parent
CASE06 = REPO_ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"
SOFTWAREA = REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l"

# e07fb00 medians / peaks measured on cachyos-rtx (RED transcript).
BASE_CASE06_S = 5.898
BASE_SOFTWAREA_S = 0.653
BASE_CASE06_MB = 535.0
BASE_SOFTWAREA_MB = 95.0
BASE_STRING_MB = 70.9
BASE_WORDS_MB = 114.0
# The string file's base time, measured on cachyos-rtx in the RED run.
BASE_STRING_S = 0.075

RUNS = 15
MB = 1024 * 1024


def _string_file(path: Path) -> Path:
    """One ANNOTATION_TEXT string over 200,000 lines (~8.5 MB), E3S-14."""
    lines = [
        "ASAP2_VERSION 1 71",
        '/begin PROJECT P ""',
        '/begin MODULE M ""',
        '/begin MOD_COMMON ""',
        "BYTE_ORDER MSB_FIRST",
        "/end MOD_COMMON",
        "/begin MEASUREMENT XS \"\"",
        " UWORD CM_ID 0 0 0 65535",
        " ECU_ADDRESS 0x10",
        " /begin ANNOTATION",
        " /begin ANNOTATION_TEXT",
    ]
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
        handle.write('"')
        for _ in range(200_000):
            handle.write("a" * 40 + "\n")
        handle.write('"\n')
        handle.write(" /end ANNOTATION_TEXT\n /end ANNOTATION\n")
        handle.write(" BIT_MASK 0x0FF0\n/end MEASUREMENT\n/end MODULE\n/end PROJECT\n")
    return path


def _words_file(path: Path) -> Path:
    """One MEASUREMENT ``BIG`` whose body is 600,000 lines of eight words each
    (~19.8 MB), E3S-28's ``gen`` shape."""
    with path.open("w", encoding="utf-8") as handle:
        handle.write(
            "ASAP2_VERSION 1 71\n"
            '/begin PROJECT P ""\n'
            '/begin MODULE M ""\n'
            '/begin MOD_COMMON ""\n'
            "BYTE_ORDER MSB_FIRST\n"
            "/end MOD_COMMON\n"
            '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n'
            "/end COMPU_METHOD\n"
            '/begin MEASUREMENT BIG ""\n'
            " UWORD CM_ID 0 0 0 65535\n"
            " ECU_ADDRESS 0x10\n"
        )
        for _ in range(600_000):
            handle.write(" ab1 ab2 ab3 ab4 ab5 ab6 ab7 ab8\n")
        handle.write("/end MEASUREMENT\n/end MODULE\n/end PROJECT\n")
    return path


@pytest.fixture(scope="module")
def big_files(tmp_path_factory: pytest.TempPathFactory) -> dict:
    d = tmp_path_factory.mktemp("b103_a2l_reader_perf")
    return {
        "case06": CASE06,
        "software_a": SOFTWAREA,
        "string": _string_file(d / "string.a2l"),
        "words": _words_file(d / "words.a2l"),
    }


def _min_time(path: Path) -> float:
    """Least of RUNS in-process parses with GC off."""
    gc.collect()
    was = gc.isenabled()
    gc.disable()
    try:
        best = None
        for _ in range(RUNS):
            t0 = time.perf_counter()
            parse_a2l_file(path)
            elapsed = time.perf_counter() - t0
            if best is None or elapsed < best:
                best = elapsed
        return best
    finally:
        if was:
            gc.enable()


def _peak_mb(path: Path) -> float:
    """Peak RSS of one parse in a fresh process (best of 3)."""
    script = (
        "import sys\n"
        "from s19_app.tui.a2l import parse_a2l_file\n"
        "from pathlib import Path\n"
        "parse_a2l_file(Path(sys.argv[1]))\n"
        "peak_kb = 0\n"
        "with open('/proc/self/status') as fh:\n"
        "    for line in fh:\n"
        "        if line.startswith('VmHWM:'):\n"
        "            peak_kb = int(line.split()[1])\n"
        "            break\n"
        "print(peak_kb)\n"
    )
    best = None
    for _ in range(3):
        completed = subprocess.run(
            [sys.executable, "-c", script, str(path)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        rss_kb = int(completed.stdout.strip())
        if best is None or rss_kb < best:
            best = rss_kb
    return best / 1024.0  # KB -> MB


@pytest.mark.serial_timing
def test_r_a2l_read_52_case06_time(big_files: dict) -> None:
    elapsed = _min_time(big_files["case06"])
    bound = BASE_CASE06_S * 1.5
    assert elapsed < report_margin("R-A2L-READ.52/1 case_06 time", elapsed, timing_bound(bound)), elapsed


@pytest.mark.serial_timing
def test_r_a2l_read_52_software_a_time(big_files: dict) -> None:
    elapsed = _min_time(big_files["software_a"])
    bound = BASE_SOFTWAREA_S * 1.5
    assert elapsed < report_margin("R-A2L-READ.52/1 software_a time", elapsed, timing_bound(bound)), elapsed


@pytest.mark.serial_timing
def test_r_a2l_read_52_string_time(big_files: dict) -> None:
    elapsed = _min_time(big_files["string"])
    bound = BASE_STRING_S * 1.5
    assert elapsed < report_margin("R-A2L-READ.52/2 string time", elapsed, timing_bound(bound)), elapsed


@pytest.mark.serial_timing
def test_r_a2l_read_52_case06_memory(big_files: dict) -> None:
    peak = _peak_mb(big_files["case06"])
    bound = BASE_CASE06_MB * 2.0
    assert peak < report_margin("R-A2L-READ.52/1 case_06 peak RSS", peak, timing_bound(bound)), peak


@pytest.mark.serial_timing
def test_r_a2l_read_52_software_a_memory(big_files: dict) -> None:
    peak = _peak_mb(big_files["software_a"])
    bound = BASE_SOFTWAREA_MB * 2.0
    assert peak < report_margin("R-A2L-READ.52/1 software_a peak RSS", peak, timing_bound(bound)), peak


@pytest.mark.serial_timing
def test_r_a2l_read_52_string_memory(big_files: dict) -> None:
    peak = _peak_mb(big_files["string"])
    bound = BASE_STRING_MB * 2.0
    assert peak < report_margin("R-A2L-READ.52/2 string peak RSS", peak, timing_bound(bound)), peak


@pytest.mark.serial_timing
def test_r_a2l_read_52_words_memory(big_files: dict) -> None:
    peak = _peak_mb(big_files["words"])
    bound = BASE_WORDS_MB * 2.0
    assert peak < report_margin("R-A2L-READ.52/3 words peak RSS", peak, timing_bound(bound)), peak


def test_r_a2l_read_52_words_no_exception_and_one_error(big_files: dict) -> None:
    """R-A2L-READ.52/3 / .65/6: the 19.8 MB file parses with one surplus-word
    error and the tag ``BIG`` has no address."""
    data = parse_a2l_file(big_files["words"])
    big = [t for t in data["tags"] if t["name"] == "BIG"]
    assert len(big) == 1 and big[0]["address"] is None
    assert any("ECU_ADDRESS has 4800001 of its 1 arguments" in e for e in data["errors"])
