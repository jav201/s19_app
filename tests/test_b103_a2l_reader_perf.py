"""Batch-103 Inc 11 — the timing / memory arms (R-A2L-READ.52).

Run ALONE on linux-runner (``-m serial_timing``, never under ``-n``). Every
measurement is the median of 3 runs, each in a FRESH process (``/proc/self/status``
``VmHWM`` for the peak and ``VmRSS`` before the parse), so the peak is the true
peak (``ru_maxrss`` is inherited across ``fork``/``exec``). Each run reports its
pre-parse RSS and the peak minus it (E3S-30).

The bound is the requirement's number: time <= 1.5 x the e07fb00 median and peak
RSS <= 2 x e07fb00's peak, both measured on the same host in the SAME session.
When ``B103_BASE_ROOT`` names a checkout of the e07fb00 base (its
``s19_app/tui/a2l.py`` exists), the base median/peak is measured in this same
session and used as the reference; otherwise the hard-coded RED-transcript base
numbers below are the fallback (the thresholds are never weakened).

The base numbers (e07fb00, linux-runner, E3 re-measure): case_06 parse 5.898 s /
535 MB; software_a 0.653 s / 95 MB; the 200,000-line string file 70.9 MB; the
4.8-million-word one-section file 114.0 MB (memory only — its time is not
bounded). The round-2 list form of ``_section_words`` (752.7 MB) and P2's
per-character alternation (1,005 MB) both trip the 2 x memory bound.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from s19_app.tui.a2l import parse_a2l_file, render_a2l_view

from tests.support.timing import report_margin, timing_bound

REPO_ROOT = Path(__file__).resolve().parent.parent
CASE06 = REPO_ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"
SOFTWAREA = REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l"

# e07fb00 medians / peaks measured on linux-runner (RED transcript) — the
# fallback reference when B103_BASE_ROOT is not set.
BASE_CASE06_S = 5.898
BASE_SOFTWAREA_S = 0.653
BASE_CASE06_MB = 535.0
BASE_SOFTWAREA_MB = 95.0
BASE_STRING_MB = 70.9
BASE_WORDS_MB = 114.0
# The string file's base time, measured on linux-runner in the RED run.
BASE_STRING_S = 0.075

RUNS = 3
MB = 1024 * 1024

#: The e07fb00 base checkout for the same-session base/current comparison.
_BASE_ROOT = os.environ.get("B103_BASE_ROOT")


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


_WORDS_GROUP = "ab1 ab2 ab3 ab4 ab5 ab6 ab7 ab8"


def _words_file(path: Path, one_line: bool = False) -> Path:
    """One MEASUREMENT ``BIG`` whose body is 4.8 million words (600,000 groups
    of eight words) — one group per line (~19.8 MB) or, when ``one_line``, all
    4.8 million words on one body line (~19.2 MB), E3S-28's ``gen`` shape."""
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
        if one_line:
            handle.write(" " + " ".join(_WORDS_GROUP for _ in range(600_000)) + "\n")
        else:
            for _ in range(600_000):
                handle.write(f" {_WORDS_GROUP}\n")
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
        "words_one_line": _words_file(d / "words_one_line.a2l", one_line=True),
    }


_METRICS_SCRIPT = (
    "import json, sys, time\n"
    "from pathlib import Path\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from s19_app.tui.a2l import parse_a2l_file\n"
    "def _rss():\n"
    "    with open('/proc/self/status') as fh:\n"
    "        for line in fh:\n"
    "            if line.startswith('VmRSS:'):\n"
    "                return int(line.split()[1])\n"
    "    return 0\n"
    "def _hwm():\n"
    "    with open('/proc/self/status') as fh:\n"
    "        for line in fh:\n"
    "            if line.startswith('VmHWM:'):\n"
    "                return int(line.split()[1])\n"
    "    return 0\n"
    "pre = _rss()\n"
    "t0 = time.perf_counter()\n"
    "data = parse_a2l_file(Path(sys.argv[2]))\n"
    "elapsed = time.perf_counter() - t0\n"
    "peak = _hwm()\n"
    "print(json.dumps({'elapsed': elapsed, 'pre_kb': pre, 'peak_kb': peak, 'errors': data['errors']}))\n"
)


def _run_metrics(root: Path, path: Path) -> dict:
    """One parse in a fresh process; ``root`` on ``sys.path`` resolves ``s19_app``."""
    completed = subprocess.run(
        [sys.executable, "-c", _METRICS_SCRIPT, str(root), str(path)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout.strip())


def _median(values: list) -> float:
    return sorted(values)[len(values) // 2]


def _median_metrics(root: Path, path: Path) -> dict:
    """Median of RUNS fresh-process runs; the returned ``elapsed``/``pre_kb``/
    ``peak_kb`` are the medians and the first run's errors are kept."""
    runs = [_run_metrics(root, path) for _ in range(RUNS)]
    return {
        "elapsed": _median([r["elapsed"] for r in runs]),
        "pre_kb": _median([r["pre_kb"] for r in runs]),
        "peak_kb": _median([r["peak_kb"] for r in runs]),
        "errors": runs[0]["errors"],
    }


def _base_root() -> Path | None:
    """The e07fb00 base checkout, when ``B103_BASE_ROOT`` names it."""
    if not _BASE_ROOT:
        return None
    root = Path(_BASE_ROOT)
    if (root / "s19_app" / "tui" / "a2l.py").exists():
        return root
    return None


def _report_rss(label: str, peak_mb: float, pre_mb: float) -> None:
    """Report the pre-parse RSS and the peak minus it (E3S-30)."""
    print(
        f"{label}: peak={peak_mb:.1f} MB pre-parse={pre_mb:.1f} MB "
        f"peak-minus-before={peak_mb - pre_mb:.1f} MB"
    )


@pytest.mark.serial_timing
def test_r_a2l_read_52_case06_time(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["case06"])["elapsed"]
    root = _base_root()
    base = _median_metrics(root, big_files["case06"])["elapsed"] if root else BASE_CASE06_S
    bound = base * 1.5
    assert current < report_margin("R-A2L-READ.52/1 case_06 time", current, timing_bound(bound)), (current, base)


@pytest.mark.serial_timing
def test_r_a2l_read_52_software_a_time(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["software_a"])["elapsed"]
    root = _base_root()
    base = _median_metrics(root, big_files["software_a"])["elapsed"] if root else BASE_SOFTWAREA_S
    bound = base * 1.5
    assert current < report_margin("R-A2L-READ.52/1 software_a time", current, timing_bound(bound)), (current, base)


@pytest.mark.serial_timing
def test_r_a2l_read_52_string_time(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["string"])["elapsed"]
    root = _base_root()
    base = _median_metrics(root, big_files["string"])["elapsed"] if root else BASE_STRING_S
    bound = base * 1.5
    assert current < report_margin("R-A2L-READ.52/2 string time", current, timing_bound(bound)), (current, base)


@pytest.mark.serial_timing
def test_r_a2l_read_52_case06_memory(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["case06"])
    peak = current["peak_kb"] / 1024.0
    root = _base_root()
    base = _median_metrics(root, big_files["case06"])["peak_kb"] / 1024.0 if root else BASE_CASE06_MB
    bound = base * 2.0
    _report_rss("R-A2L-READ.52/1 case_06 peak RSS", peak, current["pre_kb"] / 1024.0)
    assert peak < report_margin("R-A2L-READ.52/1 case_06 peak RSS", peak, timing_bound(bound)), (peak, base)


@pytest.mark.serial_timing
def test_r_a2l_read_52_software_a_memory(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["software_a"])
    peak = current["peak_kb"] / 1024.0
    root = _base_root()
    base = _median_metrics(root, big_files["software_a"])["peak_kb"] / 1024.0 if root else BASE_SOFTWAREA_MB
    bound = base * 2.0
    _report_rss("R-A2L-READ.52/1 software_a peak RSS", peak, current["pre_kb"] / 1024.0)
    assert peak < report_margin("R-A2L-READ.52/1 software_a peak RSS", peak, timing_bound(bound)), (peak, base)


@pytest.mark.serial_timing
def test_r_a2l_read_52_string_memory(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["string"])
    peak = current["peak_kb"] / 1024.0
    root = _base_root()
    base = _median_metrics(root, big_files["string"])["peak_kb"] / 1024.0 if root else BASE_STRING_MB
    bound = base * 2.0
    _report_rss("R-A2L-READ.52/2 string peak RSS", peak, current["pre_kb"] / 1024.0)
    assert peak < report_margin("R-A2L-READ.52/2 string peak RSS", peak, timing_bound(bound)), (peak, base)


@pytest.mark.serial_timing
def test_r_a2l_read_52_words_memory(big_files: dict) -> None:
    current = _median_metrics(REPO_ROOT, big_files["words"])
    peak = current["peak_kb"] / 1024.0
    root = _base_root()
    base = _median_metrics(root, big_files["words"])["peak_kb"] / 1024.0 if root else BASE_WORDS_MB
    bound = base * 2.0
    _report_rss("R-A2L-READ.52/3 words peak RSS", peak, current["pre_kb"] / 1024.0)
    assert peak < report_margin("R-A2L-READ.52/3 words peak RSS", peak, timing_bound(bound)), (peak, base)


def test_r_a2l_read_52_words_no_exception_and_one_error(big_files: dict) -> None:
    """R-A2L-READ.52/3 / .65/6: the 19.8 MB file and the 4.8-million-word
    one-body-line variant parse and render with exactly one surplus-word error
    (``Line 11: ECU_ADDRESS has 4800001 of its 1 arguments``) and ``BIG`` has
    no address."""
    for key in ("words", "words_one_line"):
        data = parse_a2l_file(big_files[key])
        render_a2l_view(data)
        big = [t for t in data["tags"] if t["name"] == "BIG"]
        assert len(big) == 1 and big[0]["address"] is None, key
        errs = [e for e in data["errors"] if "ECU_ADDRESS has 4800001 of its 1 arguments" in e]
        assert errs == ["Line 11: ECU_ADDRESS has 4800001 of its 1 arguments"], (key, data["errors"])
