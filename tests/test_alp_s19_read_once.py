"""FA-TICK2 — the S19 reader reads the file once and keeps its line semantics.

The image load route builds ``S19File`` on the worker and, on the base tree,
``S19File._load`` iterated the text file line by line (``enumerate(f, 1)``).
Every raw buffer refill handed the GIL back to the UI thread, so the 50 ms UI
timer tick fired late during post-parse preparation (R-A2L-REFRESH.050).
The reader now reads the text once and iterates it in memory
(``io.StringIO(f.read())``). These nodes pin two things: the read is
single-pass at the raw layer, and the S19 line semantics (terminator,
trailing records, damaged data lines, S5 tally, CRLF/lone-CR handling) are
unchanged by the move from stream iteration to in-memory iteration.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import s19_app.core as core
from tests.conftest import make_large_s19


class _CountingFileIO(io.FileIO):
    """A raw ``FileIO`` that counts every raw read at the binary layer."""

    raw_reads: int = 0

    def read(self, *args, **kwargs):
        _CountingFileIO.raw_reads += 1
        return super().read(*args, **kwargs)

    def readinto(self, *args, **kwargs):
        _CountingFileIO.raw_reads += 1
        return super().readinto(*args, **kwargs)

    def readall(self, *args, **kwargs):
        _CountingFileIO.raw_reads += 1
        return super().readall(*args, **kwargs)


def _counting_open(path: str, mode: str = "r", *args, **kwargs):
    """Text-mode ``open`` whose binary layer counts raw reads."""
    raw = _CountingFileIO(str(path), "rb")
    return io.TextIOWrapper(io.BufferedReader(raw), encoding="utf-8")


def _record_signature(record) -> tuple:
    """The pinned record identity: type, address, data, valid."""
    return (record.type, record.address, list(record.data), record.valid)


def test_r_a2l_refresh_050_s19_reader_reads_the_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-A2L-REFRESH.050 (E4R) — ``S19File._load`` reads the text file once.

    On the base tree ``_load`` iterated the file object line by line, issuing
    one raw read per buffer refill (~295 raw reads for a 2.4 MB image), and
    each refill yielded the GIL to the UI thread during post-parse
    preparation. With ``io.StringIO(f.read())`` the whole text is read in one
    raw read, so the worker does not hand the GIL back and forth per read.
    The node asserts <= 2 raw reads and that the parsed records equal a
    baseline built without the patch.
    """
    path = make_large_s19(tmp_path / "large.s19")
    assert path.stat().st_size >= 1_000_000, path.stat().st_size

    baseline = core.S19File(str(path))
    expected = [_record_signature(r) for r in baseline.records]
    assert expected, "baseline parsed no records"

    _CountingFileIO.raw_reads = 0
    monkeypatch.setattr(core, "open", _counting_open, raising=False)
    loaded = core.S19File(str(path))

    assert _CountingFileIO.raw_reads <= 2, _CountingFileIO.raw_reads
    got = [_record_signature(r) for r in loaded.records]
    assert got == expected


def test_r_read_002_s19_reader_line_semantics_unchanged(
    tmp_path: Path,
) -> None:
    """R-READ.2, R-READ-001.1, R-READ-007.1, R-READ-007.3, R-PARSE.2 and
    R-READ-006.1 — in-memory iteration preserves S19 line semantics.

    The input mixes CRLF lines, one lone-CR line ending, blank lines, a
    damaged ``S1`` data line, an S5 count, and data records after an S9
    terminator. ``f.read()`` applies the same universal-newline translation
    as iterating the text stream, so the terminator/trailing/tally behavior
    (and the line numbers attached to errors) must be identical to the base
    tree. Expected values below were produced by the base tree at 7f2286db.

    What this node pins, row by row:
    - R-READ.2: CR LF and the lone CR each end a line (this input has no
      bare LF line end).
    - R-READ-001.1: the blank line makes no record.
    - R-READ-007.1 and R-READ-007.3: the S3 record after S9 makes no record
      and gives the ``S19-AFTER-TERMINATOR`` notice.
    - R-PARSE.2: the damaged ``S1ZZ`` line gives ``Invalid byte count hex``.
    - R-READ-006.1: the S5 count (2) equals the data-record tally, which
      counts the rejected S1 line before the terminator, so no
      ``S19-COUNT-MISMATCH`` notice is attached.
    """
    s0 = "S009000053545245535312"        # S0 header "STRESS"
    s3_data = "S30900001000AABBCCDDD8"   # S3 at 0x1000, data AA BB CC DD
    s5 = "S5030002FA"                    # S5 count = 2
    s1_bad = "S1ZZ"                      # damaged S1: bad byte-count hex
    s9 = "S9030000FC"                    # S9 terminator
    s3_trailing = "S307000020000102D5"   # S3 at 0x2000, data 01 02 (trailing)

    raw = (
        s0 + "\r\n"
        + "\r\n"
        + s3_data + "\r"                 # lone-CR line ending
        + s5 + "\r\n"
        + s1_bad + "\r\n"
        + s9 + "\r\n"
        + s3_trailing + "\r\n"
    ).encode("ascii")

    path = tmp_path / "semantics.s19"
    path.write_bytes(raw)

    loaded = core.S19File(str(path))

    assert [(r.type, r.address) for r in loaded.records] == [
        ("S0", 0),
        ("S3", 0x1000),
        ("S5", 2),
        ("S9", 0),
    ]

    assert len(loaded.load_errors) == 2, loaded.load_errors
    first, second = loaded.load_errors
    assert first["line_number"] == 5, first
    assert first["segment"] == "SRecord constructor", first
    assert first["error"].startswith("Invalid byte count hex"), first

    assert second["line_number"] is None, second
    assert second["segment"] == "integrity", second
    assert second["error"].startswith("S19-AFTER-TERMINATOR"), second
