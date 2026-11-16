"""Batch-103 Inc 10, E4 group G3 (the Intel HEX emit and the engine's conversions).

Cases: ``inc-10/02-test-cases.md`` rows R-HEX-EMIT-001.11/1..2 (the changed node ``emit_intel_hex_from_mem_map``:
no type-00 record crosses a 64 KiB boundary), and the cited engine rows that the new save-back path depends on:
R-HEX-SAVE-001.2/1..4, R-PE-EXPORT.16/1..8, R-HEX-EMIT-001.2/1, .3/1..2, R-S19-EMIT.3/1, .4/1..2, .5/1,
R-IMG-WRITE.2/1, R-HEX-VERIFY-001.1/5.  "Through the writer" = ``save_patched_image`` with the output format as
``source_kind`` (the call the save-back handler makes) into an isolated work area, then ``verify_written_image``.

Expected values: the x64u lines are read from ``tests/fixtures/b103_inc10/x64u.hex`` (never retyped); record types,
offsets and lengths are parsed from the written text; images are read back with
``tests/support/independent_reader.py``.  The cited engine rows are GREEN on base ``439860c4`` by design (the
engine is not changed by this increment: census C); only R-HEX-EMIT-001.11 is RED there.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from s19_app.tui.changes.apply import save_patched_image
from s19_app.tui.changes.verify import STATUS_MISMATCH, STATUS_VERIFIED, verify_written_image
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR
from tests.support import b103_inc10 as t
from tests.support.independent_reader import read_hex, read_s19


@pytest.fixture(scope="module")
def sources(tmp_path_factory) -> dict:
    """The 8 conversion sources by file name, each as (path, loaded image)."""
    folder = tmp_path_factory.mktemp("b103_inc10_sources")
    return {p.name: (p, t.load_image(p)) for p in t.conversion_sources(folder)}


@pytest.fixture()
def work(tmp_path) -> Path:
    area = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    area.mkdir(parents=True)
    return area


def write(loaded, work: Path, name: str, kind: str, width: int = 32):
    """The save-back writer as the handler calls it; returns (path, issues)."""
    return save_patched_image(dict(loaded.mem_map), list(loaded.ranges), work, name, source_kind=kind,
                              bytes_per_line=width, s0_header=None, workarea_root=work)


def written_lines(loaded, work: Path, name: str, kind: str, width: int = 32) -> list:
    path, issues = write(loaded, work, name, kind, width)
    assert path is not None, [i.code for i in issues]
    return path.read_text(encoding="ascii").splitlines()


def hex_types(lines) -> list:
    return [int(line[7:9], 16) for line in lines]


# ------------------------------------------------------------------ R-HEX-EMIT-001.11


@pytest.mark.parametrize("case,source", [("R-HEX-EMIT-001.11/1", "x64u.s19"), ("R-HEX-EMIT-001.11/2", "x64u.hex")],
                         ids=["R-HEX-EMIT-001.11/1", "R-HEX-EMIT-001.11/2"])
def test_r_hex_emit_001_11_no_type_00_record_crosses_a_64_kib_boundary(tmp_path, work, case, source):
    """R-HEX-EMIT-001.11/1,/2: x64u (32 bytes at 0x0000FFF8, off a 16-byte boundary) written as Intel HEX at
    width 32: the written lines equal ``x64u.hex`` line for line (the committed data) and every type-00 record's
    offset + length is at most 0x10000.  Negative control: the base loop (``:10FFF800...``, a crossing
    record, ``x64u-base-emitter.hex``) -> RED; the cap inside the fixed 16-step loop (bytes 0x10000..0x10007
    lost) -> the lines differ -> RED."""
    src = tmp_path / source
    src.write_text((t.X64U_DIR / source).read_text(encoding="ascii"), newline="\n")
    expected = (t.X64U_DIR / "x64u.hex").read_text(encoding="ascii").splitlines()
    lines = written_lines(t.load_image(src), work, "x64u-patched.hex", "hex")
    crossing = [l for l in lines if l[7:9] == "00" and int(l[3:7], 16) + int(l[1:3], 16) > 0x10000]
    assert crossing == [], (case, crossing)
    assert lines == expected, (case, lines, expected)


def test_r_hex_emit_001_11_the_data_files_are_what_the_base_emitter_would_cross():
    """Oracle guard for R-HEX-EMIT-001.11 (not a case): the committed base-emitter file does cross the boundary
    and the committed expected file does not, so the two cases above can fail and can pass."""
    base = (t.X64U_DIR / "x64u-base-emitter.hex").read_text(encoding="ascii").splitlines()
    good = (t.X64U_DIR / "x64u.hex").read_text(encoding="ascii").splitlines()
    over = lambda ls: [l for l in ls if l[7:9] == "00" and int(l[3:7], 16) + int(l[1:3], 16) > 0x10000]  # noqa: E731
    assert over(base) and not over(good)


def test_r_hex_emit_001_11_a_row_starting_at_low_ffff_ends_at_the_boundary_and_the_walk_advances(monkeypatch):
    """Bound for R-HEX-EMIT-001.11 (E5, not a case): a row whose first address has low 16 bits 0xFFFF holds one
    byte and the next row starts at 0x00010000.  The emitter's record writer is counted and stopped after 64
    records, so a walk that stops advancing fails here in milliseconds instead of hanging the run (mutant MU24c,
    the boundary ``(row_start | 0xFFFF)`` without ``+ 1``, hung to the 300 s runner timeout).  Expected lines are
    hand-computed Intel HEX (checksums = two's complement of the byte sum), not read from the emitter.  Negative
    controls: MU24c -> the 64-record stop -> RED; the base loop (16-byte rows from the range start) -> one record
    ``:02FFFF00...`` across the boundary -> RED."""
    from s19_app.tui.changes import io as changes_io

    real_record = changes_io._intel_hex_record
    calls = []

    def bounded_record(*args, **kwargs):
        calls.append(args)
        assert len(calls) <= 64, "the HEX row walk stopped advancing (more than 64 records for a 2-byte image)"
        return real_record(*args, **kwargs)

    monkeypatch.setattr(changes_io, "_intel_hex_record", bounded_record)
    text = changes_io.emit_intel_hex_from_mem_map({0xFFFF: 0xAA, 0x10000: 0xBB}, [(0xFFFF, 0x10001)])
    assert text.splitlines() == [":020000040000FA", ":01FFFF00AA57", ":020000040001F9", ":01000000BB44",
                                 ":00000001FF"]


# ------------------------------------------------------------------ R-HEX-SAVE-001.2: the suffix rule


NAMES = [("R-HEX-SAVE-001.2/1", "firmware-patched.s19", "hex", "firmware-patched.s19.hex"),
         ("R-HEX-SAVE-001.2/2", "firmware-patched.HEX", "hex", "firmware-patched.HEX"),
         ("R-HEX-SAVE-001.2/3", "firmware-patched", "hex", "firmware-patched.hex"),
         ("R-HEX-SAVE-001.2/4", "firmware-patched.hex", "s19", "firmware-patched.hex.s19")]


@pytest.mark.parametrize("case,typed,kind,expected", NAMES, ids=[c[0] for c in NAMES])
def test_r_hex_save_001_2_the_format_suffix_is_added_when_missing(sources, work, case, typed, kind, expected):
    """R-HEX-SAVE-001.2/1..4: the writer, case01, the typed name and output format -> the written name.
    GREEN on base by design (C: the engine's suffix rule is unchanged).  Negative control: the suffix taken
    from the loaded image's kind -> /1 and /4 RED."""
    path, issues = write(sources["firmware.s19"][1], work, typed, kind)
    assert path is not None and path.name == expected, (case, path, [i.code for i in issues])


# ------------------------------------------------------------------ R-PE-EXPORT.16: HEX record types


HEX_SOURCES = [("R-PE-EXPORT.16/1", "s19_sample.s19"), ("R-PE-EXPORT.16/2", "s2_source.s19"),
               ("R-PE-EXPORT.16/3", "firmware.s19"), ("R-PE-EXPORT.16/4", "cross64k.s19"),
               ("R-PE-EXPORT.16/5", "s19_sample.hex"), ("R-PE-EXPORT.16/6", "s2_source.hex"),
               ("R-PE-EXPORT.16/7", "firmware.hex"), ("R-PE-EXPORT.16/8", "cross64k.hex")]


@pytest.mark.parametrize("case,source", HEX_SOURCES, ids=[c[0] for c in HEX_SOURCES])
def test_r_pe_export_16_a_hex_save_back_holds_only_record_types_00_01_04(sources, work, case, source):
    """R-PE-EXPORT.16/1..8: each of the 8 sources written as Intel HEX at width 32 holds only records of type 00,
    01 or 04 (and has data records, an end record).  GREEN on base by design (C: 16/16).  Negative control: the
    S19 header or the S19 terminator carried into the file as another record type -> RED."""
    lines = written_lines(sources[source][1], work, "out.hex", "hex")
    types = hex_types(lines)
    assert set(types) <= {0, 1, 4} and 0 in types and types[-1] == 1, (case, sorted(set(types)))


# ------------------------------------------------------------------ the emitted records


def test_r_hex_emit_001_2_1_a_type_04_record_precedes_the_first_data_record(sources, work):
    """R-HEX-EMIT-001.2/1: case01 as Intel HEX -> first line ``:0200000480007A`` (read from the written file).
    GREEN on base by design (C).  Negative control: no type-04 before the data -> RED."""
    assert written_lines(sources["firmware.s19"][1], work, "out.hex", "hex")[0] == ":0200000480007A"


@pytest.mark.parametrize("case,source,count", [("R-HEX-EMIT-001.3/1", "s2_source.s19", 2),
                                               ("R-HEX-EMIT-001.3/2", "cross64k.s19", 2)],
                         ids=["R-HEX-EMIT-001.3/1", "R-HEX-EMIT-001.3/2"])
def test_r_hex_emit_001_3_a_type_04_record_when_the_upper_16_bits_change(sources, work, case, source, count):
    """R-HEX-EMIT-001.3/1,/2: s2src (two ranges) and x64 (one range crossing 64 KiB) as Intel HEX -> 2 type-04
    records; for s2src ``:020000040001F9`` first, for x64 the upper words 0x0000 then 0x0001.  GREEN on base
    by design (C).  Negative control: no type-04 on the change -> RED."""
    lines = written_lines(sources[source][1], work, "out.hex", "hex")
    ela = [l for l in lines if l[7:9] == "04"]
    assert len(ela) == count, (case, ela)
    if source == "s2_source.s19":
        assert ela[0] == ":020000040001F9", ela
    else:
        assert [int(l[9:13], 16) for l in ela] == [0x0000, 0x0001], ela


# ------------------------------------------------------------------ an Intel HEX source written as S19


S19_RECORDS = [("R-S19-EMIT.3/1", "s19_sample.hex", "S1", "S9"), ("R-S19-EMIT.4/1", "s2_source.hex", "S2", "S8"),
               ("R-S19-EMIT.4/2", "cross64k.hex", "S2", "S8"), ("R-S19-EMIT.5/1", "firmware.hex", "S3", "S7")]


@pytest.mark.parametrize("case,source,data_tag,end_tag", S19_RECORDS, ids=[c[0] for c in S19_RECORDS])
def test_r_s19_emit_the_record_size_follows_the_highest_address(sources, work, case, source, data_tag, end_tag):
    """R-S19-EMIT.3/1, .4/1, .4/2, .5/1: an Intel HEX source written as S19 uses S1 (highest 0x80F1), S2 (0x20010,
    0x10013) or S3 (0x8000007F) data records and the matching terminator tag.  Tags only (E4-N2).  GREEN on
    base by design (C).  Negative control: the wrong record size for the address -> RED."""
    lines = written_lines(sources[source][1], work, "out.s19", "s19")
    data = {l[:2] for l in lines if l[:2] in ("S1", "S2", "S3")}
    assert data == {data_tag} and lines[-1][:2] == end_tag, (case, data, lines[-1][:2])


# ------------------------------------------------------------------ R-IMG-WRITE.2, R-HEX-VERIFY-001.1/5: the matrix


OUTPUTS = [("s19", 32), ("s19", 16), ("hex", 32), ("hex", 16)]


def read_back(path: Path, kind: str):
    return read_hex(path) if kind == "hex" else read_s19(path)


def test_r_img_write_2_1_every_conversion_reads_back_to_the_same_image(sources, work):
    """R-IMG-WRITE.2/1: the 8 conversion sources x 4 outputs (S19 and Intel HEX, width 32 and 16): 32/32 read
    back to the source image by the independent reader and by the system's loader, with no parse error.  GREEN
    on base by design (C: ``reread_equal True``).  Negative control: one byte dropped by a writer -> RED."""
    bad = []
    for name, (_path, loaded) in sources.items():
        for kind, width in OUTPUTS:
            out, issues = write(loaded, work, f"{name}-{kind}{width}.{kind}", kind, width)
            assert out is not None, (name, kind, width, [i.code for i in issues])
            image = read_back(out, kind)
            again = t.load_image(out)
            if image.errors or image.data != dict(loaded.mem_map) or dict(again.mem_map) != dict(loaded.mem_map):
                bad.append((name, kind, width, image.errors[:2]))
    assert bad == [], bad


def test_r_hex_verify_001_1_5_the_conversion_matrix_verifies_and_the_wrong_reader_does_not(sources, work):
    """R-HEX-VERIFY-001.1/5: 32/32 writes (8 sources x 4 outputs) are ``verified`` when read back with the
    output format's reader; the negative control (each source written in the other format and read with the
    source's own reader) gives ``mismatch`` 8/8.  GREEN on base by design (C).  Negative control: the verify
    reading with the loaded image's reader -> the converting cases ``mismatch`` -> RED."""
    wrong, mismatched = [], 0
    for name, (_path, loaded) in sources.items():
        for kind, width in OUTPUTS:
            out, _issues = write(loaded, work, f"{name}-{kind}{width}.{kind}", kind, width)
            if verify_written_image(out, dict(loaded.mem_map), kind).status != STATUS_VERIFIED:
                wrong.append((name, kind, width))
        other = "hex" if loaded.file_type == "s19" else "s19"
        out, _issues = write(loaded, work, f"{name}-neg.{other}", other)
        if verify_written_image(out, dict(loaded.mem_map), loaded.file_type).status == STATUS_MISMATCH:
            mismatched += 1
    assert wrong == [], wrong
    assert mismatched == len(sources) == 8, mismatched
