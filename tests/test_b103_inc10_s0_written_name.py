"""Batch-103 Inc 10, E4 integration: the S0 header of an S19 save-back is the name of the file written.

Case: ``inc-10/02-test-cases.md`` row R-S19-S0HEADER-001.2/5 (open code change D8-28, folded into Inc 10 E4 by
the P-022 ruling) and backlog BL-I10-E3-8 (HIGH, privacy): R-S19-S0HEADER-001.2 says "the written file name";
a typed full path, a name the write completes with its suffix, or a name the work area numbers must never
reach the header, which ships inside the firmware file.  The account folder in the typed paths is the
placeholder ``username_subject``.

Expected values: the written name is the one the work area holds after the write (the typed name reduced to its
bare name, the ``.s19`` suffix forced on, numbered ``_<N>`` when a different file holds the name); the header
data is that name without its non-ASCII characters.  RED before the fix: the header is the typed text.
"""
from __future__ import annotations

import pytest

from tests.support import b103_inc10 as t

TYPED = [
    ("full-windows-path", "C:\\Users\\username_subject\\Desktop\\fw.s19", "fw.s19", b"fw.s19"),
    ("full-posix-path", "/home/username_subject/fw.s19", "fw.s19", b"fw.s19"),
    ("suffix-added", "C:\\Users\\username_subject\\Desktop\\fw", "fw.s19", b"fw.s19"),
    ("non-ascii-dropped", "C:\\Users\\username_subject\\Desktop\\fw_\u00e9.s19", "fw_\u00e9.s19", b"fw_.s19"),
]


@pytest.mark.parametrize("typed,name,header", [c[1:] for c in TYPED], ids=[c[0] for c in TYPED])
def test_r_s19_s0header_001_2_5_the_header_is_the_written_name_never_the_typed_path(tmp_path, typed, name, header):
    """R-S19-S0HEADER-001.2/5 and BL-I10-E3-8: an Intel HEX source written as S19 at width 32 under a typed
    name that differs from the written one gets the WRITTEN name as header data.  The account folder of the
    typed path is in neither the header nor any byte of the file.  Negative control: the header built from the
    typed text (the code before the P-022 fix) -> RED."""

    async def body(app, pilot):
        await t.post_decision(app, pilot, typed, "s19", 32)
        path = t.written(app, name)
        return t.s0_data(path), path.read_bytes(), t.work_files(app)

    data, raw, files = t.run_loaded(tmp_path, t.SIZE, "firmware.hex", body)
    assert data == header, (typed, data)
    assert b"username_subject" not in raw
    assert files == [name], files


def test_r_s19_s0header_001_2_5_a_numbered_written_name_wins_over_the_typed_one(tmp_path):
    """R-S19-S0HEADER-001.2/5 (D8-28): ``firmware-patched.s19`` already in the work area with other content;
    the save-back under that typed name is written as ``firmware-patched_1.s19`` and its header data is
    ``firmware-patched_1.s19``.  The file already there is left as it was.  Negative control: the header built
    from the typed name (``firmware-patched.s19``) -> RED."""
    other = b"other content\n"

    async def body(app, pilot):
        holder = t.workarea(app) / "firmware-patched.s19"
        holder.parent.mkdir(parents=True, exist_ok=True)
        holder.write_bytes(other)
        lines = await t.post_decision(app, pilot, "firmware-patched.s19", "s19", 32)
        numbered = t.written(app, "firmware-patched_1.s19")
        return t.s0_data(numbered), holder.read_bytes(), lines

    data, held, lines = t.run_loaded(tmp_path, t.SIZE, "firmware.hex", body)
    assert data == b"firmware-patched_1.s19", (data, lines)
    assert held == other
