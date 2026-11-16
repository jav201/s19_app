"""Batch-103 Inc 10, E4 mutant run (MU10): tests written for the mutants the first 124 nodes let live.

Survivors of the first run (``inc-10/E4-mutants.md``):

* MU04 (the prompt's chips back in the base's two-row grid), MU34 (the prompt rows padded by 4 rows), MU36 (the chip
  row 3 rows high): every prompt control stayed inside a 54-row screen, so R-PE-EXPORT.2 and R-TUI-064.* stayed
  GREEN.  What they change is the dock's height, which the requirement row R-PE-EXPORT.2/11 re-maps to "the 4-row
  dock, I-8.3 fit" and the tests only printed.  ``test_the_largest_dock_is_four_rows_high_with_one_chip_row`` pins it.
* MU26d (the S0 header cut at 253 bytes): R-S19-S0HEADER-001.2 says "cut to 252 bytes"; no node wrote a name long
  enough to be cut.
* MU26f (``_S0_NAME_ROUNDS`` 2 instead of 3): a work area where the second round's landing name differs again
  (a reused name, then a numbered one) needs the third round.

Each test is RED on the mutant it names and GREEN on the tree; the control is in each docstring.
"""
from __future__ import annotations

from tests.support import b103_inc10 as t

import pytest

CHIPS = ("patch_saveback_format_button", "patch_saveback_width_button",
         "patch_saveback_confirm_button", "patch_saveback_decline_button")


@pytest.mark.parametrize("case,size", [("MU-DOCK/1", t.SIZE), ("MU-DOCK/2", t.WIDE)], ids=["MU-DOCK/1", "MU-DOCK/2"])
def test_the_largest_dock_is_four_rows_high_with_one_chip_row(tmp_path, case, size):
    """Pins the approved graph's I-8.3 budget (the 4-row dock, F-R8-1 fit), which keeps R-PE-EXPORT.2 and
    R-TUI-064.1 true at 118x54; it is not requirement text. Prompt and before/after control both shown, S19 (the dock's
    largest form): the dock is at most 4 rows high and the four prompt chips lie in one screen row.
    Negative controls: the chips in the base's two-row grid (MU04), the prompt rows padded (MU34), the chip row
    3 rows high (MU36) -> RED."""

    async def body(app, pilot):
        await t.write_file(pilot, app)
        await t.press_apply(pilot, app)
        dock = t.need(app.screen, "#patch_export_dock")
        rows = {i: t.need(app.screen, f"#{i}").region.y for i in CHIPS}
        return dock.region.height, rows, t.prompt_is_shown(app)

    height, rows, prompt = t.run_applied(tmp_path, size, "firmware.s19", "patch_tab_inspector", body)
    assert prompt, "the prompt is not a shown widget, so the height says nothing"
    assert height <= 4, (case, "the dock is taller than the 4 rows I-8.3 fits", height)
    assert len(set(rows.values())) == 1, (case, "the prompt chips are not in one row", rows)


def test_r_s19_s0header_001_2_6_a_long_written_name_is_cut_to_252_bytes(tmp_path):
    """R-S19-S0HEADER-001.2/6: an Intel HEX source written as S19 under a 254-character name (the longest a
    file system takes) gets header data of exactly the first 252 bytes of the written name.
    Negative control: the header cut at 253 bytes (MU26d) -> RED."""
    name = "n" * 250 + ".s19"

    async def body(app, pilot):
        await t.post_decision(app, pilot, name, "s19", 32)
        return t.s0_data(t.written(app, name))

    data = t.run_loaded(tmp_path, t.SIZE, "firmware.hex", body)
    assert data == name.encode("ascii")[:252], len(data)


def test_r_s19_s0header_001_2_7_the_header_follows_a_landing_name_that_moves_twice(tmp_path):
    """R-S19-S0HEADER-001.2/7 (D8-28): ``fw.s19`` holds other bytes and ``fw_1.s19`` holds exactly the bytes a
    save under the header ``fw.s19`` renders, so the first prediction is the reused ``fw_1.s19``; the header of
    that name renders other bytes, which land as ``fw_2.s19``; only the third render carries ``fw_2.s19``.
    The file written is ``fw_2.s19`` and its header data is ``fw_2.s19``.
    Negative control: two rounds only (MU26f) -> the header says ``fw_1.s19`` -> RED."""

    async def first(app, pilot):
        await t.post_decision(app, pilot, "fw.s19", "s19", 32)
        return t.written(app, "fw.s19").read_bytes()

    render_for_fw = t.run_loaded(tmp_path / "one", t.SIZE, "firmware.hex", first)

    async def second(app, pilot):
        area = t.workarea(app)
        area.mkdir(parents=True, exist_ok=True)
        (area / "fw.s19").write_bytes(b"other content\n")
        (area / "fw_1.s19").write_bytes(render_for_fw)
        lines = await t.post_decision(app, pilot, "fw.s19", "s19", 32)
        return t.s0_data(t.written(app, "fw_2.s19")), t.work_files(app), lines

    data, files, lines = t.run_loaded(tmp_path / "two", t.SIZE, "firmware.hex", second)
    assert data == b"fw_2.s19", (data, files, lines)
    assert files == ["fw.s19", "fw_1.s19", "fw_2.s19"], files
