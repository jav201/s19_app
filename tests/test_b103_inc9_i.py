"""Batch-103 Inc 9 E4 (tester T9b): group I - the two integration lines in Inc 8's files.

C-4 ``LayoutMixin.compose`` (``patch_editor/layout.py``): the sheet window's border subtitle gains ` · arrays open
the bench` (R-PE-BENCH.1). C-1 ``PatchEditorPanel.__init__`` (``patch_editor/panel.py``): the panel builds the bench
sheet in place of Inc 8's ``StagingSheet`` (R-PE-BENCH.3's route; every other widget test reaches the bench sheet only
through this line). Cases: ``inc-9/02-test-cases-W.md``.

The module imports nothing of ``bench_sheet`` at top level and names the class by ``type(...).__name__``, so on
the base revision these tests fail on the BEHAVIOUR they assert (Inc 8's subtitle, a plain ``StagingSheet``), not on an
import. The real app under Pilot, at 118x54 and 220x60.
"""
from __future__ import annotations

import pytest

from tests.support.b103_inc9_w import SIZE, WIDE, defc_dir, need, run  # noqa: F401  (defc_dir is a fixture used by name)

SUBTITLE = "enter edit · ↑↓ row · arrays open the bench"
INC8_SUBTITLE = "enter edit · ↑↓ row"


@pytest.mark.parametrize("size", [SIZE, WIDE], ids=["118x54", "220x60"])
def test_r_pe_bench_1_1_the_sheet_window_subtitle_names_the_bench(tmp_path, defc_dir, size):
    """The window's `border_subtitle` equals the text; control: it still begins with Inc 8's own words (the
    clause is appended, nothing of Inc 8's text is replaced)."""

    async def body(app, pilot, panel):
        return need(panel, "#patch_sheet_win").border_subtitle

    subtitle = run(tmp_path, defc_dir, body, size=size)
    assert str(subtitle).startswith(INC8_SUBTITLE), subtitle
    assert subtitle == SUBTITLE


def test_r_pe_bench_3_the_panel_builds_the_bench_sheet_with_inc_8s_id(tmp_path, defc_dir):
    """EX-L1: the one sheet of a new panel is an `ArrayBenchSheet` (a `StagingSheet`) with id `patch_sheet`, and
    the panel's `_sheet` is that widget (the subclass keeps Inc 8's base class)."""

    async def body(app, pilot, panel):
        from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

        sheet = need(panel, "#patch_sheet")
        return type(sheet).__name__, isinstance(sheet, StagingSheet), sheet is panel._sheet

    name, is_staging, same = run(tmp_path, defc_dir, body)
    assert name == "ArrayBenchSheet" and is_staging and same
