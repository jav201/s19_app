"""Inc 7 G-T-V: the A2L viewer in list mode (batch-103, E4 tester T7).

Cases: ``.dev-flow/2026-11-05-batch-103/inc-7/02-test-cases-V.md`` (116 cases, one test
each, the case id in the test name). Every test drives the real app on case 08 (seed
20260001, 462 tags): the list reaches the viewer as the filter box's value, as the paste
routes leave it. Expected values come from the shipped parser, the shipped matcher, the
app's own text-mode cell builder and the oracle of ``tests/support/b103_label_list.py``;
none is typed except the layout widths of the requirements. The list module is imported
inside the tests that need it, so a base tree fails each test, not the collection.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import time
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea

from s19_app.tui.services.label_match import build_label_index, rank
from tests.support import b100_projects as projects
from tests.support.b100_workers import settle_workers
from tests.support.b103_label_list import (
    G2L_JOINED,
    G2L_NAMES,
    G2L_TEXT,
    REPO_ROOT,
    Hold,
    build_case08,
    build_paste,
    capture_workers,
    case_names,
    flush,
    oracle_counts,
    oracle_missing,
    oracle_ribbon,
    oracle_rows,
    patch_seam,
    plain,
    real_seam,
    release_after_close,
    run_a2l,
    set_filter,
    settle,
    static_text,
    table_labels,
    table_rows,
    tag_by_name,
    text_cells,
    worker_errors,
)
from tests.support.timing import timing_bound, wait_until

LIST_COLUMNS = ["#", "Tag", "Status", "Kind", "Address", "Len", "Physical", "Unit", "Limits"]
TEXT_COLUMNS = [
    "Address", "Length", "Tag", "Source", "Raw", "Physical", "InMem", "Region",
    "Limits", "Unit", "Bits", "Endian", "Virt", "Func", "Access", "Dtype",
]
GLYPH = {"found": "●", "missing": "✗", "duplicate": "=", "hidden": "◐"}
TEXT_FOOT = "   paste several names, or alt+p, to filter by a LIST"
LIST_FOOT = "   field ignored in LIST mode · esc back to text filter · alt+p edit the list"


@pytest.fixture(scope="module")
def case08(tmp_path_factory) -> Path:
    return build_case08(tmp_path_factory.mktemp("i7_v_case08"))


@pytest.fixture(scope="module")
def names(case08) -> list:
    return case_names(case08)


def chips(app) -> list:
    return static_text(app.query_one("#a2l_list_chips", Static)).split("\n")


def missing_text(app) -> str:
    return static_text(app.query_one("#a2l_list_missing", Static))


def mode_tag(app) -> str:
    return static_text(app.query_one("#a2l_filter_mode_tag", Label))


def summary(app) -> str:
    return static_text(app.query_one("#a2l_tags_summary", Label))


async def press(app, pilot, wid: str) -> None:
    app.query_one(wid, Button).press()
    await flush(app, pilot)


async def snapshot(app, pilot) -> dict:
    """Everything the G2 list shows at 118x54 over case 08 (image + A2L)."""
    await set_filter(app, pilot, G2L_JOINED)
    by = tag_by_name(app)
    return {
        "rows": table_rows(app), "labels": table_labels(app), "summary": summary(app),
        "chips": chips(app), "missing": missing_text(app), "tag": mode_tag(app),
        "cells": {n: text_cells(app, by[n]) for n in set(G2L_NAMES) if n in by},
        "kind": {n: (by[n].get("char_type"), by[n].get("section")) for n in by},
        "n_tags": len(app._a2l_enriched_tags),
    }


@pytest.fixture(scope="module")
def g2l(case08, tmp_path_factory) -> dict:
    return run_a2l(tmp_path_factory.mktemp("i7_v_g2l"), case08, snapshot)


def g2l_rows(names) -> list:
    return oracle_rows(G2L_NAMES, set(names))


# ---------------------------------------------------------------------------
# The table: rows, columns, cells (.006 - .016)
# ---------------------------------------------------------------------------


def test_r_a2l_list_006_1(g2l) -> None:
    """R-A2L-LIST.006/1: the G2 list -> 12 rows, #1 ... #12 in pasted order."""
    assert [r[0] for r in g2l["rows"]] == [str(i) for i in range(1, 13)]
    assert [r[1][2:] for r in g2l["rows"]] == G2L_NAMES


def test_r_a2l_list_006_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.006/2: ``CURVE_0017 MAP_0001`` typed -> 2 rows."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "CURVE_0017 MAP_0001")
        return [r[1][2:] for r in table_rows(app)]

    assert run_a2l(tmp_path, case08, sc) == ["CURVE_0017", "MAP_0001"]


def test_r_a2l_list_006_3(case08, tmp_path) -> None:
    """R-A2L-LIST.006/3: field ``all`` with the G2 list -> 12 rows (D-3)."""
    async def sc(app, pilot):
        app._set_a2l_filter_field("all")
        await set_filter(app, pilot, G2L_JOINED)
        return len(table_rows(app)), app._a2l_list_names()

    count, listed = run_a2l(tmp_path, case08, sc)
    assert count == 12 and listed == G2L_NAMES


def test_r_a2l_list_007_1(g2l) -> None:
    """R-A2L-LIST.007/1: the mode tag reads ``LIST`` for the G2 list."""
    assert g2l["tag"] == "LIST"


def test_r_a2l_list_008_1(case08, tmp_path) -> None:
    """R-A2L-LIST.008/1: an empty filter -> ``FILTER``."""
    async def sc(app, pilot):
        return mode_tag(app)

    assert run_a2l(tmp_path, case08, sc) == "FILTER"


def test_r_a2l_list_008_2(case08, tmp_path) -> None:
    """R-A2L-LIST.008/2: ``VALUE`` -> ``FILTER`` (text mode)."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE")
        return mode_tag(app)

    assert run_a2l(tmp_path, case08, sc) == "FILTER"


async def _list_then_unload(app, pilot) -> dict:
    await set_filter(app, pilot, G2L_JOINED)
    assert mode_tag(app) == "LIST"
    app._apply_unload("a2l")
    await settle_workers(pilot)
    await flush(app, pilot)
    return {"tag": mode_tag(app), "rows": table_rows(app), "summary": summary(app),
            "chips": chips(app), "missing": app.query_one("#a2l_list_missing").display,
            "resolution": app._a2l_list_resolution}


def test_r_a2l_list_008_3(case08, tmp_path) -> None:
    """R-A2L-LIST.008/3 (E3A-08): the G2 list shown, then the A2L unloaded -> ``FILTER``, 0 rows, ``No A2L tags.``."""
    out = run_a2l(tmp_path, case08, _list_then_unload)
    assert out["tag"] == "FILTER" and out["rows"] == [] and out["summary"] == "No A2L tags."
    assert not any(" LIST " in line for line in out["chips"]) and out["resolution"] is None


def test_r_a2l_list_009_1(g2l) -> None:
    """R-A2L-LIST.009/1: the list-mode columns in order."""
    assert g2l["labels"] == LIST_COLUMNS


def test_r_a2l_list_010_1(case08, tmp_path) -> None:
    """R-A2L-LIST.010/1: at 80x54 scrolled fully right, the ``#`` and ``Tag`` cells stay at their x."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        table = app.query_one("#a2l_tags_list", DataTable)
        width = sum(c.get_render_width(table) for c in table.ordered_columns[:2])
        before = [table.render_line(y).text[:width] for y in range(1, 5)]
        table.scroll_x = table.max_scroll_x
        await settle(pilot)
        after = [table.render_line(y).text[:width] for y in range(1, 5)]
        return table.max_scroll_x, before, after, table.fixed_columns

    maxx, before, after, fixed = run_a2l(tmp_path, case08, sc, size=(80, 54))
    assert maxx > 0 and fixed == 2 and before == after and "VALUE_0002" in before[0]


def _tag_cell(g2l, pos: int) -> str:
    return g2l["rows"][pos - 1][1]


def test_r_a2l_list_011_1(g2l) -> None:
    """R-A2L-LIST.011/1: ``● VALUE_0002``."""
    assert _tag_cell(g2l, 1) == "● VALUE_0002"


def test_r_a2l_list_011_2(g2l) -> None:
    """R-A2L-LIST.011/2: ``✗ MAP_0024``."""
    assert _tag_cell(g2l, 7) == "✗ MAP_0024"


def test_r_a2l_list_011_3(g2l) -> None:
    """R-A2L-LIST.011/3: ``= VALUE_0002`` (#10)."""
    assert _tag_cell(g2l, 10) == "= VALUE_0002"


def _hidden_inmem(case08, tmp_path) -> dict:
    async def sc(app, pilot):
        await press(app, pilot, "#a2l_filter_inmem")
        await set_filter(app, pilot, G2L_JOINED)
        return {"rows": table_rows(app), "chips": chips(app)}

    return run_a2l(tmp_path, case08, sc, image=False)


def test_r_a2l_list_011_4(case08, tmp_path) -> None:
    """R-A2L-LIST.011/4: mode In-Memory with no image -> ``◐ VALUE_0002``."""
    assert _hidden_inmem(case08, tmp_path)["rows"][0][1] == "◐ VALUE_0002"


def test_r_a2l_list_012_1(g2l) -> None:
    """R-A2L-LIST.012/1: ``found``."""
    assert g2l["rows"][0][2] == "found"


def test_r_a2l_list_012_2(g2l) -> None:
    """R-A2L-LIST.012/2: ``not in A2L``."""
    assert g2l["rows"][6][2] == "not in A2L"


def test_r_a2l_list_012_3(g2l) -> None:
    """R-A2L-LIST.012/3: ``dup of #1``."""
    assert g2l["rows"][9][2] == "dup of #1"


def test_r_a2l_list_012_4(case08, tmp_path) -> None:
    """R-A2L-LIST.012/4: ``hidden: In-memory``."""
    assert _hidden_inmem(case08, tmp_path)["rows"][0][2] == "hidden: In-memory"


def _kind(g2l, pos: int) -> str:
    return g2l["rows"][pos - 1][3]


def test_r_a2l_list_013_1(g2l) -> None:
    """R-A2L-LIST.013/1: ``VALUE_0002`` -> ``VALUE`` (its characteristic type)."""
    assert _kind(g2l, 1) == "VALUE" == g2l["kind"]["VALUE_0002"][0]


def test_r_a2l_list_013_2(g2l) -> None:
    """R-A2L-LIST.013/2: ``MAP_0003`` -> ``MAP``."""
    assert _kind(g2l, 3) == "MAP" == g2l["kind"]["MAP_0003"][0]


def test_r_a2l_list_013_3(g2l) -> None:
    """R-A2L-LIST.013/3: ``MEASUREMENT_0005`` (no char type) -> ``MEASURE``."""
    assert g2l["kind"]["MEASUREMENT_0005"] == (None, "MEASUREMENT") and _kind(g2l, 4) == "MEASURE"


def _cells_match(g2l, k: int) -> None:
    name = [n for n in dict.fromkeys(G2L_NAMES) if n in g2l["cells"]][k - 1]
    row = g2l["rows"][G2L_NAMES.index(name)]
    cells = g2l["cells"][name]
    assert row[4:9] == [cells["Address"], cells["Length"], cells["Physical"], cells["Unit"], cells["Limits"]]


def test_r_a2l_list_014_1(g2l) -> None:
    """R-A2L-LIST.014/1: found name 1's cells 5-9 equal its text-mode cells."""
    _cells_match(g2l, 1)


def test_r_a2l_list_014_2(g2l) -> None:
    """R-A2L-LIST.014/2: found name 2."""
    _cells_match(g2l, 2)


def test_r_a2l_list_014_3(g2l) -> None:
    """R-A2L-LIST.014/3: found name 3."""
    _cells_match(g2l, 3)


def test_r_a2l_list_014_4(g2l) -> None:
    """R-A2L-LIST.014/4: found name 4."""
    _cells_match(g2l, 4)


def test_r_a2l_list_014_5(g2l) -> None:
    """R-A2L-LIST.014/5: found name 5."""
    _cells_match(g2l, 5)


def test_r_a2l_list_014_6(g2l) -> None:
    """R-A2L-LIST.014/6: found name 6."""
    _cells_match(g2l, 6)


def test_r_a2l_list_014_7(g2l) -> None:
    """R-A2L-LIST.014/7: found name 7."""
    _cells_match(g2l, 7)


def test_r_a2l_list_014_8(g2l) -> None:
    """R-A2L-LIST.014/8: found name 8."""
    _cells_match(g2l, 8)


def test_r_a2l_list_014_9(g2l) -> None:
    """R-A2L-LIST.014/9: found name 9 (and the nine are the nine found names of the list)."""
    assert len(g2l["cells"]) == 9
    _cells_match(g2l, 9)


def test_r_a2l_list_015_1(g2l) -> None:
    """R-A2L-LIST.015/1: a missing name (``MAP_0024``) leaves its cells after ``Status`` blank."""
    assert g2l["rows"][6][3:] == [""] * 6


def test_r_a2l_list_015_2(g2l) -> None:
    """R-A2L-LIST.015/2: the same for ``CURVE_0071``."""
    assert g2l["rows"][10][3:] == [""] * 6 and g2l["rows"][10][1] == "✗ CURVE_0071"


def test_r_a2l_list_016_1(g2l) -> None:
    """R-A2L-LIST.016/1: the summary under the table."""
    assert g2l["summary"] == "LIST  rows 1-12 / 12 in pasted order"


async def _page_two(app, pilot, names) -> list:
    await set_filter(app, pilot, ", ".join(names[:250]))
    first = summary(app)
    await press(app, pilot, "#a2l_page_next_button")
    return [first, summary(app), len(table_rows(app)), table_labels(app)]


def test_r_a2l_list_016_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.016/2: 250 names, page 2 -> ``LIST  rows 201-250 / 250 in pasted order``."""
    first, second, n_rows, labels = run_a2l(tmp_path, case08, lambda a, p: _page_two(a, p, names))
    assert first == "LIST  rows 1-200 / 250 in pasted order"
    assert second == "LIST  rows 201-250 / 250 in pasted order" and n_rows == 50 and labels == LIST_COLUMNS


# ---------------------------------------------------------------------------
# The chips, the mode line, the missing line (.017 - .024)
# ---------------------------------------------------------------------------


def test_r_a2l_list_017_1(g2l, names) -> None:
    """R-A2L-LIST.017/1: `` LIST `` + the counts line."""
    assert g2l["chips"][0] == " LIST   " + oracle_counts(g2l_rows(names))


def test_r_a2l_list_017_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.017/2: mode Invalid (image + A2L) -> the nine found names are hidden by mode."""
    async def sc(app, pilot):
        await press(app, pilot, "#a2l_filter_invalid")
        await set_filter(app, pilot, G2L_JOINED)
        return chips(app)

    lines = run_a2l(tmp_path, case08, sc)
    hidden = set(G2L_NAMES) & set(names)
    assert lines[0] == " LIST   " + oracle_counts(oracle_rows(G2L_NAMES, set(names), hidden))
    assert lines[0].endswith("= 1 duplicate  ·  ◐ 9 hidden by mode")


def test_r_a2l_list_018_1(g2l, names) -> None:
    """R-A2L-LIST.018/1: ``order`` + the ribbon (budget 80) + the key hints."""
    assert g2l["chips"][1] == "order " + oracle_ribbon(g2l_rows(names), 80) + LIST_FOOT


def test_r_a2l_list_018_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.018/2: 100 names -> 80 unspaced glyphs and `` +20``."""
    async def sc(app, pilot):
        await set_filter(app, pilot, ", ".join(names[:100]))
        return chips(app)

    assert run_a2l(tmp_path, case08, sc)[1] == "order " + "●" * 80 + " +20" + LIST_FOOT


def _text_chip(case08, tmp_path, text: str, field: str = "name") -> list:
    async def sc(app, pilot):
        app._set_a2l_filter_field(field)
        await set_filter(app, pilot, text)
        return chips(app)

    return run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_019_1(case08, names, tmp_path) -> None:
    """R-A2L-LIST.019/1: ``VALUE`` in name -> `` TEXT   'VALUE' in name  ·  showing <n> of 462``."""
    n = sum(1 for x in names if "value" in x.lower())
    line = _text_chip(case08, tmp_path, "VALUE")[0]
    assert line == f" TEXT   'VALUE' in name  ·  showing {n} of {len(names)}" + TEXT_FOOT


def test_r_a2l_list_019_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.019/2: no filter text."""
    line = _text_chip(case08, tmp_path, "")[0]
    assert line == f" TEXT   no text filter  ·  showing {len(names)} of {len(names)}" + TEXT_FOOT


def test_r_a2l_list_019_3(case08, names, tmp_path) -> None:
    """R-A2L-LIST.019/3 (E3S-02): 300 characters with NUL and TAB, field ``unit`` -> its short text."""
    text = "".join("\x00" if i == 10 else "\t" if i == 20 else "k" for i in range(300))
    line = _text_chip(case08, tmp_path, text, "unit")[0]
    shown = text[:63].replace("\x00", "�").replace("\t", "�") + "…"
    assert line.startswith(f" TEXT   '{shown}' in unit  ·  showing 0 of {len(names)}")


def test_r_a2l_list_020_1(g2l, names) -> None:
    """R-A2L-LIST.020/1: list mode, mode All -> ``mode All · no tag hidden by mode (462 tags)``."""
    assert f"mode All · no tag hidden by mode ({len(names)} tags)" in g2l["chips"]


def test_r_a2l_list_020_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.020/2: text mode, mode All -> the same line."""
    assert f"mode All · no tag hidden by mode ({len(names)} tags)" in _text_chip(case08, tmp_path, "VALUE")


def _mode_line(case08, tmp_path, button: str, image: bool) -> list:
    async def sc(app, pilot):
        await press(app, pilot, button)
        await set_filter(app, pilot, "VALUE")
        return chips(app), sum(1 for t in app._a2l_enriched_tags if t.get("in_memory"))

    return run_a2l(tmp_path, case08, sc, image=image)


def test_r_a2l_list_021_1(case08, names, tmp_path) -> None:
    """R-A2L-LIST.021/1: Invalid -> ``mode Invalid · hides 462 of 462 tags  alt+a All``."""
    lines, _ = _mode_line(case08, tmp_path, "#a2l_filter_invalid", True)
    assert f"mode Invalid · hides {len(names)} of {len(names)} tags  alt+a All" in lines


def test_r_a2l_list_021_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.021/2: In-Memory, image + A2L -> hides the tags not in the image."""
    lines, in_image = _mode_line(case08, tmp_path, "#a2l_filter_inmem", True)
    assert f"mode In-memory · hides {len(names) - in_image} of {len(names)} tags  alt+a All" in lines


def test_r_a2l_list_021_3(case08, names, tmp_path) -> None:
    """R-A2L-LIST.021/3: In-Memory, A2L only -> hides all of them."""
    lines, _ = _mode_line(case08, tmp_path, "#a2l_filter_inmem", False)
    assert f"mode In-memory · hides {len(names)} of {len(names)} tags  alt+a All" in lines


def test_r_a2l_list_022_1(g2l, names) -> None:
    """R-A2L-LIST.022/1: the missing line of the G2 list."""
    assert g2l["missing"] == oracle_missing(g2l_rows(names))


def test_r_a2l_list_022_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.022/2: a list with no missing and no duplicate."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE_0002 CURVE_0001 MAP_0003")
        return missing_text(app)

    assert run_a2l(tmp_path, case08, sc) == "Missing 0     Duplicates 0 "


def test_r_a2l_list_023_1(case08, tmp_path) -> None:
    """R-A2L-LIST.023/1: text mode shows no missing line."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE")
        return app.query_one("#a2l_list_missing").display

    assert run_a2l(tmp_path, case08, sc) is False


def test_r_a2l_list_023_2(case08, tmp_path) -> None:
    """R-A2L-LIST.023/2 (E3A-08): after an unload the outgoing list's missing line is gone."""
    assert run_a2l(tmp_path, case08, _list_then_unload)["missing"] is False


def _missing_line(case08, tmp_path, text: str) -> str:
    async def sc(app, pilot):
        await set_filter(app, pilot, text)
        return missing_text(app)

    return run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_024_1(case08, names, tmp_path) -> None:
    """R-A2L-LIST.024/1: 25 missing names -> 20 listed + `` +5``."""
    want = [f"NOSUCH_{i:03d}" for i in range(25)]
    line = _missing_line(case08, tmp_path, ", ".join(want))
    assert line == oracle_missing(oracle_rows(want, set(names))) and " +5" in line


def test_r_a2l_list_024_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.024/2: the 4,906-name hostile paste -> ``+1616`` missing and ``+2942`` duplicates."""
    pasted = build_paste(names).split("\n")
    line = _missing_line(case08, tmp_path, ", ".join(pasted))
    assert line == oracle_missing(oracle_rows(pasted, set(names)))
    assert " +1616" in line and " +2942" in line


def _no_match(case08, tmp_path, text: str, field: str = "name", button="#a2l_filter_inmem") -> str:
    async def sc(app, pilot):
        await press(app, pilot, button)
        await set_filter(app, pilot, text)
        return summary(app)

    return run_a2l(tmp_path, case08, sc, image=False)


def test_r_a2l_list_025_1(case08, tmp_path) -> None:
    """R-A2L-LIST.025/1: ``VALUE_0002`` with In-Memory (A2L only) -> 1 match with mode All."""
    assert _no_match(case08, tmp_path, "VALUE_0002") == (
        "No tag matches 'VALUE_0002' with mode In-memory — 1 match with mode All alt+a")


def test_r_a2l_list_025_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.025/2: ``VALUE`` -> the count of names holding it."""
    n = sum(1 for x in names if "value" in x.lower())
    assert _no_match(case08, tmp_path, "VALUE") == (
        f"No tag matches 'VALUE' with mode In-memory — {n} match with mode All alt+a")


def test_r_a2l_list_025_3(case08, tmp_path) -> None:
    """R-A2L-LIST.025/3 (E3S-02, E3S-R2): a 300-character name with NUL and ESC -> short text in both summaries."""
    hostile = "".join("\x00" if i == 10 else "\x1b" if i == 20 else "h" for i in range(300))
    shown = hostile[:63].replace("\x00", "�").replace("\x1b", "�") + "…"

    async def sc(app, pilot):
        row = dict(app._a2l_enriched_tags[0], name=hostile, in_memory=False)
        app._a2l_enriched_tags = [row]
        await press(app, pilot, "#a2l_filter_inmem")
        await set_filter(app, pilot, hostile)
        first = summary(app)
        app._a2l_enriched_tags = [dict(row, name="other")]
        await press(app, pilot, "#a2l_filter_all")
        return first, summary(app)

    first, second = run_a2l(tmp_path, case08, sc, image=False)
    assert first == f"No tag matches '{shown}' with mode In-memory — 1 match with mode All alt+a"
    assert second == f"No A2L tags match '{shown}'."


def _alt_a(case08, tmp_path, button: str) -> str:
    async def sc(app, pilot):
        await press(app, pilot, button)
        assert app.a2l_tags_filter_mode != "all"
        app.query_one("#a2l_tags_filter_input", Input).focus()
        await pilot.press("alt+a")
        await flush(app, pilot)
        return app.a2l_tags_filter_mode, app.query_one("#a2l_filter_all").has_class("-on")

    return run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_026_1(case08, tmp_path) -> None:
    """R-A2L-LIST.026/1: alt+a from Invalid -> mode ``all``, ``All`` marked active."""
    assert _alt_a(case08, tmp_path, "#a2l_filter_invalid") == ("all", True)


def test_r_a2l_list_026_2(case08, tmp_path) -> None:
    """R-A2L-LIST.026/2: alt+a from In-Memory -> mode ``all``."""
    assert _alt_a(case08, tmp_path, "#a2l_filter_inmem") == ("all", True)


# ---------------------------------------------------------------------------
# The detail card, the jump, Esc, the write route (.027 - .036, .085/2)
# ---------------------------------------------------------------------------


def card_text(app) -> str:
    return static_text(app.query_one("#a2l_detail_card"))


async def highlight(app, pilot, row: int) -> None:
    table = app.query_one("#a2l_tags_list", DataTable)
    table.focus()
    table.move_cursor(row=row - 1)
    await settle(pilot)
    await settle_workers(pilot)
    await settle(pilot)


def shipped_card(app, name: str) -> str:
    from s19_app.tui.app.shared import _a2l_detail_card_text

    return plain(_a2l_detail_card_text(tag_by_name(app)[name]))


def test_r_a2l_list_027_1(case08, tmp_path) -> None:
    """R-A2L-LIST.027/1: a missing row's card -> ``✗ MAP_0024  not in this A2L`` and ``pasted #7``."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        await highlight(app, pilot, 7)
        return card_text(app)

    text = run_a2l(tmp_path, case08, sc)
    assert "✗ MAP_0024  not in this A2L" in text and "pasted #7" in text and "Highlight a tag" not in text


def test_r_a2l_list_028_1(case08, names, tmp_path) -> None:
    """R-A2L-LIST.028/1: ``VALUE_002`` missing -> ``closest`` + its 3 ranked names."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE_0002, VALUE_002")
        await highlight(app, pilot, 2)
        return card_text(app)

    want = " · ".join(m.name for m in rank("VALUE_002", build_label_index(names), 3))
    assert f"closest {want}" in run_a2l(tmp_path, case08, sc) and want.startswith("VALUE_0020")


def test_r_a2l_list_028_2(case08, tmp_path) -> None:
    """R-A2L-LIST.028/2: ``MAP_0024`` has no ranked name -> ``closest —``."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        await highlight(app, pilot, 7)
        return card_text(app)

    assert "closest —" in run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_029_1(case08, tmp_path) -> None:
    """R-A2L-LIST.029/1: a duplicate row's card = the tag's card + ``duplicate of pasted #1``; row 1 has none."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        await highlight(app, pilot, 10)
        dup = card_text(app)
        await highlight(app, pilot, 1)
        return dup, card_text(app), shipped_card(app, "VALUE_0002")

    dup, first, shipped = run_a2l(tmp_path, case08, sc)
    assert shipped in dup and "duplicate of pasted #1" in dup and "duplicate of pasted" not in first


def test_r_a2l_list_030_1(case08, tmp_path) -> None:
    """R-A2L-LIST.030/1: a hidden row's card = the tag's card + ``hidden by the active filter mode``."""
    async def sc(app, pilot):
        await press(app, pilot, "#a2l_filter_invalid")
        await set_filter(app, pilot, G2L_JOINED)
        await highlight(app, pilot, 1)
        return card_text(app), shipped_card(app, "VALUE_0002")

    text, shipped = run_a2l(tmp_path, case08, sc)
    assert shipped in text and "hidden by the active filter mode" in text


async def _enter_row(app, pilot, log, row: int) -> tuple:
    table = app.query_one("#a2l_tags_list", DataTable)
    table.focus()
    table.move_cursor(row=row - 1)
    await settle(pilot)
    mark, hexview = len(log.messages), static_text(app.query_one("#alt_hex_view"))
    await pilot.press("enter")
    await settle(pilot)
    return log.since(mark), hexview, static_text(app.query_one("#alt_hex_view"))


def _jump(case08, tmp_path, row: int, name: str | None, mode: str | None = None):
    async def sc(app, pilot):
        log = projects.StatusLog(app)
        if mode:
            await press(app, pilot, mode)
        await set_filter(app, pilot, G2L_JOINED)
        sent, before, after = await _enter_row(app, pilot, log, row)
        want = None if name is None else f"Tag at 0x{tag_by_name(app)[name]['address']:08X}"
        return sent, want, before, after

    return run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_031_1(case08, tmp_path) -> None:
    """R-A2L-LIST.031/1: enter on #3 ``MAP_0003`` -> ``Tag at 0x...`` of that tag (row key not the position)."""
    sent, want, before, after = _jump(case08, tmp_path, 3, "MAP_0003")
    assert want in sent and before != after


def test_r_a2l_list_031_2(case08, tmp_path) -> None:
    """R-A2L-LIST.031/2: enter on the duplicate #10 -> ``VALUE_0002``'s address."""
    sent, want, _, _ = _jump(case08, tmp_path, 10, "VALUE_0002")
    assert want in sent


def test_r_a2l_list_031_3(case08, tmp_path) -> None:
    """R-A2L-LIST.031/3: enter on a hidden row #1 (mode Invalid) -> its address."""
    sent, want, _, _ = _jump(case08, tmp_path, 1, "VALUE_0002", "#a2l_filter_invalid")
    assert want in sent


def test_r_a2l_list_031_4(case08, tmp_path) -> None:
    """R-A2L-LIST.031/4 (E3A-13): enter on the missing row #7 -> no status line, the hex pane unchanged."""
    sent, _, before, after = _jump(case08, tmp_path, 7, None)
    assert not any(m.startswith("Tag at") for m in sent) and before == after


def test_r_a2l_list_032_1(case08, tmp_path) -> None:
    """R-A2L-LIST.032/1: Esc in the filter box (no dropdown) on a list -> filter ``''``, text mode, 462 tags."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        box = app.query_one("#a2l_tags_filter_input", Input)
        box.focus()
        await pilot.press("escape")
        await flush(app, pilot)
        return box.value, mode_tag(app), summary(app)

    value, tag, text = run_a2l(tmp_path, case08, sc)
    assert value == "" and tag == "FILTER" and "/ 462" in text


@pytest.mark.serial_timing
def test_r_a2l_list_035_1(tmp_path) -> None:
    """R-A2L-LIST.035/1: a 2,048-name list over 13,990 tags paints within 1.0 s of the debounce (median of 3)."""
    import shutil

    from tests.support.b103_label_list import build_paste, case_names

    folder = tmp_path / "swa"
    folder.mkdir()
    shutil.copy(REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l", folder / "firmware.a2l")
    text = build_paste(case_names(folder)).replace("\n", ", ")

    async def sc(app, pilot):
        box = app.query_one("#a2l_tags_filter_input", Input)
        times = []
        for _ in range(3):
            box.value = ""
            await flush(app, pilot)
            start = time.perf_counter()
            box.value = text
            await wait_until(
                pilot, lambda: chips(app)[0].startswith(" LIST ") and missing_text(app).startswith("Missing "),
                "the list-mode table, counts and missing lines", timeout=30,
            )
            times.append(time.perf_counter() - start - 0.15)
        return statistics.median(times), len(app._a2l_enriched_tags)

    print("load average before:", os.getloadavg())
    median, n_tags = run_a2l(tmp_path, folder, sc, image=False)
    print(f"{n_tags} tags, median {median:.3f} s, load average after: {os.getloadavg()}")
    assert n_tags == 13990 and median <= timing_bound(1.0)


def test_r_a2l_list_036_1(case08, tmp_path) -> None:
    """R-A2L-LIST.036/1: a resize 118 -> 80 -> 118 keeps the list-mode columns and rows."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        out = []
        for width in (80, 118):
            await pilot.resize_terminal(width, 54)
            await settle(pilot, 10)
            out.append((table_labels(app), table_rows(app)[0][0], len(table_rows(app))))
        return out

    assert run_a2l(tmp_path, case08, sc) == [(LIST_COLUMNS, "1", 12)] * 2


def test_r_a2l_list_036_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.036/2: a page change (250 names) keeps the columns and writes the second page summary."""
    _, second, n_rows, labels = run_a2l(tmp_path, case08, lambda a, p: _page_two(a, p, names))
    assert second == "LIST  rows 201-250 / 250 in pasted order" and labels == LIST_COLUMNS and n_rows == 50


def _flip_and_write(app, name: str) -> None:
    """Change one image byte under ``name`` and run the in-place write route's A2L refresh."""
    tag = tag_by_name(app)[name]
    mem = app.current_file.mem_map
    mem[tag["address"]] = mem.get(tag["address"], 0) ^ 0xFF
    app._refresh_a2l_values_after_write()


def test_r_a2l_list_036_3(case08, tmp_path) -> None:
    """R-A2L-LIST.036/3 (E3A-07): the in-place write with a missing and a duplicate row updates Physical, no clear."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        old = table_rows(app)[0][6]
        _flip_and_write(app, "VALUE_0002")
        await settle(pilot, 10)
        rows = table_rows(app)
        fresh = text_cells(app, tag_by_name(app)["VALUE_0002"])["Physical"]
        return table_labels(app), rows, old, fresh

    labels, rows, old, fresh = run_a2l(tmp_path, case08, sc)
    assert labels == LIST_COLUMNS and len(rows) == 12 and old != fresh
    assert rows[0][6] == fresh and rows[9][6] == fresh


def _scrolled_write(case08, names, tmp_path, *, first_row: int | None, cursor_row: int | None):
    pasted = names[:249] + ["NOSUCH_000"]

    async def sc(app, pilot):
        await set_filter(app, pilot, ", ".join(pasted))
        table = app.query_one("#a2l_tags_list", DataTable)
        table.focus()
        if first_row:
            table.scroll_to(y=first_row - 1, animate=False)
        if cursor_row:
            table.move_cursor(row=cursor_row - 1, animate=False)
        await settle(pilot)
        before = (table.scroll_y, table.cursor_row, table_rows(app)[table.cursor_row][1])
        _flip_and_write(app, names[1])
        await settle(pilot, 10)
        return before, (table.scroll_y, table.cursor_row, table_rows(app)[table.cursor_row][1]), card_text(app)

    return run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_036_4(case08, names, tmp_path) -> None:
    """R-A2L-LIST.036/4 (E3A-07): with row 30 the first shown row, the in-place write keeps it (R-A2L-049/1)."""
    before, after, _ = _scrolled_write(case08, names, tmp_path, first_row=30, cursor_row=None)
    assert before[0] >= 29 and after[0] == before[0]


def test_r_a2l_list_036_5(case08, names, tmp_path) -> None:
    """R-A2L-LIST.036/5 (E3A-07): with the cursor on row 40 it stays there and the card names that entry."""
    before, after, card = _scrolled_write(case08, names, tmp_path, first_row=None, cursor_row=40)
    assert after[1] == before[1] == 39 and after[2] == before[2] and after[2][2:] in card


def test_r_a2l_list_085_2(case08, monkeypatch, tmp_path) -> None:
    """R-A2L-LIST.085/2: the card's closest-names ranking released after teardown paints nothing; live it paints."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def live(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        app.query_one("#a2l_tags_list", DataTable).move_cursor(row=6)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the card's ranking started")
        spy.gate.set()
        await wait_until(pilot, lambda: "closest —" in card_text(app), "the closest line painted")
        return True

    assert run_a2l(tmp_path, case08, live)
    held = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", held)
    seen: list = []

    async def go():
        from s19_app.tui.app import S19TuiApp
        from tests.support.b103_label_list import open_a2l

        app = S19TuiApp(base_dir=tmp_path / "b")
        seen.extend(capture_workers(app, monkeypatch))
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            await open_a2l(app, pilot, case08)
            await set_filter(app, pilot, G2L_JOINED)
            app.query_one("#a2l_tags_list", DataTable).move_cursor(row=6)
            await wait_until(pilot, lambda: held.entered.is_set(), "the card's ranking started")
        await release_after_close([held])
        return app

    app = asyncio.run(go())
    assert app._exception is None and worker_errors(seen) == []


# ---------------------------------------------------------------------------
# Canon rows in text mode and the layout rows
# ---------------------------------------------------------------------------


def _text_mode(case08, tmp_path, text: str, field: str = "name", mode=None):
    async def sc(app, pilot):
        app._set_a2l_filter_field(field)
        if mode:
            await press(app, pilot, mode)
        await set_filter(app, pilot, text)
        return (len(app._a2l_filtered_tags), summary(app), app._a2l_list_names(), list(app._a2l_enriched_tags))

    return run_a2l(tmp_path, case08, sc)


def test_r_a2l_007_1_1(case08, names, tmp_path) -> None:
    """R-A2L-007.1/1: ``value_00`` shows the tags whose name holds it, ignoring case."""
    count, _, listed, _ = _text_mode(case08, tmp_path, "value_00")
    assert count == sum(1 for n in names if "value_00" in n.lower()) > 0 and listed is None


def test_r_a2l_007_1_2(case08, tmp_path) -> None:
    """R-A2L-007.1/2: ``cuvre_00`` -> 0 rows."""
    count, text, _, _ = _text_mode(case08, tmp_path, "cuvre_00")
    assert count == 0 and text == "No A2L tags match 'cuvre_00'."


def test_r_a2l_007_2_1(case08, tmp_path) -> None:
    """R-A2L-007.2/1: ``synthetic`` in field ``all`` -> the tags whose description holds it (one name: text mode)."""
    count, _, listed, tags = _text_mode(case08, tmp_path, "synthetic", "all")
    want = sum(1 for t in tags if "synthetic" in str(t.get("description") or "").lower())
    assert count == want > 0 and listed is None


def test_r_a2l_007_6_1(case08, names, tmp_path) -> None:
    """R-A2L-007.6/1: ``All`` in text mode shows every tag."""
    assert _text_mode(case08, tmp_path, "", mode="#a2l_filter_all")[0] == len(names)


def test_r_a2l_007_7_1(case08, tmp_path) -> None:
    """R-A2L-007.7/1: ``Invalid`` in text mode -> only red rows (none in case 08)."""
    assert _text_mode(case08, tmp_path, "", mode="#a2l_filter_invalid")[0] == 0


def test_r_a2l_007_8_1(case08, tmp_path) -> None:
    """R-A2L-007.8/1: ``In-Memory`` in text mode -> only the tags in the image."""
    count, _, _, tags = _text_mode(case08, tmp_path, "", mode="#a2l_filter_inmem")
    assert count == sum(1 for t in tags if t.get("in_memory")) > 0


def test_r_tui_042a_4_1(case08, tmp_path) -> None:
    """R-TUI-042a.4/1: back to text mode -> the 16 shipped columns, Address and Length first and fixed."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        assert table_labels(app) == LIST_COLUMNS
        await set_filter(app, pilot, "")
        return table_labels(app), app.query_one("#a2l_tags_list", DataTable).fixed_columns

    labels, fixed = run_a2l(tmp_path, case08, sc)
    assert labels == TEXT_COLUMNS and fixed == 2


def _regions(app) -> dict:
    ids = ("#a2l_panes", "#a2l_tags_pane", "#a2l_hex_pane", "#a2l_detail_card", "#alt_hex_scroll",
           "#alt_hex_view", "#a2l_tags_list")
    return {i: app.query_one(i).region for i in ids}


def _layout(case08, tmp_path, size, scenario=None):
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        await settle(pilot, 10)
        out = {"regions": _regions(app), "classes": set(app.query_one("#a2l_panes").classes)}
        if scenario:
            out["extra"] = await scenario(app, pilot)
        return out

    return run_a2l(tmp_path, case08, sc, size=size)


def test_r_tui_069_6_1(case08, tmp_path) -> None:
    """R-TUI-069.6/1: at 220x60 the card is at most 8 lines, above the hex view."""
    r = _layout(case08, tmp_path, (220, 60))["regions"]
    assert r["#a2l_detail_card"].height <= 8 and r["#a2l_detail_card"].bottom <= r["#alt_hex_scroll"].y


async def _long_card(app, pilot) -> tuple:
    card = app.query_one("#a2l_detail_card")
    card.update("\n".join(f"card line {i}" for i in range(card.size.height + 4)))
    await settle(pilot, 4)
    top = card.max_scroll_y
    card.scroll_down(animate=False)
    await settle(pilot, 4)
    return top, card.scroll_y


def test_r_tui_069_7_1(case08, tmp_path) -> None:
    """R-TUI-069.7/1 (E3A-11): wide body (220x60) -> the long card scrolls."""
    top, moved = _layout(case08, tmp_path, (220, 60), _long_card)["extra"]
    assert top >= 1 and moved >= 1


def test_r_tui_069_7_2(case08, tmp_path) -> None:
    """R-TUI-069.7/2 (E3A-11): stacked body (118x54) -> the long card scrolls."""
    top, moved = _layout(case08, tmp_path, (118, 54), _long_card)["extra"]
    assert top >= 1 and moved >= 1


def test_r_tui_069_7_3(case08, tmp_path) -> None:
    """R-TUI-069.7/3 (E3A-11): short body (120x30) -> the long card scrolls."""
    top, moved = _layout(case08, tmp_path, (120, 30), _long_card)["extra"]
    assert top >= 1 and moved >= 1


def _split(case08, tmp_path, size) -> tuple:
    r = _layout(case08, tmp_path, size)["regions"]
    return r["#a2l_tags_pane"].width, r["#a2l_hex_pane"].width, r["#a2l_hex_pane"].x >= r["#a2l_tags_pane"].right


def test_r_tui_037_1_1(case08, tmp_path) -> None:
    """R-TUI-037.1/1: 80x24 -> the tags pane 42 of the 74-column body (P3)."""
    assert _split(case08, tmp_path, (80, 24))[0] == 42


def test_r_tui_037_1_2(case08, tmp_path) -> None:
    """R-TUI-037.1/2: 120x30 -> 54 of 96."""
    assert _split(case08, tmp_path, (120, 30))[0] == 54


def test_r_tui_037_1_3(case08, tmp_path) -> None:
    """R-TUI-037.1/3: 160x40 -> 77 of 136."""
    assert _split(case08, tmp_path, (160, 40))[0] == 77


def test_r_tui_037_2_1(case08, tmp_path) -> None:
    """R-TUI-037.2/1: 80x24 -> the hex pane 32, right of the tags pane."""
    _, hex_w, right = _split(case08, tmp_path, (80, 24))
    assert hex_w == 32 and right


def test_r_tui_037_2_2(case08, tmp_path) -> None:
    """R-TUI-037.2/2: 120x30 -> 42, right of the tags pane."""
    _, hex_w, right = _split(case08, tmp_path, (120, 30))
    assert hex_w == 42 and right


def test_r_tui_037_2_3(case08, tmp_path) -> None:
    """R-TUI-037.2/3: 160x40 -> 59, right of the tags pane."""
    _, hex_w, right = _split(case08, tmp_path, (160, 40))
    assert hex_w == 59 and right


def test_r_a2l_list_080_1(case08, tmp_path) -> None:
    """R-A2L-LIST.080/1: 118x54 (stacked) -> the hex pane 14 rows high under the tags pane."""
    out = _layout(case08, tmp_path, (118, 54))
    r = out["regions"]
    assert "-wide" not in out["classes"] and "-short" not in out["classes"]
    assert r["#a2l_hex_pane"].height == 14 and r["#a2l_hex_pane"].y >= r["#a2l_tags_pane"].bottom


async def _hex_rows(app, pilot) -> tuple:
    app._jump_to_tag_by_data(tag_by_name(app)["MAP_0003"])
    await settle(pilot, 10)
    view = app.query_one("#alt_hex_view")
    lines = [strip.text.rstrip() for strip in view.render_lines(view.region.reset_offset)]
    rows = [line for line in lines if line.startswith("  0x")]
    return view.content_region.width, rows


def test_r_a2l_list_080_2(case08, tmp_path) -> None:
    """R-A2L-LIST.080/2: every painted hex row is whole on one line at 118x54 (the 81-character row)."""
    width, rows = _layout(case08, tmp_path, (118, 54), _hex_rows)["extra"]
    assert width >= 81 and rows and all(len(r) >= 81 and r.endswith("|") for r in rows)


def test_r_a2l_list_081_1(case08, tmp_path) -> None:
    """R-A2L-LIST.081/1: 220x60 -> the tags pane left of a 90-column hex pane."""
    out = _layout(case08, tmp_path, (220, 60))
    r = out["regions"]
    assert "-wide" in out["classes"] and r["#a2l_hex_pane"].width == 90
    assert r["#a2l_hex_pane"].x >= r["#a2l_tags_pane"].right


def _card_cap(case08, tmp_path, size) -> bool:
    r = _layout(case08, tmp_path, size)["regions"]
    return r["#a2l_detail_card"].height <= 5 and r["#a2l_detail_card"].bottom <= r["#alt_hex_scroll"].y


def test_r_a2l_list_082_1(case08, tmp_path) -> None:
    """R-A2L-LIST.082/1: 120x30 (short body) -> the card at most 5 lines, above the hex view."""
    assert _card_cap(case08, tmp_path, (120, 30))


def test_r_a2l_list_082_2(case08, tmp_path) -> None:
    """R-A2L-LIST.082/2: 80x54 (short body) -> the same."""
    assert _card_cap(case08, tmp_path, (80, 54))


def _table_rows_shown(case08, tmp_path, size) -> int:
    async def shown(app, pilot):
        table = app.query_one("#a2l_tags_list", DataTable)
        return table.size.height - table.header_height

    return _layout(case08, tmp_path, size, shown)["extra"]


def test_r_a2l_list_083_1(case08, tmp_path) -> None:
    """R-A2L-LIST.083/1 (E3A-10, measured P4): 120x30 list mode -> at least 1 table row."""
    assert _table_rows_shown(case08, tmp_path, (120, 30)) >= 1


def test_r_a2l_list_083_2(case08, tmp_path) -> None:
    """R-A2L-LIST.083/2: 160x40 -> at least 11 rows."""
    assert _table_rows_shown(case08, tmp_path, (160, 40)) >= 11


def test_r_a2l_list_083_3(case08, tmp_path) -> None:
    """R-A2L-LIST.083/3: 118x54 -> at least 11 rows."""
    assert _table_rows_shown(case08, tmp_path, (118, 54)) >= 11


# ---------------------------------------------------------------------------
# The paste window opened from the viewer (.040 - .056)
# ---------------------------------------------------------------------------


def window(app):
    """The paste window when it is the top screen, else ``None``."""
    import s19_app.tui.a2l_label_list as mod

    return app.screen if isinstance(app.screen, mod.LabelListPasteModal) else None


async def open_window(app, pilot, how: str = "key") -> object:
    if how == "key":
        app.query_one("#a2l_tags_list", DataTable).focus()
        await pilot.press("alt+p")
    else:
        app.query_one("#a2l_paste_list_button", Button).press()
    await wait_until(pilot, lambda: window(app) is not None, "the paste window opened")
    await settle(pilot, 4)
    return window(app)


def titles(modal) -> list:
    return [static_text(w) for w in modal.query("Static, Label")]


def test_r_a2l_list_040_1(case08, tmp_path) -> None:
    """R-A2L-LIST.040/1: alt+p with the focus in the tag table opens ``Paste a list of labels``."""
    async def sc(app, pilot):
        return titles(await open_window(app, pilot))

    assert "Paste a list of labels" in run_a2l(tmp_path, case08, sc)


def test_r_a2l_list_040_2(case08, tmp_path) -> None:
    """R-A2L-LIST.040/2: the ``Paste list…  alt+p`` button opens it."""
    async def sc(app, pilot):
        label = plain(app.query_one("#a2l_paste_list_button", Button).label)
        return label, titles(await open_window(app, pilot, "button"))

    label, found = run_a2l(tmp_path, case08, sc)
    assert label == "Paste list…  alt+p" and "Paste a list of labels" in found


def test_r_a2l_list_041_1(case08, tmp_path) -> None:
    """R-A2L-LIST.041/1: opened in list mode -> the text area holds the pasted names, one per line."""
    async def sc(app, pilot):
        await set_filter(app, pilot, G2L_JOINED)
        return (await open_window(app, pilot)).query_one("#a2l_list_text", TextArea).text

    text = run_a2l(tmp_path, case08, sc)
    assert text.split("\n")[:-1] == G2L_NAMES and text.endswith("\n")


def test_r_a2l_list_041_2(case08, tmp_path) -> None:
    """R-A2L-LIST.041/2: opened in text mode -> an empty text area."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE")
        return (await open_window(app, pilot)).query_one("#a2l_list_text", TextArea).text

    assert run_a2l(tmp_path, case08, sc) == ""


async def _apply(app, pilot, text: str, filter_before: str = "") -> tuple:
    if filter_before:
        await set_filter(app, pilot, filter_before)
    modal = await open_window(app, pilot)
    modal.query_one("#a2l_list_text", TextArea).text = text
    await pilot.pause(0.3)
    await pilot.press("alt+f")
    await settle(pilot, 6)
    await flush(app, pilot)
    return window(app), app.query_one("#a2l_tags_filter_input", Input).value


def test_r_a2l_list_053_1(case08, tmp_path) -> None:
    """R-A2L-LIST.053/1: alt+f with the G2 list closes the window and the viewer shows 12 list rows."""
    async def sc(app, pilot):
        open_after, value = await _apply(app, pilot, G2L_TEXT)
        return open_after, value, summary(app), mode_tag(app)

    open_after, value, text, tag = run_a2l(tmp_path, case08, sc)
    assert open_after is None and value == G2L_JOINED and "/ 12" in text and tag == "LIST"


def test_r_a2l_list_053_2(case08, tmp_path) -> None:
    """R-A2L-LIST.053/2: one name ``MAP_0003`` -> filter ``MAP_0003``, text mode, 1 row."""
    async def sc(app, pilot):
        _, value = await _apply(app, pilot, "MAP_0003")
        return value, mode_tag(app), len(app._a2l_filtered_tags)

    assert run_a2l(tmp_path, case08, sc) == ("MAP_0003", "FILTER", 1)


def test_r_a2l_list_054_1(case08, tmp_path) -> None:
    """R-A2L-LIST.054/1: alt+f with an empty text area keeps the filter ``VALUE``."""
    async def sc(app, pilot):
        open_after, value = await _apply(app, pilot, "", "VALUE")
        return open_after, value

    assert run_a2l(tmp_path, case08, sc) == (None, "VALUE")


def test_r_a2l_list_055_1(case08, tmp_path) -> None:
    """R-A2L-LIST.055/1: Esc with no dropdown closes the window and keeps the filter text."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE")
        modal = await open_window(app, pilot)
        modal.query_one("#a2l_list_text", TextArea).text = G2L_TEXT
        await pilot.pause(0.3)
        await pilot.press("escape")
        await settle(pilot, 6)
        return window(app), app.query_one("#a2l_tags_filter_input", Input).value

    assert run_a2l(tmp_path, case08, sc) == (None, "VALUE")


def test_r_a2l_list_055_2(case08, tmp_path) -> None:
    """R-A2L-LIST.055/2: the ``Cancel`` button closes the window and keeps the filter text."""
    async def sc(app, pilot):
        await set_filter(app, pilot, "VALUE")
        modal = await open_window(app, pilot)
        modal.query_one("#a2l_list_text", TextArea).text = G2L_TEXT
        await pilot.pause(0.3)
        modal.query_one("#a2l_list_cancel", Button).press()
        await settle(pilot, 6)
        return window(app), app.query_one("#a2l_tags_filter_input", Input).value

    assert run_a2l(tmp_path, case08, sc) == (None, "VALUE")


def _a2l_with_map_0024(case: Path, target: Path) -> Path:
    """A copy of case 08's A2L with one MEASUREMENT block duplicated under the name ``MAP_0024``."""
    import re

    text = (case / "firmware.a2l").read_text(encoding="utf-8")
    block = re.search(r"/begin MEASUREMENT (\S+)(.*?)/end MEASUREMENT", text, re.S)
    clone = block.group(0).replace(block.group(1), "MAP_0024")
    target.write_text(text[: block.end()] + "\n" + clone + text[block.end():], encoding="utf-8")
    return target


def test_r_a2l_list_056_1(case08, names, tmp_path) -> None:
    """R-A2L-LIST.056/1: an A2L transition while the window is open re-resolves it (10 found, 1 missing)."""
    other = _a2l_with_map_0024(case08, tmp_path / "other.a2l")

    async def sc(app, pilot):
        modal = await open_window(app, pilot)
        modal.query_one("#a2l_list_text", TextArea).text = G2L_TEXT
        await pilot.pause(0.3)
        app.load_a2l_from_path(other)
        await settle_workers(pilot)
        await settle(pilot, 6)
        return static_text(modal.query_one("#a2l_list_counts"))

    counts = run_a2l(tmp_path, case08, sc)
    assert oracle_counts(oracle_rows(G2L_NAMES, set(names) | {"MAP_0024"})) in counts
    assert "● 10 found" in counts and "✗ 1 missing" in counts


# ---------------------------------------------------------------------------
# The dropdown under the filter box, as the viewer drives it (.060, .062, .072, .074)
# ---------------------------------------------------------------------------


def suggest_lines(app) -> tuple:
    box = app.query_one("#a2l_filter_suggest")
    return box.is_open, static_text(box).split("\n")


async def type_and_wait(app, pilot, text: str) -> tuple:
    await set_filter(app, pilot, text)
    await wait_until(pilot, lambda: suggest_lines(app)[0], "the dropdown opened", timeout=15)
    return suggest_lines(app)


def test_r_a2l_list_060_1(case08, names, tmp_path) -> None:
    """R-A2L-LIST.060/1: ``0017`` -> the dropdown with 5 rows, ``MAP_0017`` first."""
    async def sc(app, pilot):
        return await type_and_wait(app, pilot, "0017")

    _, lines = run_a2l(tmp_path, case08, sc)
    want = [m.name for m in rank("0017", build_label_index(names), 20)]
    assert len(want) == 5 and lines[1].startswith("▸ " + want[0]) and want[0] == "MAP_0017"
    assert all(n in "\n".join(lines) for n in want)


def test_r_a2l_list_060_2(case08, names, tmp_path) -> None:
    """R-A2L-LIST.060/2: ``cuvre_00`` -> 8 rows, ``CURVE_0001`` first."""
    async def sc(app, pilot):
        return await type_and_wait(app, pilot, "cuvre_00")

    _, lines = run_a2l(tmp_path, case08, sc)
    assert lines[0] == "8 of 20+ similar names" and lines[1].startswith("▸ CURVE_0001")


def test_r_a2l_list_060_3(case08, tmp_path) -> None:
    """R-A2L-LIST.060/3: ``map_002`` -> ``MAP_0020`` first, rule ``prefix``."""
    async def sc(app, pilot):
        return await type_and_wait(app, pilot, "map_002")

    _, lines = run_a2l(tmp_path, case08, sc)
    assert lines[1].startswith("▸ MAP_0020") and lines[1].rstrip().endswith("prefix")


def test_r_a2l_list_062_1(case08, tmp_path) -> None:
    """R-A2L-LIST.062/1: ``0017`` then cleared -> the dropdown closes."""
    async def sc(app, pilot):
        await type_and_wait(app, pilot, "0017")
        await set_filter(app, pilot, "")
        return suggest_lines(app)[0]

    assert run_a2l(tmp_path, case08, sc) is False


def test_r_a2l_list_062_2(case08, tmp_path) -> None:
    """R-A2L-LIST.062/2: ``0042 val`` (a list text) closes an open dropdown."""
    async def sc(app, pilot):
        await type_and_wait(app, pilot, "0017")
        await set_filter(app, pilot, "0042 val")
        return suggest_lines(app)[0], mode_tag(app)

    assert run_a2l(tmp_path, case08, sc) == (False, "LIST")


def test_r_a2l_list_072_1(case08, names, monkeypatch, tmp_path) -> None:
    """R-A2L-LIST.072/1: attaching case 08 prepares its 462 distinct names on a worker thread."""
    from tests.support.b103_label_list import open_a2l

    spy = Hold(real_seam("build_label_index"), block=False)
    patch_seam(monkeypatch, "build_label_index", spy)
    ui: list = []

    async def sc(app, pilot):
        import threading

        ui.append(threading.get_ident())
        await open_a2l(app, pilot, case08)
        await wait_until(pilot, lambda: app._a2l_label_ranker.ready, "the name list was prepared")
        return list(spy.calls[0][0])

    prepared_names = run_a2l(tmp_path, case08, sc, load=False)
    assert len(prepared_names) == len(set(names)) == 462 and set(prepared_names) == set(names)
    assert spy.threads and all(t != ui[0] for t in spy.threads)


def test_r_a2l_list_072_2(case08, monkeypatch, tmp_path) -> None:
    """R-A2L-LIST.072/2: unloading the A2L prepares an empty list (no names to suggest)."""
    spy = Hold(real_seam("build_label_index"), block=False)
    patch_seam(monkeypatch, "build_label_index", spy)

    async def sc(app, pilot):
        await wait_until(pilot, lambda: app._a2l_label_ranker.ready, "the name list was prepared")
        app._apply_unload("a2l")
        await settle_workers(pilot)
        await settle(pilot, 6)
        return len(spy.calls), len(spy.calls[-1][0])

    n_calls, last = run_a2l(tmp_path, case08, sc)
    assert n_calls >= 2 and last == 0


def test_r_a2l_list_074_1(case08, tmp_path, monkeypatch) -> None:
    """R-A2L-LIST.074/1: ``0017`` typed while the preparation is held -> the dropdown opens when it is released."""
    build = Hold(real_seam("build_label_index"))
    patch_seam(monkeypatch, "build_label_index", build)

    async def sc(app, pilot):
        app.load_a2l_from_path(case08 / "firmware.a2l")
        await wait_until(pilot, lambda: build.entered.is_set(), "the preparation started")
        app.action_show_screen("a2l")
        await settle(pilot, 4)
        app.query_one("#a2l_tags_filter_input", Input).value = "0017"
        await pilot.pause(0.4)
        assert not suggest_lines(app)[0], "the dropdown opened before the name list was ready"
        build.gate.set()
        await wait_until(pilot, lambda: suggest_lines(app)[0], "the held request painted", timeout=15)
        return suggest_lines(app)[1]

    lines = run_a2l(tmp_path, case08, sc, load=False)
    assert lines[0] == "5 of 5 similar names" and lines[1].startswith("▸ MAP_0017")
