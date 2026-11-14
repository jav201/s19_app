"""Inc 7 G-T-L: the list module and the I-1 paste hook (batch-103, E4 tester T7).

Cases: ``.dev-flow/2026-11-05-batch-103/inc-7/02-test-cases-L.md`` (105 cases, one test
each, the case id in the test name) plus a few I-7 interface checks. Expected values are
computed from the shipped parser (I-5), the shipped matcher (I-3) and case 08 (seed
20260001); the list text of the approved G2 scene is the only typed list. The module
under test is imported inside each test, so a base tree without it fails each test with
``ModuleNotFoundError`` instead of failing the collection. No test touches the OS
clipboard: ``read_os_clipboard`` is patched and the app clipboard is the seam.
"""
from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
from textual import events
from textual.app import App
from textual.widgets import Button, Input, Static, TextArea

from s19_app.tui.a2l_parameter_picker import parse_parameter_list
from s19_app.tui.os_clipboard_input import OsClipboardInput
from s19_app.tui.services.label_match import build_label_index, rank
from tests.support.b100_workers import settle_workers
from tests.support.b103_clipboard import P_CTRL, right_click_app_route, terminal_paste
from tests.support.b103_label_list import (
    G2L_JOINED,
    G2L_NAMES,
    G2L_TEXT,
    HOST_NAME,
    HOST_SHOWN,
    Hold,
    build_case08,
    capture_workers,
    case_names,
    case_tags,
    patch_seam,
    plain,
    real_seam,
    release_after_close,
    settle,
    static_text,
    worker_errors,
)
from tests.support.timing import timing_bound, wait_until

GLYPH = {"found": "●", "missing": "✗", "duplicate": "=", "hidden": "◐"}


@pytest.fixture(scope="module")
def case08(tmp_path_factory) -> Path:
    return build_case08(tmp_path_factory.mktemp("i7_l_case08"))


@pytest.fixture(scope="module")
def tags(case08) -> list:
    return case_tags(case08)


@pytest.fixture(scope="module")
def names(case08) -> list:
    return case_names(case08)


@pytest.fixture
def ll():
    import s19_app.tui.a2l_label_list as module

    return module


def resolve(ll, text_or_names, tags, hidden=None):
    items = parse_parameter_list(text_or_names) if isinstance(text_or_names, str) else text_or_names
    return ll.resolve_label_list(items, tags, hidden)


def statuses(res) -> list:
    return [e.status for e in res.entries]


# ---------------------------------------------------------------------------
# Resolving a list (.001 - .005)
# ---------------------------------------------------------------------------


def test_r_a2l_list_001_1(ll, tags) -> None:
    """R-A2L-LIST.001/1: the G2 list (9 lines, commas) -> 12 names in order."""
    res = resolve(ll, G2L_TEXT, tags)
    assert [e.name for e in res.entries] == G2L_NAMES and len(G2L_NAMES) == 12
    assert ll.is_list_text(G2L_TEXT) is True


def test_r_a2l_list_001_2(ll) -> None:
    """R-A2L-LIST.001/2: ``A;B  C\\r\\nD`` -> A, B, C, D."""
    res = resolve(ll, "A;B  C\r\nD", [])
    assert [e.name for e in res.entries] == ["A", "B", "C", "D"]
    assert ll.is_list_text("A;B  C\r\nD") is True


def test_r_a2l_list_001_3(ll) -> None:
    """R-A2L-LIST.001/3: ``' ,;\\n '`` -> 0 names (not a list text)."""
    assert resolve(ll, " ,;\n ", []).entries == ()
    assert ll.is_list_text(" ,;\n ") is False


def test_r_a2l_list_002_1(ll, tags, names) -> None:
    """R-A2L-LIST.002/1: G2L over case 08 -> found at #1-#6, #8, #9, #12."""
    res = resolve(ll, G2L_TEXT, tags)
    found = [e.pos for e in res.entries if e.status == ll.FOUND]
    assert found == [1, 2, 3, 4, 5, 6, 8, 9, 12]
    assert all(e.name in names for e in res.entries if e.status == ll.FOUND)


def test_r_a2l_list_002_2(ll, tags, names) -> None:
    """R-A2L-LIST.002/2: ``value_0002`` is missing (case kept)."""
    assert "VALUE_0002" in names
    assert statuses(resolve(ll, ["value_0002"], tags)) == [ll.MISSING]


def test_r_a2l_list_002_3(ll, tags) -> None:
    """R-A2L-LIST.002/3: ``VALUE_0002 `` with a trailing space is found (the parser trims)."""
    assert statuses(resolve(ll, "VALUE_0002 ", tags)) == [ll.FOUND]


def test_r_a2l_list_003_1(ll, tags) -> None:
    """R-A2L-LIST.003/1: G2L #10 ``VALUE_0002`` -> duplicate of #1."""
    entry = resolve(ll, G2L_TEXT, tags).entries[9]
    assert (entry.name, entry.status, entry.first_pos) == ("VALUE_0002", ll.DUPLICATE, 1)


def test_r_a2l_list_003_2(ll, tags, names) -> None:
    """R-A2L-LIST.003/2: ``X X X`` (no such tag) -> missing, then 2 duplicates of #1."""
    assert "X" not in names
    res = resolve(ll, "X X X", tags)
    assert statuses(res) == [ll.MISSING, ll.DUPLICATE, ll.DUPLICATE]
    assert [e.first_pos for e in res.entries] == [None, 1, 1]


def test_r_a2l_list_004_1(ll, tags, names) -> None:
    """R-A2L-LIST.004/1: G2L #7 ``MAP_0024`` is missing."""
    assert "MAP_0024" not in names
    assert resolve(ll, G2L_TEXT, tags).entries[6].status == ll.MISSING


def test_r_a2l_list_004_2(ll, tags, names) -> None:
    """R-A2L-LIST.004/2: G2L #11 ``CURVE_0071`` is missing."""
    assert "CURVE_0071" not in names
    assert resolve(ll, G2L_TEXT, tags).entries[10].status == ll.MISSING


def test_r_a2l_list_004_3(ll) -> None:
    """R-A2L-LIST.004/3: over no tag every first occurrence is missing (11 missing, 1 duplicate)."""
    res = resolve(ll, G2L_TEXT, [])
    assert (res.count(ll.MISSING), res.count(ll.DUPLICATE)) == (11, 1)


def test_r_a2l_list_005_1(ll, tags) -> None:
    """R-A2L-LIST.005/1: with a mode that leaves every tag out, the 9 found names are hidden."""
    res = resolve(ll, G2L_TEXT, tags, hidden=lambda tag: True)
    assert res.count(ll.HIDDEN) == 9 and res.count(ll.FOUND) == 0
    assert res.count(ll.MISSING) == 2 and res.count(ll.DUPLICATE) == 1


def test_r_a2l_list_005_2(ll, tags) -> None:
    """R-A2L-LIST.005/2: ``hidden`` is asked per tag, so a mode that keeps a tag shows it found."""
    keep = {t["name"] for t in tags if t["name"] == "VALUE_0002"}
    res = resolve(ll, G2L_TEXT, tags, hidden=lambda tag: tag["name"] not in keep)
    assert res.entries[0].status == ll.FOUND and res.count(ll.HIDDEN) == 8


# ---------------------------------------------------------------------------
# I-7 interface checks (resolution is pure, comparable, and its rows are the tags)
# ---------------------------------------------------------------------------


def test_i7_resolution_rows_are_the_tag_objects_and_equal_when_repeated(ll, tags) -> None:
    """I-7 / E3A-02, E3A-07: found, duplicate rows ARE the tag; a missing row is a fresh dict."""
    first, second = resolve(ll, G2L_TEXT, tags), resolve(ll, G2L_TEXT, tags)
    by_name = {t["name"]: t for t in tags}
    assert first.rows[0] is by_name["VALUE_0002"] and first.rows[9] is by_name["VALUE_0002"]
    assert first.rows[6] == {"name": "MAP_0024", "_list_pos": 7}
    assert first == second  # no RecursionError, value equality


def test_i7_display_text_never_raises_and_keeps_length(ll) -> None:
    """I-7: ``display_text`` replaces one for one and never raises for any ``str``."""
    for text in ("", "plain", HOST_NAME, "\ud800", "\x00" * 5, "é漢😀"):
        assert len(ll.display_text(text)) == len(text)
    assert ll.display_text(HOST_NAME) == HOST_SHOWN


def test_i7_list_row_cells_reads_text_cells_by_the_shipped_labels(ll) -> None:
    """I-7 / E3A-03 (e): a mapping that lacks ``Length`` raises ``KeyError``, not a blank cell."""
    from rich.text import Text

    entry = ll.LabelListEntry(1, "VALUE_0002", ll.FOUND, {"name": "VALUE_0002", "section": "S"}, None)
    cells = {k: Text(k) for k in ("Address", "Physical", "Unit", "Limits")}
    with pytest.raises(KeyError):
        ll.list_row_cells(entry, cells, "all")


# ---------------------------------------------------------------------------
# Paste routes into the filter box (host app: the box needs no G-V code)
# ---------------------------------------------------------------------------


class RestrictBox(OsClipboardInput):
    """A ``restrict`` box whose override would take every paste (R-PASTE.1/4)."""

    hook_calls: list = []

    def _take_paste(self, text: str) -> bool:
        type(self).hook_calls.append(text)
        return True


class PasteHost(App):
    """A stock box, a ``restrict`` box and the list-aware filter box."""

    def __init__(self, box_cls=None, with_filter: bool = True) -> None:
        super().__init__()
        self.field = "name"
        self.box_cls = box_cls
        self.with_filter = with_filter

    def compose(self):
        yield Button("other", id="other")
        yield OsClipboardInput(placeholder="load", id="plain")
        yield RestrictBox(placeholder="r", id="restr", restrict=r"[A-Za-z0-9_ ]*")
        if not self.with_filter:
            return
        import s19_app.tui.a2l_label_list as mod

        suggest = mod.LabelSuggestBox(accept="tab complete", id="a2l_filter_suggest")
        cls = self.box_cls or mod.ListAwareFilterInput
        yield cls(
            suggest=suggest, list_enabled=lambda: self.field in ("name", "all"),
            placeholder="f", id="a2l_tags_filter_input",
        )
        yield suggest


def drive_paste(route: str, box_id: str, text: str, *, field: str = "name", box_cls=None):
    """Deliver ``text`` to a box by one paste route; return ``(value, cursor, host)``."""

    async def run():
        host = PasteHost(box_cls, with_filter=box_id == FILTER)
        host.field = field
        with mock.patch("s19_app.tui.os_clipboard_input.read_os_clipboard", return_value=None):
            async with host.run_test(size=(100, 30)) as pilot:
                await pilot.pause()
                box = host.query_one(f"#{box_id}", Input)
                box.focus()
                host._clipboard = text
                await pilot.pause()
                if route == "terminal":
                    await terminal_paste(host, text)
                elif route == "ctrl_v":
                    await pilot.press("ctrl+v")
                else:
                    await right_click_app_route(host, pilot, box)
                await pilot.pause(0.2)
                return box.value, box.cursor_position, host

    return asyncio.run(run())


FILTER = "a2l_tags_filter_input"


def test_r_a2l_list_033_1(ll) -> None:
    """R-A2L-LIST.033/1: the terminal paste of G2L -> the names joined by ``, ``, cursor 0."""
    value, cursor, _ = drive_paste("terminal", FILTER, G2L_TEXT)
    assert (value, cursor) == (G2L_JOINED, 0)


def test_r_a2l_list_033_2(ll) -> None:
    """R-A2L-LIST.033/2: Ctrl+V (the clipboard seam) of G2L -> the joined names, cursor 0."""
    value, cursor, _ = drive_paste("ctrl_v", FILTER, G2L_TEXT)
    assert (value, cursor) == (G2L_JOINED, 0)


def test_r_a2l_list_033_3(ll) -> None:
    """R-A2L-LIST.033/3: a right-click with no selection (the seam) -> the joined names."""
    value, cursor, _ = drive_paste("right_click", FILTER, G2L_TEXT)
    assert (value, cursor) == (G2L_JOINED, 0)


def test_r_a2l_list_033_4(ll) -> None:
    """R-A2L-LIST.033/4 (E3A-12): field ``source`` -> the stock first line, text mode."""
    value, _, _ = drive_paste("terminal", FILTER, G2L_TEXT, field="source")
    assert value == G2L_NAMES[0]


def test_r_a2l_list_033_5(ll) -> None:
    """R-A2L-LIST.033/5 (E3S-05): 32,768 one-character names -> a 98,302-character value, not cut."""
    text = "\n".join("a" for _ in range(32768))
    assert len(text) == 65535
    value, _, _ = drive_paste("terminal", FILTER, text)
    assert len(value) == 32768 + 2 * 32767 == 98302


def test_r_a2l_list_034_1(ll) -> None:
    """R-A2L-LIST.034/1: ``VALUE_0002<ESC>[31m`` + new line + ``MAP_0003`` -> the controls removed."""
    value, _, _ = drive_paste("terminal", FILTER, "VALUE_0002\x1b[31m\nMAP_0003")
    assert value == "VALUE_0002[31m, MAP_0003"


def test_r_a2l_list_034_2(ll) -> None:
    """R-A2L-LIST.034/2: a bidi control (U+202E) is removed before the names are taken."""
    value, _, _ = drive_paste("terminal", FILTER, "A‮B\nC")
    assert value == "AB, C"


def test_r_a2l_list_034_3(ll) -> None:
    """R-A2L-LIST.034/3 (E3S-03): the hook receives the stripped text (no ESC reaches the override)."""
    import s19_app.tui.a2l_label_list as mod

    seen: list = []

    class Spy(mod.ListAwareFilterInput):
        def _take_paste(self, text: str) -> bool:
            seen.append(text)
            return super()._take_paste(text)

    drive_paste("terminal", FILTER, "VALUE_0002\x1b[31m\nMAP_0003", box_cls=Spy)
    assert seen == ["VALUE_0002[31m\nMAP_0003"]


def test_r_paste_1_1() -> None:
    """R-PASTE.1/1: a stock box (the Load box) takes the first line; the default hook is False."""
    value, _, host = drive_paste("terminal", "plain", G2L_TEXT)
    assert value == G2L_NAMES[0]
    assert host.query_one("#plain", OsClipboardInput)._take_paste("x\ny") is False


def test_r_paste_1_2(ll) -> None:
    """R-PASTE.1/2: one name pasted into the filter box -> the stock insert; the hook says False."""
    value, _, host = drive_paste("terminal", FILTER, "VALUE_0002")
    assert value == "VALUE_0002"
    assert host.query_one(f"#{FILTER}")._take_paste("VALUE_0002") is False


def test_r_paste_1_3(ll) -> None:
    """R-PASTE.1/3 (E3A-01 (2)): ``P_CTRL`` into the filter box -> the stock first-line strip."""
    value, _, _ = drive_paste("terminal", FILTER, P_CTRL)
    assert value == "A[13DB\x00C"


def test_r_paste_1_4(ll) -> None:
    """R-PASTE.1/4 (E3S-03): a ``restrict`` box never calls the hook; R-LOADDLG.20's refusal stands."""
    assert hasattr(OsClipboardInput, "_take_paste"), "the I-1 hook must exist for this case to mean anything"
    RestrictBox.hook_calls = []
    value, _, _ = drive_paste("terminal", "restr", G2L_TEXT)
    assert RestrictBox.hook_calls == [] and value == G2L_NAMES[0]
    refused, _, _ = drive_paste("terminal", "restr", "A\x1bB")
    assert RestrictBox.hook_calls == [] and refused == ""


def test_r_tui_043_4_1() -> None:
    """R-TUI-043.4/1: Ctrl+V of G2L in the Load box -> the first line."""
    value, _, _ = drive_paste("ctrl_v", "plain", G2L_TEXT)
    assert value == G2L_NAMES[0]


def test_r_tui_043_4_2(ll) -> None:
    """R-TUI-043.4/2: Ctrl+V of G2L in the filter box -> as R-A2L-LIST.033/2."""
    value, cursor, _ = drive_paste("ctrl_v", FILTER, G2L_TEXT)
    assert (value, cursor) == (G2L_JOINED, 0)


def test_r_tui_043_4_3(ll) -> None:
    """R-TUI-043.4/3 (E3A-01 (2)): ``P_CTRL`` by Ctrl+V into the filter box -> the stock strip."""
    value, _, _ = drive_paste("ctrl_v", FILTER, P_CTRL)
    assert value == "A[13DB\x00C"


def test_r_paste_29_1() -> None:
    """R-PASTE.29/1: a right-click in the Load box pastes the first line at the press."""
    value, _, _ = drive_paste("right_click", "plain", G2L_TEXT)
    assert value == G2L_NAMES[0]


def test_r_paste_29_2(ll) -> None:
    """R-PASTE.29/2: a right-click in the filter box pastes the joined list (as .033/3)."""
    value, _, _ = drive_paste("right_click", FILTER, G2L_TEXT)
    assert value == G2L_JOINED


def test_r_paste_29_3(ll) -> None:
    """R-PASTE.29/3 (E3A-01 (2)): ``P_CTRL`` by right-click into the filter box -> the stock strip."""
    value, _, _ = drive_paste("right_click", FILTER, P_CTRL)
    assert value == "A[13DB\x00C"


# ---------------------------------------------------------------------------
# The ranker (host app: a bare App owns the workers)
# ---------------------------------------------------------------------------


class RankHost(App):
    def compose(self):
        yield Static("host", id="host_static")


def run_host(monkeypatch, scenario, after=None, app_cls=RankHost):
    """Run ``scenario(app, pilot, seen)``; then, once the app closed, ``after(app, ctx, seen)``."""

    async def go():
        app = app_cls()
        seen = capture_workers(app, monkeypatch)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            ctx = await scenario(app, pilot, seen)
        if after is not None:
            await after(app, ctx, seen)
        return app, ctx, seen

    return asyncio.run(go())


async def prepared(ll, app, pilot, names, generation: int = 1):
    ranker = ll.LabelRanker(app)
    ranker.prepare(names, generation)
    await wait_until(pilot, lambda: ranker.ready, "the name list was prepared")
    return ranker


def expect(names, query: str, limit: int = 20) -> list:
    return rank(query, build_label_index(names), limit)


def test_r_a2l_list_073_1(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.073/1: ``rank`` for the dropdown runs on a worker thread, 20 matches delivered."""
    spy = Hold(real_seam("rank"), block=False)
    patch_seam(monkeypatch, "rank", spy)
    ui: list = []

    async def sc(app, pilot, seen):
        ui.append(threading.get_ident())
        ranker = await prepared(ll, app, pilot, names)
        got: list = []
        ranker.request("filter", "cuvre_00", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: got, "the ranking was delivered")
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert got[0] == expect(names, "cuvre_00") and len(got[0]) == 20
    assert spy.threads and all(t != ui[0] for t in spy.threads)


def test_r_a2l_list_073_2(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.073/2: the closest names (key ``similar:1``, limit 3) rank off the UI thread."""
    spy = Hold(real_seam("rank"), block=False)
    patch_seam(monkeypatch, "rank", spy)
    ui: list = []

    async def sc(app, pilot, seen):
        ui.append(threading.get_ident())
        ranker = await prepared(ll, app, pilot, names)
        got: list = []
        ranker.request("similar:1", "MAP_0024", 3, got.append, lambda: True)
        await wait_until(pilot, lambda: got, "the ranking was delivered")
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert got[0] == expect(names, "MAP_0024", 3) == []
    assert spy.threads and all(t != ui[0] for t in spy.threads)


def test_r_a2l_list_071_1(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.071/1: ``cu`` then ``cuvre_00`` before ``cu``'s result -> only ``cuvre_00`` delivered."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def sc(app, pilot, seen):
        ranker = await prepared(ll, app, pilot, names)
        got: list = []
        ranker.request("filter", "cu", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: spy.entered.is_set(), "cu started ranking")
        ranker.request("filter", "cuvre_00", 20, got.append, lambda: True)
        spy.gate.set()
        await wait_until(pilot, lambda: got, "cuvre_00 was delivered")
        await settle(pilot)
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert got == [expect(names, "cuvre_00")]


def test_r_a2l_list_071_2(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.071/2: a result of generation 1 arriving after generation 2 was prepared is dropped."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def sc(app, pilot, seen):
        ranker = await prepared(ll, app, pilot, names)
        got: list = []
        ranker.request("filter", "0017", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the ranking started")
        ranker.prepare(names, 2)
        spy.gate.set()
        await wait_until(pilot, lambda: ranker.ready, "generation 2 was prepared")
        await settle_workers(pilot)
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert got == []


def test_r_a2l_list_075_1(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.075/1 (E3A-06): one running + 5 keystrokes -> exactly 2 ``rank`` calls, the last text painted."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)
    texts = ["cuvre_001", "cuvre_0012", "cuvre_00", "cuvre_0", "cuvre_00x"]

    async def sc(app, pilot, seen):
        ranker = await prepared(ll, app, pilot, names)
        got: list = []
        ranker.request("filter", "cuvre_00", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the first ranking started")
        for text in texts:
            ranker.request("filter", text, 20, got.append, lambda: True)
        spy.gate.set()
        await wait_until(pilot, lambda: got, "the last text was delivered")
        await settle_workers(pilot)
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert [c[0] for c in spy.calls] == ["cuvre_00", "cuvre_00x"]
    assert got == [expect(names, "cuvre_00x")]


# ---------------------------------------------------------------------------
# Robustness of the deferred work (R-COPY.26's form: live arm, then after teardown)
# ---------------------------------------------------------------------------


def _teardown_case(ll, names, monkeypatch, key: str, query: str, limit: int):
    """Hold one ranking, close the app, release it; return ``(got, spy, errors, app)``."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)
    got: list = []

    async def sc(app, pilot, seen):
        ranker = await prepared(ll, app, pilot, names)
        ranker.request(key, query, limit, got.append, lambda: True)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the ranking started")

    async def after(app, ctx, seen):
        await release_after_close([spy])

    app, _, seen = run_host(monkeypatch, sc, after)
    return got, app, worker_errors(seen)


def test_r_a2l_list_085_1(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.085/1: the filter box's ranking released after the app closed -> nothing painted, no error."""
    got, app, errors = _teardown_case(ll, names, monkeypatch, "filter", "cuvre_00", 20)
    assert got == [] and errors == [] and app._exception is None


def test_r_a2l_list_085_3(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.085/3: a ``similar:1`` ranking released after the app closed -> the same."""
    got, app, errors = _teardown_case(ll, names, monkeypatch, "similar:1", "MAP_0024", 3)
    assert got == [] and errors == [] and app._exception is None


def test_r_a2l_list_085_5(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.085/5: a ``rank`` stand-in raising ValueError -> nothing delivered, the app keeps running."""
    patch_seam(monkeypatch, "rank", Hold(real_seam("rank"), fail=ValueError("x"), block=False))

    async def sc(app, pilot, seen):
        ranker = await prepared(ll, app, pilot, names)
        got: list = []
        ranker.request("filter", "0017", 20, got.append, lambda: True)
        await settle_workers(pilot)
        await settle(pilot)
        return got, app.is_running

    _, (got, running), seen = run_host(monkeypatch, sc)
    assert got == [] and running and worker_errors(seen) == []


def test_r_a2l_list_085_6(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.085/6: positive arm, the held filter and similar rankings released while running paint."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def sc(app, pilot, seen):
        ranker = await prepared(ll, app, pilot, names)
        f: list = []
        s: list = []
        ranker.request("filter", "0017", 20, f.append, lambda: True)
        ranker.request("similar:1", "MAP_0024", 3, s.append, lambda: True)
        await wait_until(pilot, lambda: spy.entered.is_set(), "a ranking started")
        spy.gate.set()
        await wait_until(pilot, lambda: f and s, "both rankings were delivered")
        return f, s

    _, (f, s), _ = run_host(monkeypatch, sc)
    assert f == [expect(names, "0017")] and len(f[0]) == 5 and s == [[]]


def test_r_a2l_list_084_1(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.084/1: the held preparation released after the app closed -> no error, rank never called."""
    build = Hold(real_seam("build_label_index"))
    spy = Hold(real_seam("rank"), block=False)
    patch_seam(monkeypatch, "build_label_index", build)
    patch_seam(monkeypatch, "rank", spy)
    got: list = []

    async def sc(app, pilot, seen):
        ranker = ll.LabelRanker(app)
        ranker.prepare(names, 1)
        ranker.request("filter", "0017", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: build.entered.is_set(), "the build started")

    async def after(app, ctx, seen):
        await release_after_close([build])

    app, _, seen = run_host(monkeypatch, sc, after)
    assert got == [] and spy.calls == [] and worker_errors(seen) == [] and app._exception is None


def test_r_a2l_list_084_2(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.084/2: ``build_label_index`` raising -> not ready, request dropped, app running, spy kwargs."""
    patch_seam(monkeypatch, "build_label_index",
               Hold(real_seam("build_label_index"), fail=ValueError("x"), block=False))

    async def sc(app, pilot, seen):
        ranker = ll.LabelRanker(app)
        ranker.prepare(names, 1)
        got: list = []
        ranker.request("filter", "0017", 20, got.append, lambda: True)
        await settle_workers(pilot)
        await settle(pilot)
        return got, ranker.ready, app.is_running

    _, (got, ready, running), seen = run_host(monkeypatch, sc)
    assert got == [] and ready is False and running and worker_errors(seen) == []
    kwargs = seen[0][0]
    assert kwargs.get("thread") is True and kwargs.get("exit_on_error") is False


def test_r_a2l_list_084_3(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.084/3: positive arm, the build released while running -> the held request paints 5 rows."""
    build = Hold(real_seam("build_label_index"))
    patch_seam(monkeypatch, "build_label_index", build)

    async def sc(app, pilot, seen):
        ranker = ll.LabelRanker(app)
        ranker.prepare(names, 1)
        got: list = []
        ranker.request("filter", "0017", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: build.entered.is_set(), "the build started")
        build.gate.set()
        await wait_until(pilot, lambda: got, "the held request was delivered")
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert got == [expect(names, "0017")] and len(got[0]) == 5


def test_r_a2l_list_087_1(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.087/1: a build that fails once is retried at the next request, then the dropdown opens."""
    build = Hold(real_seam("build_label_index"), fail=ValueError("x"), fail_times=1)
    patch_seam(monkeypatch, "build_label_index", build)

    async def sc(app, pilot, seen):
        ranker = ll.LabelRanker(app)
        ranker.prepare(names, 1)
        got: list = []
        ranker.request("filter", "001", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: build.entered.is_set(), "the build started")
        build.gate.set()
        await settle_workers(pilot)
        await settle(pilot)
        assert got == [] and not ranker.ready
        ranker.request("filter", "0017", 20, got.append, lambda: True)
        await wait_until(pilot, lambda: got, "the retried build delivered")
        return got

    _, got, _ = run_host(monkeypatch, sc)
    assert len(build.calls) == 2 and got == [expect(names, "0017")] and len(got[0]) == 5


def test_r_a2l_list_087_2(ll, names, monkeypatch) -> None:
    """R-A2L-LIST.087/2: a build that always fails -> exactly 2 builds over 5 requests, the app running."""
    build = Hold(real_seam("build_label_index"), fail=ValueError("x"), block=False)
    patch_seam(monkeypatch, "build_label_index", build)

    async def sc(app, pilot, seen):
        ranker = ll.LabelRanker(app)
        ranker.prepare(names, 1)
        await settle_workers(pilot)
        got: list = []
        for text in ("0", "00", "001", "0017", "00171"):
            ranker.request("filter", text, 20, got.append, lambda: True)
            await settle_workers(pilot)
            await settle(pilot)
        return got, ranker.ready, app.is_running

    _, (got, ready, running), _ = run_host(monkeypatch, sc)
    assert len(build.calls) == 2 and got == [] and ready is False and running


# ---------------------------------------------------------------------------
# The dropdown (LabelSuggestBox) and the filter box's keys, in the host app
# ---------------------------------------------------------------------------


def drive_box(scenario):
    """Run ``scenario(host, pilot, box, suggest)`` on a host with the list-aware filter box."""

    async def go():
        host = PasteHost()
        async with host.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            box = host.query_one(f"#{FILTER}", Input)
            return await scenario(host, pilot, box, host.query_one("#a2l_filter_suggest"))

    return asyncio.run(go())


def shown(suggest) -> list:
    return static_text(suggest).split("\n")


def dropdown(names, query: str, scenario=None, limit: int = 20):
    """Open the filter dropdown for ``query`` over case 08's names; return its lines."""

    async def sc(host, pilot, box, suggest):
        suggest.show_ranked(query, expect(names, query, limit))
        await settle(pilot, 2)
        return shown(suggest), suggest

    return drive_box(sc)


def test_r_a2l_list_063_1(ll, names) -> None:
    """R-A2L-LIST.063/1: ``cuvre_00`` -> 8 rows, row 1 ``▸ CURVE_0001 ... fuzzy · 1 edit``."""
    lines, _ = dropdown(names, "cuvre_00")
    rows = lines[1:9]
    assert rows[0].startswith("▸ CURVE_0001") and rows[0].rstrip().endswith("fuzzy · 1 edit")
    assert all(r.startswith("  CURVE_000") for r in rows[1:]) and "choose" in lines[9]


def test_r_a2l_list_063_2(ll, names) -> None:
    """R-A2L-LIST.063/2: ``0017`` -> 5 rows, row 1 ``▸ MAP_0017 ... substring``."""
    lines, _ = dropdown(names, "0017")
    assert lines[1].startswith("▸ MAP_0017") and lines[1].rstrip().endswith("substring")
    assert len(lines[1:6]) == 5 and "choose" in lines[6]


def test_r_a2l_list_065_1(ll, names) -> None:
    """R-A2L-LIST.065/1: ``0017`` -> title ``5 of 5 similar names``."""
    assert dropdown(names, "0017")[0][0] == "5 of 5 similar names"


def test_r_a2l_list_065_2(ll, names) -> None:
    """R-A2L-LIST.065/2: ``cuvre_00`` -> title ``8 of 20+ similar names``."""
    assert dropdown(names, "cuvre_00")[0][0] == "8 of 20+ similar names"


def _highlighted(suggest, row_index: int, spans: list, prefix: int = 2) -> tuple:
    """The characters of one row inside / outside its match spans that carry the highlight style."""
    content = suggest.render()
    text = content.plain
    lines = text.split("\n")
    start = sum(len(line) + 1 for line in lines[:row_index]) + prefix
    covered = lambda i: [str(s.style) for s in content.spans if s.start <= i < s.end]
    inside = [i for a, b in spans for i in range(start + a, start + b)]
    marks = [covered(i) for i in inside]
    return start, inside, marks, covered


def test_r_a2l_list_064_1(ll, names) -> None:
    """R-A2L-LIST.064/1: ``CURVE_0001`` for ``cuvre_00`` -> chars (0,5) and (6,10) highlighted, (5,6) not."""
    _, suggest = dropdown(names, "cuvre_00")
    start, inside, marks, covered = _highlighted(suggest, 1, [(0, 5), (6, 10)])
    assert all(marks), "every span character must carry a style"
    common = set.intersection(*(set(m) for m in marks))
    assert common, "the spans share one highlight style"
    assert not (set(covered(start + 5)) & common)


def test_r_a2l_list_064_2(ll, names) -> None:
    """R-A2L-LIST.064/2: ``MAP_0017`` for ``0017`` -> chars (4,8) highlighted, (0,4) not."""
    _, suggest = dropdown(names, "0017")
    start, inside, marks, covered = _highlighted(suggest, 1, [(4, 8)])
    common = set.intersection(*(set(m) for m in marks))
    assert common and not (set(covered(start + 1)) & common)


def test_r_a2l_list_066_1(ll, names) -> None:
    """R-A2L-LIST.066/1: ``zzzz`` -> title ``no similar name`` and the two hint lines, no choice."""
    lines, suggest = dropdown(names, "zzzz")
    assert lines[0] == "no similar name" and lines[1] == "nothing matches 'zzzz'"
    assert lines[2] == "digits must match exactly; a word may have 1–2 typos" and suggest.choice is None


def test_r_a2l_list_066_2(ll, names) -> None:
    """R-A2L-LIST.066/2: a 257-character query echoes as its short text (63 characters + ``…``)."""
    query = "x" * 257
    lines, _ = dropdown(names, query)
    assert lines[1] == f"nothing matches '{query[:63]}…'"


def test_r_a2l_list_066_3(ll, names) -> None:
    """R-A2L-LIST.066/3 (E3S-02): 300 characters with NUL and ESC -> U+FFFD for both, cut at 63 + ``…``."""
    query = "".join("\x00" if i == 10 else "\x1b" if i == 20 else "y" for i in range(300))
    lines, _ = dropdown(names, query)
    shown_text = lines[1][len("nothing matches '"):-1]
    assert shown_text == query[:63].replace("\x00", "�").replace("\x1b", "�") + "…"


def test_r_a2l_list_067_1(ll, names) -> None:
    """R-A2L-LIST.067/1: the filter dropdown's key line and the rank line."""
    lines, _ = dropdown(names, "0017")
    assert "↑↓ choose  tab complete  esc close" in lines
    assert "rank: exact › prefix › substring › token › fuzzy › subsequence" in lines


def test_r_a2l_list_067_2(ll, names) -> None:
    """R-A2L-LIST.067/2: the add line's dropdown (accept ``enter add to the list``)."""
    import s19_app.tui.a2l_label_list as mod

    async def sc(host, pilot, box, suggest):
        other = mod.LabelSuggestBox(accept="enter add to the list", id="add_suggest")
        await host.mount(other)
        other.show_ranked("0017", expect(names, "0017"))
        await settle(pilot, 2)
        return shown(other)

    lines = drive_box(sc)
    assert "↑↓ choose  enter add to the list  esc close" in lines
    assert "rank: exact › prefix › substring › token › fuzzy › subsequence" in lines


def _keys(names, query: str, keys: list):
    async def sc(host, pilot, box, suggest):
        box.value = query
        box.focus()
        suggest.show_ranked(query, expect(names, query))
        await pilot.pause()
        for key in keys:
            await pilot.press(key)
        await pilot.pause()
        return box, suggest

    return drive_box(sc)


def test_r_a2l_list_068_1(ll, names) -> None:
    """R-A2L-LIST.068/1: ``cuvre_00`` open, down -> choice ``CURVE_0002``."""
    box, suggest = _keys(names, "cuvre_00", ["down"])
    assert suggest.choice == "CURVE_0002"


def test_r_a2l_list_068_2(ll, names) -> None:
    """R-A2L-LIST.068/2: down x 9 stays within the 8 rows -> ``CURVE_0008``."""
    box, suggest = _keys(names, "cuvre_00", ["down"] * 9)
    assert suggest.choice == "CURVE_0008"


def test_r_a2l_list_068_3(ll, names) -> None:
    """R-A2L-LIST.068/3: up at row 1 stays on ``CURVE_0001``."""
    box, suggest = _keys(names, "cuvre_00", ["up"])
    assert suggest.choice == "CURVE_0001"


def test_r_a2l_list_069_1(ll, names) -> None:
    """R-A2L-LIST.069/1: tab -> the box holds ``CURVE_0001``, cursor at its end, dropdown closed."""
    box, suggest = _keys(names, "cuvre_00", ["tab"])
    assert box.value == "CURVE_0001" and box.cursor_position == 10 and not suggest.is_open


def test_r_a2l_list_069_2(ll, names) -> None:
    """R-A2L-LIST.069/2: down then tab -> ``CURVE_0002``."""
    box, suggest = _keys(names, "cuvre_00", ["down", "tab"])
    assert box.value == "CURVE_0002"


def test_r_a2l_list_069_control_inserts_the_name_not_its_display_text(ll) -> None:
    """R-A2L-LIST.069 control (I-3 obligation 3): a name holding U+0007 is inserted as is."""
    from s19_app.tui.services.label_match import LabelMatch, MatchRule

    name = "AB\x07CD"

    async def sc(host, pilot, box, suggest):
        box.focus()
        suggest.show_ranked("ab", [LabelMatch(name, MatchRule.PREFIX, 0, ((0, 2),))])
        await pilot.pause()
        await pilot.press("tab")
        await pilot.pause()
        return box.value

    assert drive_box(sc) == name


def test_r_a2l_list_070_1(ll, names) -> None:
    """R-A2L-LIST.070/1: Esc closes the open dropdown and keeps the box text."""
    box, suggest = _keys(names, "cuvre_00", ["escape"])
    assert not suggest.is_open and box.value == "cuvre_00"


def test_i7_filter_box_esc_clears_a_list_text(ll) -> None:
    """I-7 (box level of R-A2L-LIST.032): Esc with no dropdown on a list text clears the box."""

    async def sc(host, pilot, box, suggest):
        box.value = G2L_JOINED
        box.focus()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        return box.value

    assert drive_box(sc) == ""


# ---------------------------------------------------------------------------
# Pure text surfaces: names on every surface (.076, .077)
# ---------------------------------------------------------------------------

PASTED_HOST = "A[red]\x1bB\x00C"  # a pasted name cannot hold U+0085: the parser splits there
PASTED_SHOWN = "A[red]�B�C"


def entry_of(ll, name: str, status: str = "missing", pos: int = 1, tag=None, first=None):
    return ll.LabelListEntry(pos, name, status, tag, first)


def test_r_a2l_list_076_1(ll) -> None:
    """R-A2L-LIST.076/1: a list-mode row of a tag named ``A[red]<ESC>B<NUL><U+0085>`` paints its display text."""
    from rich.text import Text

    tag = {"name": HOST_NAME, "section": "CHARACTERISTIC", "char_type": "VALUE"}
    cells = {k: Text("x") for k in ("Address", "Length", "Physical", "Unit", "Limits")}
    row = ll.list_row_cells(entry_of(ll, HOST_NAME, "found", tag=tag), cells, "all")
    assert row[1].plain == "● " + HOST_SHOWN and list(row[1].spans) == []


def test_r_a2l_list_076_2(ll) -> None:
    """R-A2L-LIST.076/2: the detail card's ``✗`` line paints the display text, brackets literal."""
    text = ll.list_card_text(entry_of(ll, HOST_NAME), None)
    assert text.plain.split("\n")[0] == f"✗ {HOST_SHOWN}  not in this A2L" and "\x1b" not in text.plain
    assert list(text.spans) == []


def test_r_a2l_list_076_3(ll) -> None:
    """R-A2L-LIST.076/3: the missing line paints the display text with no markup span from the name."""
    res = ll.resolve_label_list([HOST_NAME], [])
    counts, ribbon, missing = ll.list_summary_texts(res, 80)
    assert f"#1 {HOST_SHOWN}" in missing.plain and "\x1b" not in missing.plain + counts.plain
    assert "[red]" in missing.plain


def test_r_a2l_list_076_6(ll) -> None:
    """R-A2L-LIST.076/6: a dropdown row over a tag named with markup, ESC, NUL and U+0085 paints its display text."""
    from s19_app.tui.services.label_match import LabelMatch, MatchRule

    async def sc(host, pilot, box, suggest):
        suggest.show_ranked("a", [LabelMatch(HOST_NAME, MatchRule.PREFIX, 0, ((0, 1),))])
        await settle(pilot, 2)
        return shown(suggest)

    lines = drive_box(sc)
    assert lines[1].startswith("▸ " + HOST_SHOWN) and "\x1b" not in "\n".join(lines)


def test_r_a2l_list_076_7(ll) -> None:
    """R-A2L-LIST.076/7 (E3S-06, E3S-R1): bidi and zero-width controls -> U+FFFD one for one, length kept."""
    name = "A‮B⁦C​D﻿"
    assert ll.display_text(name) == "A�B�C�D�" and len(name) == 8


def test_r_a2l_list_077_1(ll) -> None:
    """R-A2L-LIST.077/1: a 300-character missing name -> 63 characters + ``…`` in the missing line."""
    name = "N" * 300
    res = ll.resolve_label_list([name], [])
    _, _, missing = ll.list_summary_texts(res, 80)
    assert f"#1 {name[:63]}…" in missing.plain and name[:64] not in missing.plain
    assert ll.display_text(name, 64) == name[:63] + "…" and len(ll.display_text(name, 64)) == 64


def test_r_a2l_list_077_2(ll) -> None:
    """R-A2L-LIST.077/2: a 64-character name is shown whole."""
    name = "M" * 64
    assert ll.display_text(name, 64) == name
    _, _, missing = ll.list_summary_texts(ll.resolve_label_list([name], []), 80)
    assert f"#1 {name}" in missing.plain and "…" not in missing.plain


def test_r_a2l_list_077_3(ll) -> None:
    """R-A2L-LIST.077/3 (E3S-09): a 1,024-character tag name in a dropdown row -> 63 characters + ``…``."""
    from s19_app.tui.services.label_match import LabelMatch, MatchRule

    name = "LONG_" + "z" * 1019
    assert len(name) == 1024

    async def sc(host, pilot, box, suggest):
        suggest.show_ranked("LONG_", [LabelMatch(name, MatchRule.PREFIX, 0, ((0, 5),))])
        await settle(pilot, 2)
        return shown(suggest), suggest.choice

    lines, choice = drive_box(sc)
    assert lines[1].startswith("▸ " + name[:63] + "…") and lines[1].rstrip().endswith("prefix")
    assert choice == name


def test_r_a2l_list_077_4(ll) -> None:
    """R-A2L-LIST.077/4 (E3S-09): the card's ``✗`` line of a 300-character missing name is its short text."""
    name = "Q" * 300
    first = ll.list_card_text(entry_of(ll, name), None).plain.split("\n")[0]
    assert first == f"✗ {name[:63]}…  not in this A2L"


# ---------------------------------------------------------------------------
# The paste window (host app pushes the modal; real ranker, real rank)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def enriched(case08, tmp_path_factory) -> list:
    """The enriched tags of case 08 as the real viewer builds them."""
    from tests.support.b103_label_list import run_a2l

    async def grab(app, pilot):
        return list(app._a2l_enriched_tags)

    return run_a2l(tmp_path_factory.mktemp("i7_l_enriched"), case08, grab)


class ModalHost(App):
    def __init__(self, tags, names, initial, wide, hook=None) -> None:
        super().__init__()
        self.tags, self.names, self.initial, self.wide, self.hook = tags, names, initial, wide, hook
        self.results: list = []

    def on_mount(self) -> None:
        import s19_app.tui.a2l_label_list as mod

        self.ranker = mod.LabelRanker(self)
        self.ranker.prepare(self.names, 1)
        self.modal = mod.LabelListPasteModal(
            tags=self.tags, ranker=self.ranker, names=self.initial, wide=self.wide
        )
        if self.hook is not None:
            self.hook(self.modal)
        self.push_screen(self.modal, self.results.append)


def run_modal(monkeypatch, enriched, names, scenario, *, initial=(), wide=False,
              size=(118, 54), hook=None, after=None):
    """Open the paste window over case 08; ``scenario(app, pilot, modal, seen)``, then ``after``."""

    async def go():
        app = ModalHost(enriched, names, list(initial), wide, hook)
        seen = capture_workers(app, monkeypatch)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await wait_until(pilot, lambda: app.ranker.ready and app.screen is app.modal, "window open")
            await settle(pilot)
            ctx = await scenario(app, pilot, app.modal, seen)
        if after is not None:
            await after(app, ctx, seen)
        return app, ctx, seen

    return asyncio.run(go())


async def type_text(pilot, modal, text: str) -> None:
    """Replace the window's text and let the 0.15 s preview and its rankings finish."""
    modal.query_one("#a2l_list_text", TextArea).text = text
    await pilot.pause(0.3)
    await settle_workers(pilot)
    await settle(pilot)


def said(modal, wid: str) -> str:
    return static_text(modal.query_one(f"#{wid}"))


def paste_rows(modal) -> list:
    from textual.widgets import DataTable

    table = modal.query_one("#a2l_list_preview", DataTable)
    return [[plain(c) for c in table.get_row_at(i)] for i in range(table.row_count)]


def paste_labels(modal) -> list:
    from textual.widgets import DataTable

    return [plain(c.label) for c in modal.query_one("#a2l_list_preview", DataTable).ordered_columns]


def tag_set(names) -> set:
    return set(names)


def test_r_a2l_list_042_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.042/1: the focus is in the window's text area when it opens."""
    async def sc(app, pilot, modal, seen):
        return app.focused.id if app.focused else None

    _, focus, _ = run_modal(monkeypatch, enriched, names, sc)
    assert focus == "a2l_list_text"


def test_r_a2l_list_043_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.043/1: the add line's placeholder and the text-area label."""
    async def sc(app, pilot, modal, seen):
        add = modal.query_one("#a2l_list_add", Input)
        labels = [static_text(w) for w in modal.query("Static, Label")]
        return add.placeholder, labels

    _, (placeholder, labels), _ = run_modal(monkeypatch, enriched, names, sc)
    assert placeholder == "part of a name — start, middle, end, a typo"
    assert "or paste names — new line , ; space" in labels and "add" in labels


def test_r_a2l_list_044_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.044/1: the note under the window."""
    async def sc(app, pilot, modal, seen):
        return said(modal, "a2l_list_note")

    _, note, _ = run_modal(monkeypatch, enriched, names, sc)
    assert note == ("The list filters the viewer (LIST mode, pasted order); nothing is saved. "
                    "Missing names stay listed so you can fix them.")


def test_r_a2l_list_045_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.045/1: the two buttons' labels."""
    async def sc(app, pilot, modal, seen):
        return (plain(modal.query_one("#a2l_list_apply", Button).label),
                plain(modal.query_one("#a2l_list_cancel", Button).label))

    _, labels, _ = run_modal(monkeypatch, enriched, names, sc)
    assert labels == ("Filter viewer by list  alt+f", "Cancel  esc")


def test_r_a2l_list_046_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.046/1: G2L pasted -> the counts line and ``order`` + the ribbon."""
    from tests.support.b103_label_list import oracle_counts, oracle_ribbon, oracle_rows

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, G2L_TEXT)
        return said(modal, "a2l_list_counts")

    _, text, _ = run_modal(monkeypatch, enriched, names, sc)
    rows = oracle_rows(G2L_NAMES, tag_set(names))
    assert oracle_counts(rows) in text and "order " + oracle_ribbon(rows, 50) in text


def test_r_a2l_list_046_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.046/2: 60 names -> 50 glyphs + `` +10``."""
    sixty = names[:60]

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "\n".join(sixty))
        return said(modal, "a2l_list_counts")

    _, text, _ = run_modal(monkeypatch, enriched, names, sc)
    assert "order " + "●" * 50 + " +10" in text


def test_r_a2l_list_047_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.047/1: 118x54 -> 5 columns, 12 rows, row 7 ``✗ MAP_0024`` / ``not in A2L``."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, G2L_TEXT)
        return paste_labels(modal), paste_rows(modal)

    _, (labels, rows), _ = run_modal(monkeypatch, enriched, names, sc, wide=False)
    assert labels == ["#", "Name", "Status", "Kind", "Address"] and len(rows) == 12
    assert rows[6][:3] == ["7", "✗ MAP_0024", "not in A2L"]


def test_r_a2l_list_047_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.047/2: opened wide (220x60) -> plus ``Value`` and ``Unit``."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, G2L_TEXT)
        return paste_labels(modal)

    _, labels, _ = run_modal(monkeypatch, enriched, names, sc, wide=True, size=(220, 60))
    assert labels == ["#", "Name", "Status", "Kind", "Address", "Value", "Unit"]


def test_r_a2l_list_047_3(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.047/3 (E3A-14): opened wide at 220x60, then resized to 118x54 -> still 7 columns."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, G2L_TEXT)
        await pilot.resize_terminal(118, 54)
        await settle(pilot)
        await type_text(pilot, modal, G2L_TEXT + "VALUE_0042\n")
        return paste_labels(modal)

    _, labels, _ = run_modal(monkeypatch, enriched, names, sc, wide=True, size=(220, 60))
    assert labels == ["#", "Name", "Status", "Kind", "Address", "Value", "Unit"]


def test_r_a2l_list_048_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.048/1: the missing line under the preview (as .022/1)."""
    from tests.support.b103_label_list import oracle_missing, oracle_rows

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, G2L_TEXT)
        return said(modal, "a2l_list_missing")

    _, text, _ = run_modal(monkeypatch, enriched, names, sc)
    assert text == oracle_missing(oracle_rows(G2L_NAMES, tag_set(names)))


def _similar_lines(monkeypatch, enriched, names, text: str) -> str:
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, text)
        return said(modal, "a2l_list_similar")

    return run_modal(monkeypatch, enriched, names, sc)[1]


def test_r_a2l_list_049_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.049/1: ``VALUE_002`` at #3 -> ``  similar to #3 VALUE_002: <3 closest names>``."""
    closest = " · ".join(m.name for m in expect(names, "VALUE_002", 3))
    text = _similar_lines(monkeypatch, enriched, names, "VALUE_0002\nCURVE_0001\nVALUE_002\n")
    assert f"  similar to #3 VALUE_002: {closest}" in text and closest.startswith("VALUE_0020")


def test_r_a2l_list_049_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.049/2: ``value_0002`` -> ``...: VALUE_0002`` (case folded by the matcher)."""
    text = _similar_lines(monkeypatch, enriched, names, "VALUE_0002\nvalue_0002\n")
    assert "  similar to #2 value_0002: VALUE_0002" in text


def test_r_a2l_list_050_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.050/1 (E3A-04): #7 ``MAP_0024`` has no closest name -> the ``none`` line, #7 before #11."""
    text = _similar_lines(monkeypatch, enriched, names, G2L_TEXT)
    line7 = "  similar to #7 MAP_0024: none (digits must match exactly)"
    assert line7 in text and text.index(line7) < text.index("  similar to #11 CURVE_0071")


def test_r_a2l_list_050_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.050/2 (E3A-04): the line of #11 is painted too (one token per key)."""
    text = _similar_lines(monkeypatch, enriched, names, G2L_TEXT)
    assert "  similar to #11 CURVE_0071: none (digits must match exactly)" in text


def _requested_keys(monkeypatch, enriched, names, text: str) -> tuple:
    import s19_app.tui.a2l_label_list as mod

    keys: list = []
    real = mod.LabelRanker.request

    def spy(self, key, *args, **kwargs):
        keys.append(key)
        return real(self, key, *args, **kwargs)

    monkeypatch.setattr(mod.LabelRanker, "request", spy)

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, text)
        return said(modal, "a2l_list_similar")

    _, similar, _ = run_modal(monkeypatch, enriched, names, sc)
    return keys, similar


NOTE_51 = "  similar names are shown for the first 10 missing names"


def test_r_a2l_list_051_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.051/1: 11 missing names -> 10 similar requests and the cap line."""
    keys, similar = _requested_keys(monkeypatch, enriched, names, "\n".join(f"NOSUCH_{i:03d}" for i in range(11)))
    assert {k for k in keys if k.startswith("similar:")} == {f"similar:{i}" for i in range(1, 11)}
    assert NOTE_51 in similar


def test_r_a2l_list_051_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.051/2: 10 missing names -> 10 requests and no cap line."""
    keys, similar = _requested_keys(monkeypatch, enriched, names, "\n".join(f"NOSUCH_{i:03d}" for i in range(10)))
    assert len({k for k in keys if k.startswith("similar:")}) == 10 and NOTE_51 not in similar


def test_r_a2l_list_052_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.052/1: text edited before a held ranking returns -> the earlier line is never painted."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def sc(app, pilot, modal, seen):
        modal.query_one("#a2l_list_text", TextArea).text = "VALUE_002\n"
        await pilot.pause(0.3)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the similar ranking started")
        modal.query_one("#a2l_list_text", TextArea).text = "CURVE_0001\n"
        await pilot.pause(0.3)
        spy.gate.set()
        await settle_workers(pilot)
        await settle(pilot)
        return said(modal, "a2l_list_similar")

    _, similar, _ = run_modal(monkeypatch, enriched, names, sc)
    assert "similar to #1 VALUE_002" not in similar


def test_r_a2l_list_052_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.052/2: text unchanged while the ranking is held -> its line is painted on release."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def sc(app, pilot, modal, seen):
        modal.query_one("#a2l_list_text", TextArea).text = "VALUE_002\n"
        await pilot.pause(0.3)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the similar ranking started")
        spy.gate.set()
        await wait_until(pilot, lambda: "similar to #1" in said(modal, "a2l_list_similar"), "painted")
        return said(modal, "a2l_list_similar")

    _, similar, _ = run_modal(monkeypatch, enriched, names, sc)
    assert "  similar to #1 VALUE_002: VALUE_0020" in similar


async def _add_line(pilot, modal, text: str):
    add = modal.query_one("#a2l_list_add", Input)
    add.value = text
    suggest = modal.query_one("#a2l_list_add_suggest")
    await pilot.pause(0.3)
    await settle_workers(pilot)
    await settle(pilot)
    add.focus()
    await pilot.pause()
    return add, suggest


def test_r_a2l_list_057_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.057/1: enter on ``0042 val`` appends ``VALUE_0042`` and a new line; add line emptied."""
    async def sc(app, pilot, modal, seen):
        before = modal.query_one("#a2l_list_text", TextArea).text
        add, suggest = await _add_line(pilot, modal, "0042 val")
        await pilot.press("enter")
        await pilot.pause()
        return before, modal.query_one("#a2l_list_text", TextArea).text, add.value, suggest.is_open

    _, (before, after, add_value, is_open), _ = run_modal(monkeypatch, enriched, names, sc, initial=G2L_NAMES)
    chosen = expect(names, "0042 val")[0].name
    assert before.endswith("\n") and after == before + chosen + "\n" and add_value == "" and not is_open


def test_r_a2l_list_057_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.057/2: a text with no final new line gets one inserted first."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "MAP_0003")
        add, _ = await _add_line(pilot, modal, "0042 val")
        await pilot.press("enter")
        await pilot.pause()
        return modal.query_one("#a2l_list_text", TextArea).text

    _, text, _ = run_modal(monkeypatch, enriched, names, sc)
    assert text == "MAP_0003\n" + expect(names, "0042 val")[0].name + "\n"


def test_r_a2l_list_058_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.058/1: enter on ``zzzz`` (no ranked name) leaves the text area and the add line unchanged."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "MAP_0003\n")
        add, _ = await _add_line(pilot, modal, "zzzz")
        await pilot.press("enter")
        await pilot.pause()
        return modal.query_one("#a2l_list_text", TextArea).text, add.value

    _, (text, add_value), _ = run_modal(monkeypatch, enriched, names, sc)
    assert text == "MAP_0003\n" and add_value == "zzzz"


def test_r_a2l_list_059_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.059/1: the closest names never replace the missing name in the text area."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "VALUE_002\n")
        return modal.query_one("#a2l_list_text", TextArea).text, said(modal, "a2l_list_similar")

    _, (text, similar), _ = run_modal(monkeypatch, enriched, names, sc, initial=G2L_NAMES)
    assert text == "VALUE_002\n" and "similar to #1 VALUE_002" in similar


def test_r_a2l_list_061_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.061/1: ``0042 val`` on the add line opens its dropdown with the two token matches."""
    async def sc(app, pilot, modal, seen):
        add, suggest = await _add_line(pilot, modal, "0042 val")
        return shown(suggest), suggest.is_open

    _, (lines, is_open), _ = run_modal(monkeypatch, enriched, names, sc)
    want = [m.name for m in expect(names, "0042 val")]
    assert is_open and [n for n in want if n in "\n".join(lines)] == want and "token" in lines[1]
    assert want[:2] == ["VALUE_0042", "VAL_BLK_0042"]


def test_r_a2l_list_070_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.070/2: Esc with the add line's dropdown open closes only the dropdown."""
    async def sc(app, pilot, modal, seen):
        add, suggest = await _add_line(pilot, modal, "0042 val")
        await pilot.press("escape")
        await pilot.pause()
        return suggest.is_open, app.screen is modal, add.value

    _, (is_open, still, value), _ = run_modal(monkeypatch, enriched, names, sc)
    assert not is_open and still and value == "0042 val"


def build_paste(pool: list, cap: int = 65536) -> str:
    """The P1 section-5 hostile paste: every third name missing, the rest cycled from ``pool``."""
    parts, size, i = [], 0, 0
    while True:
        name = pool[i % len(pool)] if i % 3 else f"MISSING_{i:06d}"
        if size + len(name) + 1 > cap:
            return "\n".join(parts)
        parts.append(name)
        size += len(name) + 1
        i += 1


def _big_preview(monkeypatch, enriched, names, text: str):
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, text)
        return len(paste_rows(modal)), said(modal, "a2l_list_more"), said(modal, "a2l_list_counts")

    return run_modal(monkeypatch, enriched, names, sc)[1]


def test_r_a2l_list_078_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.078/1 (E3S-01): the 4,906-name paste -> 200 rows and the more line."""
    text = build_paste(names)
    n = len(parse_parameter_list(text))
    assert n == 4906
    rows, more, counts = _big_preview(monkeypatch, enriched, names, text)
    assert rows == 200 and more == f"  +{n - 200} more names (the counts above cover all {n})"
    assert counts.startswith(f"{n} pasted  ·  ")


def test_r_a2l_list_078_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.078/2 (E3S-01): 32,768 one-character names -> 200 rows and the more line."""
    rows, more, _ = _big_preview(monkeypatch, enriched, names, "\n".join("a" for _ in range(32768)))
    assert rows == 200 and more == "  +32568 more names (the counts above cover all 32768)"


@pytest.mark.serial_timing
def test_r_a2l_list_078_3(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.078/3 (E3S-01): one preview rebuild of 32,768 names <= 0.25 s (median of 3); load printed."""
    import os
    import statistics

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "\n".join("a" for _ in range(32768)))
        times = []
        for _ in range(3):
            start = time.perf_counter()
            modal._preview()
            times.append(time.perf_counter() - start)
        return statistics.median(times)

    print("load average before:", os.getloadavg())
    _, median, _ = run_modal(monkeypatch, enriched, names, sc)
    print(f"preview rebuild median {median:.3f} s, load average after: {os.getloadavg()}")
    assert median <= timing_bound(0.25)


def _debounce_spy():
    import types

    captured: list = []

    def hook(modal):
        def spy(delay, callback=None, *args, **kwargs):
            captured.append(callback)
            return types.SimpleNamespace(stop=lambda: None, pause=lambda: None, resume=lambda: None)

        modal.set_timer = spy

    return captured, hook


def test_r_a2l_list_086_1(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.086/1: a preview due after the window was dismissed -> no exception."""
    captured, hook = _debounce_spy()

    async def sc(app, pilot, modal, seen):
        modal.query_one("#a2l_list_text", TextArea).text = G2L_TEXT
        await pilot.pause()
        assert captured, "the text change scheduled no preview"
        modal.dismiss(None)
        await pilot.pause()
        captured[-1]()
        await pilot.pause()
        return app.is_running

    _, running, _ = run_modal(monkeypatch, enriched, names, sc, hook=hook)
    assert running


def test_r_a2l_list_086_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.086/2: a preview due after the app stopped -> no exception."""
    captured, hook = _debounce_spy()

    async def sc(app, pilot, modal, seen):
        modal.query_one("#a2l_list_text", TextArea).text = G2L_TEXT
        await pilot.pause()
        assert captured

    async def after(app, ctx, seen):
        captured[-1]()

    app, _, _ = run_modal(monkeypatch, enriched, names, sc, hook=hook, after=after)
    assert app.is_running is False


def test_r_a2l_list_086_3(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.086/3: positive arm, the debounce run while the window is open paints the counts line."""
    captured, hook = _debounce_spy()

    async def sc(app, pilot, modal, seen):
        modal.query_one("#a2l_list_text", TextArea).text = G2L_TEXT
        await pilot.pause()
        before = said(modal, "a2l_list_counts")
        captured[-1]()
        await pilot.pause()
        return before, said(modal, "a2l_list_counts")

    _, (before, after), _ = run_modal(monkeypatch, enriched, names, sc, hook=hook)
    assert "12 pasted" not in before and "12 pasted" in after


def test_r_a2l_list_085_4(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.085/4: the window dismissed with its similar ranking held -> released, no error."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)

    async def sc(app, pilot, modal, seen):
        modal.query_one("#a2l_list_text", TextArea).text = "VALUE_002\n"
        await pilot.pause(0.3)
        await wait_until(pilot, lambda: spy.entered.is_set(), "the similar ranking started")
        modal.dismiss(None)
        await pilot.pause()
        spy.gate.set()
        await settle_workers(pilot)
        await settle(pilot)
        return app.is_running

    app, running, seen = run_modal(monkeypatch, enriched, names, sc)
    assert running and worker_errors(seen) == [] and app._exception is None


def test_r_a2l_list_075_2(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.075/2 (E3S-04): 11 missing names, rankings held, 3 edits -> <= 2 rank calls per slot, <= 20."""
    spy = Hold(real_seam("rank"))
    patch_seam(monkeypatch, "rank", spy)
    base = [f"NOSUCH_{i:03d}" for i in range(11)]

    async def sc(app, pilot, modal, seen):
        for suffix in ("a", "b", "c"):
            await type_text_nowait(pilot, modal, "\n".join(n + suffix for n in base))
        spy.gate.set()
        await settle_workers(pilot)
        await settle(pilot)

    _, _, _ = run_modal(monkeypatch, enriched, names, sc)
    from collections import Counter

    per_slot = Counter(call[0][:10] for call in spy.calls)
    assert len(per_slot) == 11 and max(per_slot.values()) <= 2 and len(spy.calls) <= 20


async def type_text_nowait(pilot, modal, text: str) -> None:
    modal.query_one("#a2l_list_text", TextArea).text = text
    await pilot.pause(0.3)


def test_r_a2l_list_076_4(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.076/4: a pasted name with markup, ESC and NUL -> its preview row paints the display text."""
    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, PASTED_HOST + "\n")
        return paste_rows(modal)

    _, rows, _ = run_modal(monkeypatch, enriched, names, sc)
    assert rows[0][1] == "✗ " + PASTED_SHOWN


def test_r_a2l_list_076_5(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.076/5: the similar line of a pasted hostile name paints the display text."""
    text = _similar_lines(monkeypatch, enriched, names, PASTED_HOST + "\n")
    assert f"similar to #1 {PASTED_SHOWN}:" in text and "\x1b" not in text


def test_r_a2l_list_077_1_similar_line(ll, names, enriched, monkeypatch) -> None:
    """R-A2L-LIST.077/1: a 300-character missing name -> its similar line shows 63 characters + ``…``, then ``none``."""
    name = "N" * 300
    text = _similar_lines(monkeypatch, enriched, names, name + "\n")
    assert f"  similar to #1 {name[:63]}…: none (digits must match exactly)" in text
