"""Batch-103 Inc 9b E4 (tester T9b-S): the stepped record-stage write and refresh - R-PE-BENCH.98/2, .101/3, .101/4, .106/1, .106/2,
plus the regression R-PE-DEF.62 / batch-48 LLR-081.3 (the synchronous refresh callers repaint in the same call).

Operator need (P-127): a record stage that freezes the screen makes users force-quit the application ("de otra manera los
usuarios forzarán terminado de la aplicación"); the stage's write and refresh are therefore cut into steps with the event loop
free between them, and the cue must leave the window the moment the stage ends, whatever way it ended.

Everything drives the shipped chain (the real ``S19TuiApp`` under Textual Pilot at 118 x 54, keys through ``pilot.press``, the
Undo button, ``request_action``); the cue is read from the PAINTED top border of ``#patch_sheet_win`` (compositor), never from
``styles`` alone (E4-pilots P2). Expected values come from the requirements (``inc-9b/01-requirements.md``), from I-2's own
encode and from a full refresh of the same document (``_refresh_patch_history_view``, the base's synchronous refresh);
nothing is read from the implementation of the steps. A held job is held by ``Gate`` around I-2 (never a product hook).

Base state (P9b tip bcb22640): the write and refresh run in ONE UI-thread call and no busy cue exists, so every node that
needs the interleaved state or the cue is RED by assertion; the regression node passes on base (the behaviour it guards exists).
The two scheduler-contract nodes added by the integrator drive the real app's method with its timer captured: a later-step
raise and a panel gone must each release the record hold exactly once.
"""
from __future__ import annotations

import time

import pytest
from rich.style import Style
from textual.widgets import Button, DataTable, TextArea

from s19_app.tui.a2l_definition import Encoded, describe_definition, encode_values
from s19_app.tui.app.shell import _BUSY_LINE
from s19_app.tui.definition_bench_view import EDIT
from tests.b97_probes import painted_rows, painted_style
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    VB, Gate, apply_tool, defc_dir, entries_of, need, open_bench, run, sheet_of, st, wait_for,
)
from tests.support.timing import report_margin

NO_A2L = "Patch Editor: no A2L is loaded — nothing staged."
IDLE_LATENCY_S = 0.3  # R-PE-BENCH.101: the idle look within 0.3 s
VB_ADDRESS = 0x800090
TABLE, JSON_VIEW, WIN = "#patch_doc_entries_table", "#patch_json_view", "#patch_sheet_win"


# ------------------------------------------------------------------ drivers


def amber() -> str:
    """The busy colour: the foreground of ``definition_bench_view.EDIT`` (never a typed literal)."""
    r, g, b = Style.parse(EDIT).color.triplet
    return f"#{r:02x}{g:02x}{b:02x}"


def corner_hex(app, win):
    """The painted foreground of the window's top-left border cell, as ``#rrggbb`` (None when not a truecolour)."""
    style = painted_style(app, win.region.x, win.region.y)
    colour = getattr(style, "color", None)
    triplet = getattr(colour, "triplet", None)
    return None if triplet is None else "#%02x%02x%02x" % tuple(triplet)


def top_row(app, win) -> str:
    return painted_rows(app, win)[0]


def busy_look(app, win, name: str) -> bool:
    """The cue paints: amber border and a title holding ``BUSY`` and ``stage <name>`` (R-PE-BENCH.94/3, .96)."""
    row = top_row(app, win)
    return "BUSY" in row and f"stage {name}" in row and corner_hex(app, win) == amber()


def idle_look(app, win) -> bool:
    """The window is idle: ``STAGING SHEET`` titled, no busy word, border not amber (R-PE-BENCH.101)."""
    row = top_row(app, win)
    return "STAGING SHEET" in row and "BUSY" not in row and corner_hex(app, win) != amber()


def stamped_statuses(monkeypatch) -> list:
    """Every status line any ``S19TuiApp`` writes, as ``(time.monotonic(), message)``."""
    from s19_app.tui.app import S19TuiApp

    seen: list = []
    original = S19TuiApp.set_status

    def recording(self, message: str) -> None:
        seen.append((time.monotonic(), message))
        original(self, message)

    monkeypatch.setattr(S19TuiApp, "set_status", recording)
    return seen


def model_encode(app, name: str, edit: dict):
    """What I-2 encodes ``edit`` to for ``name`` over the app's own A2L and image (the oracle of every byte)."""
    a2l = app.current_a2l_data
    return encode_values(describe_definition(name, a2l), a2l, edit, dict(app.current_file.mem_map))


async def make_edit(pilot, sheet, name, key, operand):
    """``name``'s bench opened, ``key`` ``operand`` applied, its preview done."""
    await open_bench(pilot, sheet, name)
    await apply_tool(pilot, sheet, key, operand)
    await wait_for(pilot, lambda: bool(st(sheet, name).edit), f"the bench edit of {name}")
    await wait_for(pilot, lambda: st(sheet, name).preview is not None, f"the preview of {name}", 60)


def digest(panel, sheet) -> tuple:
    """What a refresh paints: the ledger's rows, the JSON view's text, the sheet's rows (name, staged mark, decodes)."""
    table = need(panel, TABLE, DataTable)
    ledger = tuple(tuple(str(cell) for cell in table.get_row_at(i)) for i in range(table.row_count))
    marks = tuple((r.name, r.is_staged, repr(r.current), repr(r.staged)) for r in sheet.rows)
    return ledger, need(panel, JSON_VIEW, TextArea).text, marks


async def quiet_digest(pilot, panel, sheet, quiet: float = 1.0, limit: float = 30.0) -> tuple:
    """The digest once it has not changed for ``quiet`` seconds (longer than every step gap plus the largest step)."""
    last, since, end = digest(panel, sheet), time.monotonic(), time.monotonic() + limit
    while time.monotonic() < end:
        await pilot.pause(0.05)
        now = digest(panel, sheet)
        if now != last:
            last, since = now, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return now
    raise AssertionError(f"the refresh never went quiet within {limit} s")


async def alt_s_and_catch_the_write(pilot, app, panel, before_count: int = 0) -> int:
    """alt+s, then poll (event loop free) until the document holds the entry; return the ledger's row count at that
    moment. In a stepped refresh the ledger is still empty (step 2 has not run); in a one-call write and refresh it is full."""
    table = need(panel, TABLE, DataTable)
    await pilot.press("alt+s")
    end = time.monotonic() + 60
    while len(entries_of(app)) != before_count + 1:
        assert time.monotonic() < end, "the record stage never wrote its entry"
        await pilot.pause(0.003)
    return table.row_count


# ------------------------------------------------------------------ R-PE-BENCH.98/2


def test_r_pe_bench_98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh(tmp_path, defc_dir):
    """R-PE-BENCH.98/2 (EX-BC6). Operator need: the stage must not freeze the screen (P-127, forced termination otherwise).
    VAL_BLK_DEF_0001 Set `10`, alt+s: (a) the entry written is byte-equal to I-2's encode, one 12-byte `bytes` entry at
    0x800090 (the bytes base writes, R-PE-BENCH.70); (b) the event loop runs BETWEEN the write and the refresh: a sample
    taken while the document already holds the entry still finds the ledger without it; (c) the refresh ends complete: the
    ledger shows the entry and the sheet marks the row staged. Negative control: write and refresh in one call (base) never
    shows the half state (b); a wrong byte or address fails (a); a chain that stops early fails (c)."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        want = model_encode(app, VB, {(0, 0): "10"})
        assert isinstance(want, Encoded), want
        rows_at_write = await alt_s_and_catch_the_write(pilot, app, panel)
        written = entries_of(app)
        after = await quiet_digest(pilot, panel, sheet)
        return want, rows_at_write, written, after

    want, rows_at_write, written, (ledger, _json, marks) = run(tmp_path, defc_dir, body)
    assert written == [(VB_ADDRESS, bytes(want.data))] and len(want.data) == 12, written
    assert rows_at_write == 0, (
        f"the ledger already held {rows_at_write} row(s) when the entry appeared: the write and the refresh ran in one call"
    )
    assert len(ledger) == 1 and dict((m[0], m[1]) for m in marks)[VB] is True, (ledger, marks)


# ------------------------------------------------------------------ R-PE-BENCH.101/3, .101/4


async def refused_at_the_write(pilot, app, panel, gate, sabotage, statuses, message_of) -> tuple:
    """VB Set `10`, alt+s with the encode held; the cue must show; ``sabotage()`` makes the write refuse; release.
    Returns (latency in s from the refusal status to the first painted idle look, entries, job left on the bench state)."""
    sheet, win = sheet_of(panel), need(panel, WIN)
    await make_edit(pilot, sheet, VB, "s", "10")
    gate.hold.add(VB)
    try:
        await pilot.press("alt+s")
        await wait_for(pilot, gate.entered.is_set, "the record encode held")
        await wait_for(pilot, lambda: busy_look(app, win, VB), "the busy cue `stage VAL_BLK_DEF_0001` on the painted border", 5)
        message = sabotage()
    finally:
        gate.release()
    end = time.monotonic() + 5
    seen_at = None
    while time.monotonic() < end:
        await pilot.pause(0.01)
        stamp = next((t for t, m in statuses if m == message_of(message)), None)
        if stamp is not None and idle_look(app, win):
            seen_at = (time.monotonic(), stamp)
            break
    assert seen_at is not None, (
        f"no refusal status {message_of(message)!r} with an idle look within 5 s; top row {top_row(app, win)!r}; {statuses[-3:]}"
    )
    return seen_at[0] - seen_at[1], entries_of(app), st(sheet, VB).job


@pytest.mark.serial_timing
def test_r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.101/3 (EX-BC9). Operator need: a refused stage must not leave the window looking busy (P-127). The encode
    is held past the grace (the cue `stage VAL_BLK_DEF_0001` shows on the painted border), the A2L is unloaded, the encode is
    released: the write is refused (R-PE-BENCH.76, no entry) and the window is idle (STAGING SHEET, border not amber, no job)
    within 0.3 s of the refusal status. Negative control: a cue cleared only on success stays amber -> RED."""
    gate = Gate(monkeypatch, "encode_values")
    statuses = stamped_statuses(monkeypatch)

    async def body(app, pilot, panel):
        def sabotage():
            app.current_a2l_data = None
            return None

        return await refused_at_the_write(pilot, app, panel, gate, sabotage, statuses, lambda _m: NO_A2L)

    latency, entries, job = run(tmp_path, defc_dir, body)
    assert entries == [] and job is None, (entries, job)
    assert latency <= report_margin("R-PE-BENCH.101/3 idle after a refused write", latency, IDLE_LATENCY_S), (
        f"the idle look came {latency:.3f} s after the refusal; the bound is {IDLE_LATENCY_S} s"
    )


@pytest.mark.serial_timing
def test_r_pe_bench_101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.101/4 (EX-BC9). Same as .101/3 with a session action started during the held encode (R-PE-BENCH.83): the
    write is refused with the busy line, no entry, and the window is idle within 0.3 s of that status. Negative control: a
    record hold released only by the stepped refresh's end is never released on this refusal -> amber stays -> RED."""
    gate = Gate(monkeypatch, "encode_values")
    statuses = stamped_statuses(monkeypatch)

    async def body(app, pilot, panel):
        def sabotage():
            app._busy_begin_action("file_load", "x.s19")
            return app._running_session_action().label

        return await refused_at_the_write(pilot, app, panel, gate, sabotage, statuses, lambda label: _BUSY_LINE.format(label=label))

    latency, entries, job = run(tmp_path, defc_dir, body)
    assert entries == [] and job is None, (entries, job)
    assert latency <= report_margin("R-PE-BENCH.101/4 idle after a refused write", latency, IDLE_LATENCY_S), (
        f"the idle look came {latency:.3f} s after the refusal; the bound is {IDLE_LATENCY_S} s"
    )


# ------------------------------------------------------------------ R-PE-BENCH.106/1, .106/2


async def undone_or_applied_between_steps(pilot, app, panel, act):
    """Capture the second step's timer without blocking the UI, process ``act``, then run the held callback; the token log proves the interleaving."""
    sheet = sheet_of(panel)
    await make_edit(pilot, sheet, VB, "s", "10")
    before = digest(panel, sheet)
    callbacks, tokens = [], []
    real_set_timer = app.set_timer
    real_token = app._patch_document_token

    def hold_timer(_delay, callback):
        callbacks.append(callback)

    def token_probe():
        token = real_token()
        tokens.append(token)
        return token

    app.set_timer = hold_timer
    app._patch_document_token = token_probe
    try:
        await pilot.press("alt+s")
        rows_at_write = need(panel, TABLE, DataTable).row_count
        assert len(callbacks) == 1, f"the second refresh step was not held exactly once: {len(callbacks)}"
        act()
        await pilot.pause(0.2)
        callbacks.pop(0)()
        await pilot.pause(0.2)
        settled = await quiet_digest(pilot, panel, sheet)
        app._refresh_patch_history_view()
        await pilot.pause(0.2)
        return before, rows_at_write, settled, digest(panel, sheet), tokens
    finally:
        app.__dict__.pop("set_timer", None)
        app.__dict__.pop("_patch_document_token", None)


def test_r_pe_bench_106_1_an_undo_between_two_refresh_steps_leaves_the_undone_document_everywhere(tmp_path, defc_dir):
    """R-PE-BENCH.106/1 (EX-BC14). Operator need: the stage's slow refresh must not paint an out-of-date document after the
    operator's Undo (P-127). VAL_BLK_DEF_0001 alt+s, Undo pressed as soon as the write shows (the ledger is still empty: the
    Undo lands between steps): when the refresh ends, the ledger rows, the JSON view text and the sheet's marks equal those a
    full refresh of the undone document paints, and equal the empty document's before the stage. Negative control: later steps
    that keep the document serialized in the first step repaint the stage entry in the JSON view -> RED."""

    async def body(app, pilot, panel):
        undo = need(panel, "#patch_undo_button", Button)
        return await undone_or_applied_between_steps(pilot, app, panel, undo.press), entries_of(app)

    (before, rows_at_write, settled, full, tokens), entries = run(tmp_path, defc_dir, body)
    assert rows_at_write == 0, "the Undo was not between steps: the ledger was already refreshed when the entry appeared"
    assert entries == [], entries
    assert tokens and any(token != tokens[0] for token in tokens[1:]), f"the action was not observed before the chain ended: {tokens!r}"
    assert settled == full, f"the stepped refresh ended on a different document than a full refresh:\n{settled}\n{full}"
    assert settled[0] == () and settled[1] == before[1] and not any(m[1] for m in settled[2]), settled


def test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere(tmp_path, defc_dir):
    """R-PE-BENCH.106/2 (EX-BC14). Same as .106/1 with an Apply of the change document handled between steps (the Apply
    changes the image under the sheet and the ledger's states): when the refresh ends, the ledger, the JSON view and the
    sheet's marks equal a full refresh of the applied document. A save-back prompt the Apply opens is dismissed with escape.
    Negative control: a later step repainting the pre-apply sheet or ledger differs from the full refresh -> RED."""

    async def body(app, pilot, panel):
        def apply():
            panel.request_action("apply_doc")

        result = await undone_or_applied_between_steps(pilot, app, panel, apply)
        if app.screen is not panel.screen:
            await pilot.press("escape")
            await pilot.pause(0.3)
        return result, entries_of(app)

    (before, rows_at_write, settled, full, tokens), entries = run(tmp_path, defc_dir, body)
    assert rows_at_write == 0, "the Apply was not between steps: the ledger was already refreshed when the entry appeared"
    assert len(entries) == 1, entries
    assert tokens and any(token != tokens[0] for token in tokens[1:]), f"the action was not observed before the chain ended: {tokens!r}"
    assert settled == full, f"the stepped refresh ended on a different document than a full refresh:\n{settled}\n{full}"
    assert len(settled[0]) == 1 and dict((m[0], m[1]) for m in settled[2])[VB] is True, settled


# ------------------------------------------------------------------ regression R-PE-DEF.62 / LLR-081.3


def write_bytes_change(path):
    """A real v2 change document with one 12-byte entry at VAL_BLK_DEF_0001."""
    path.write_text(
        '{"format":"s19app-changeset","version":2.0,"kind":"change",'
        '"encoding":"utf-8","value_mode":"text","entries":['
        '{"type":"bytes","address":"0x800090",'
        '"bytes":"01 02 03 04 05 06 07 08 09 0A 0B 0C"}]}',
        encoding="utf-8",
    )
    return path


def test_e5_9b_hold_apply_bytes_entry_repaints_all_views_in_the_same_call(tmp_path, defc_dir):
    """E5 / HOLD-APPLY: the real Apply handler repaints before it returns.

    The roster's return-after-hook control is equivalent for these views:
    ``_note_image_bytes_written`` itself reaches ``_patch_editor_load_tail``.
    Removing the hook as well is the discriminating negative control.
    """
    from s19_app.tui.screens_directionb import PatchEditorPanel

    document = write_bytes_change(tmp_path / "hold-apply.json")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        app._patch_editor_load(panel, str(document))
        await pilot.pause()
        before = digest(panel, sheet)
        app.on_patch_editor_panel_action_requested(
            PatchEditorPanel.ActionRequested("apply_doc")
        )
        same_call = digest(panel, sheet)
        written = bytes(app.current_file.mem_map[VB_ADDRESS + i] for i in range(12))
        app._refresh_patch_history_view()
        return before, same_call, written, digest(panel, sheet)

    before, same_call, written, full = run(tmp_path, defc_dir, body)
    assert written == bytes(range(1, 13)), written
    assert len(before[0]) == 1 and len(same_call[0]) == 1, (before, same_call)
    assert same_call == full, f"Apply returned before a full repaint:\n{same_call}\n{full}"
    assert same_call != before, "Apply did not change the painted ledger/JSON/sheet state"


def test_e5_9b_hold_load_repaints_ledger_json_and_sheet_in_the_same_call(tmp_path, defc_dir):
    """E5 / HOLD-LOAD: ``_patch_editor_load`` completes its visible tail.

    No event-loop turn occurs between the real load caller and the digest.
    An early return from ``_patch_editor_load_tail`` therefore leaves the
    previous ledger, JSON text and sheet marks and fails this exact oracle.
    """
    document = write_bytes_change(tmp_path / "hold-load.json")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        before = digest(panel, sheet)
        app._patch_editor_load(panel, str(document))
        same_call = digest(panel, sheet)
        loaded_entries = entries_of(app)
        app._refresh_patch_history_view()
        return before, same_call, loaded_entries, digest(panel, sheet)

    before, same_call, loaded_entries, full = run(tmp_path, defc_dir, body)
    assert loaded_entries == [(VB_ADDRESS, bytes(range(1, 13)))], loaded_entries
    assert before[0] == () and before[1] != same_call[1], (before, same_call)
    assert len(same_call[0]) == 1, same_call[0]
    assert dict((m[0], m[1]) for m in same_call[2])[VB] is True, same_call[2]
    assert same_call == full, f"load returned before a full repaint:\n{same_call}\n{full}"


def test_r_pe_def_62_and_llr_081_3_the_synchronous_refresh_callers_repaint_in_the_same_call(tmp_path, defc_dir):
    """Regression (R-PE-DEF.62: the sheet follows every document change; batch-48 LLR-081.3: the history strip follows the
    depths). Operator need: Undo / Redo and the other synchronous refreshes stay instant (P-127). The refresh that serves the
    Undo / Redo buttons and every other synchronous caller (``_refresh_patch_history_view``) paints the ledger, the JSON view
    BEFORE it returns (no event-loop turn, no timer), and the sheet's marks after one
    loop turn; Undo and Redo through their buttons are complete after ONE ``pilot.pause()`` (no step gap is waited).
    Negative control: a chained refresh (timer-separated steps) has not repainted the ledger when the call returns -> RED."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        table, json_view = need(panel, TABLE, DataTable), need(panel, JSON_VIEW, TextArea)
        undo, redo = need(panel, "#patch_undo_button", Button), need(panel, "#patch_redo_button", Button)
        empty_json = json_view.text
        encoded = model_encode(app, VB, {(0, 0): "10"})
        assert isinstance(encoded, Encoded), encoded
        assert app._change_service.stage_record(VB, encoded, 1).ok
        app._refresh_patch_history_view()  # no await: the refresh must be complete when it returns
        same_call = (table.row_count, json_view.text != empty_json)
        await pilot.pause()
        staged_marks = [m[1] for m in digest(panel, sheet)[2] if m[0] == VB]
        undo.press()
        await pilot.pause()
        after_undo = (table.row_count, json_view.text == empty_json,
                      [m[1] for m in digest(panel, sheet)[2] if m[0] == VB])
        redo.press()
        await pilot.pause()
        after_redo = (table.row_count, json_view.text != empty_json,
                      [m[1] for m in digest(panel, sheet)[2] if m[0] == VB])
        return same_call, staged_marks, after_undo, after_redo

    same_call, staged_marks, after_undo, after_redo = run(tmp_path, defc_dir, body)
    assert same_call == (1, True), same_call
    assert staged_marks == [True], staged_marks
    assert after_undo == (0, True, [False]), after_undo
    assert after_redo == (1, True, [True]), after_redo


# ------------------------------------------------------- scheduler contracts from the E4 hand-back


def test_r_pe_bench_98_2_a_later_step_raise_releases_record_done_exactly_once(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.98/2 scheduler contract: a raise in a timer step calls on_done once and re-raises."""

    async def body(app, pilot, panel):
        callbacks, calls = [], []
        monkeypatch.setattr(app, "set_timer", lambda _delay, callback: callbacks.append(callback))

        def raises():
            calls.append("raise")
            raise RuntimeError("later refresh step")

        try:
            app._run_refresh_steps(
                [lambda: calls.append("first"), raises, lambda: calls.append("unreached")],
                lambda: calls.append("done"),
            )
            assert len(callbacks) == 1
            with pytest.raises(RuntimeError, match="later refresh step"):
                callbacks.pop(0)()
        finally:
            app.__dict__.pop("set_timer", None)
        return calls, callbacks

    calls, callbacks = run(tmp_path, defc_dir, body)
    assert calls == ["first", "raise", "done"], calls
    assert callbacks == [], callbacks


def test_r_pe_bench_98_2_a_panel_gone_skips_the_tail_and_releases_record_done_exactly_once(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.98/2 teardown contract: no panel skips later steps and still calls on_done once."""

    async def body(app, pilot, panel):
        callbacks, calls = [], []
        monkeypatch.setattr(app, "set_timer", lambda _delay, callback: callbacks.append(callback))
        monkeypatch.setattr(app, "query", lambda _selector: [])
        try:
            app._run_refresh_steps(
                [lambda: calls.append("first"), lambda: calls.append("unreached")],
                lambda: calls.append("done"),
            )
            assert len(callbacks) == 1
            callbacks.pop(0)()
        finally:
            app.__dict__.pop("set_timer", None)
            app.__dict__.pop("query", None)
        return calls, callbacks

    calls, callbacks = run(tmp_path, defc_dir, body)
    assert calls == ["first", "done"], calls
    assert callbacks == [], callbacks
