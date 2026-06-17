"""Operations view pilot tests (batch-08 I3 — HLR-004).

Coverage map (TC-010..TC-012):

- LLR-004.1 — ``test_operations_view_lists_registry_ids`` (TC-010): the
  key-bound ``x`` action pushes ``OperationsScreen`` listing exactly the
  registry's 3 operation ids (``crc``, ``extract``, ``split_by_segment``)
  in registry order, each row labelled with its operation ``title``; the
  no-file guard (LLR-004.2) bails with one status line and pushes no
  screen and invokes no service.
- LLR-004.2 — ``test_operations_view_executes_via_service`` (TC-011):
  executing the selected ``crc`` operation through the generic (no-config)
  service path presents ``status: ok`` plus the nothing-to-check note; the
  service seam is observed — a stub injected through the LLR-003.1
  ``operation_resolver`` seam is what executes (a view bypassing
  ``run_operation`` would never reach the stub), with the same loaded
  snapshot the app passed to the screen.
- LLR-004.3 — ``test_operations_view_result_hex_render_matches_baseline``
  (TC-012): the live ``#operation_result_hex`` widget text (``.plain``)
  equals a baseline computed INDEPENDENTLY in the test by calling
  ``render_hex_view_text`` on the INPUT snapshot's ``mem_map`` with the
  LLR-004.3 pinned argument tuple (``focus_address=None, row_bases=None,
  highlight=None, mac_highlight_addresses=None, max_rows=MAX_HEX_ROWS``)
  — non-vacuous by construction: widget-side text vs test-side baseline,
  never ``result.output`` compared with itself.

Harness: the ``App.run_test()`` pilot pattern of ``tests/test_tui_app.py``
/ ``tests/test_tui_variants.py`` — ``async def _drive()`` wrapped by
``asyncio.run``, the ``_flush`` pump, assertions via ``query_one``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Button, Label, ListItem, ListView, Static

import s19_app.tui.services.operation_service as operation_service_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.hexview import MAX_HEX_ROWS, render_hex_view_text
from s19_app.tui.models import LoadedFile
from s19_app.tui.operations import OperationResult
from s19_app.tui.operations.model import OperationInput
from s19_app.tui.screens import OperationsScreen

# Minimal valid S19 image (checksum verified against s19_app.core.S19File):
# four data bytes 01 02 03 04 at address 0x1000.
S19_A = "S107100001020304DE\nS9030000FC\n"

#: Registry order pinned by LLR-002.2 — the literal TC-010 expectation.
EXPECTED_IDS = ["crc", "extract", "split_by_segment"]
EXPECTED_TITLES = ["CRC", "Extract", "Split by segment"]


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred ``call_later`` apply chain runs."""
    for _ in range(count):
        await pilot.pause()


async def _load_file(app: S19TuiApp, pilot, path: Path) -> None:
    """Load one file through the real worker pipeline and wait for apply."""
    app.load_from_path(path)
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


def _write_s19(tmp_path: Path) -> Path:
    s19_path = tmp_path / "a.s19"
    s19_path.write_text(S19_A, encoding="utf-8")
    return s19_path


# ---------------------------------------------------------------------------
# TC-010 / LLR-004.1 — listing + key binding + no-file guard
# ---------------------------------------------------------------------------


def test_operations_view_lists_registry_ids(tmp_path: Path) -> None:
    """Key ``x`` opens the modal listing exactly the 3 registry operations.

    Intent: LLR-004.1 — the ``x`` binding routes to
    ``action_operations_view``; the screen receives caller-pre-computed
    ``(operation_id, title)`` pairs equal to the literal registry order and
    labels each row with the operation title. LLR-004.2 guard: with no file
    loaded the action sets one status line and pushes no screen.
    """
    s19_path = _write_s19(tmp_path)

    async def _drive_loaded() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            stack_before = len(app.screen_stack)
            await pilot.press("x")
            await _flush(pilot)
            screen = app.screen
            is_modal = isinstance(screen, OperationsScreen)
            ids = [oid for oid, _ in screen.options] if is_modal else []
            labels = (
                [
                    str(item.query_one(Label).content)
                    for item in screen.query_one(
                        "#operations_list", ListView
                    ).query(ListItem)
                ]
                if is_modal
                else []
            )
            return len(app.screen_stack) - stack_before, is_modal, ids, labels

    pushed, is_modal, ids, labels = asyncio.run(_drive_loaded())
    assert pushed == 1, "pressing 'x' with a file loaded must push the modal"
    assert is_modal, "the pushed screen must be OperationsScreen"
    assert ids == EXPECTED_IDS, f"listed ids must equal the registry order: {ids}"
    assert len(labels) == 3, f"exactly one row per registry id: {labels}"
    for label, title in zip(labels, EXPECTED_TITLES):
        assert title in label, f"row label {label!r} must contain title {title!r}"

    async def _drive_no_file() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            stack_before = len(app.screen_stack)
            await pilot.press("x")
            await _flush(pilot)
            return len(app.screen_stack) - stack_before, list(app.log_lines)

    pushed_no_file, log_lines = asyncio.run(_drive_no_file())
    assert pushed_no_file == 0, "no modal must open without a loaded file"
    assert any("no file loaded" in line for line in log_lines), log_lines


# ---------------------------------------------------------------------------
# TC-011 / LLR-004.2 — execution exclusively through run_operation
# ---------------------------------------------------------------------------


def test_operations_view_executes_via_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute shows the crc result; the service seam is observed.

    Intent: LLR-004.2 — phase A executes the real ``crc`` operation through
    the generic no-config service path and the presented text carries
    ``status: ok`` plus the nothing-to-check note. Phase B injects a stub
    through the LLR-003.1
    ``operation_resolver`` seam: the stub is what executes (with the same
    snapshot the app handed to the screen), proving the view routes through
    ``run_operation`` and never bypasses the service — a direct
    ``registry.get_operation(...).execute(...)`` call in the view would
    leave the stub unreached and fail here.
    """
    s19_path = _write_s19(tmp_path)

    async def _drive_real() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            app.action_operations_view()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, OperationsScreen)
            screen.query_one("#operations_list", ListView).index = 0
            await pilot.pause()
            screen.query_one("#operations_execute", Button).press()
            await pilot.pause()
            return str(
                screen.query_one("#operation_result_status", Static).content
            )

    status_text = asyncio.run(_drive_real())
    assert "status: ok" in status_text, status_text
    assert "CRC: no config supplied — nothing to check" in status_text, status_text

    calls: list[OperationInput] = []

    class _StubOperation:
        operation_id = "crc"
        title = "CRC"

        def describe(self) -> str:
            return "stub"

        def execute(self, op_input: OperationInput, *, now_fn=None) -> OperationResult:
            calls.append(op_input)
            output = LoadedFile(
                path=op_input.input_path,
                file_type=op_input.file_type,
                mem_map=op_input.mem_map,
                row_bases=[],
                ranges=op_input.ranges,
                range_validity=[],
                errors=[],
                a2l_path=None,
                a2l_data=None,
                variant_id=op_input.variant_id,
            )
            return OperationResult(
                operation_id="crc",
                status="placeholder",
                input_path=op_input.input_path,
                variant_id=op_input.variant_id,
                output=output,
                notes=["stub note: seam substitution observed"],
                timestamp_utc="2026-06-11T00:00:00+00:00",
            )

    monkeypatch.setattr(
        operation_service_module,
        "operation_resolver",
        lambda operation_id: _StubOperation(),
    )

    async def _drive_stub() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            app.action_operations_view()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, OperationsScreen)
            screen.query_one("#operations_list", ListView).index = 0
            await pilot.pause()
            screen.query_one("#operations_execute", Button).press()
            await pilot.pause()
            stub_text = str(
                screen.query_one("#operation_result_status", Static).content
            )
            same_snapshot = (
                bool(calls)
                and app.current_file is not None
                and calls[0].mem_map is app.current_file.mem_map
            )
            return stub_text, same_snapshot

    stub_text, same_snapshot = asyncio.run(_drive_stub())
    assert len(calls) == 1, "exactly one execution must reach the seam stub"
    assert same_snapshot, "the stub must receive the app's current snapshot"
    assert "stub note: seam substitution observed" in stub_text, stub_text


# ---------------------------------------------------------------------------
# TC-012 / LLR-004.3 — pinned hex render equals the independent baseline
# ---------------------------------------------------------------------------


def test_operations_view_result_hex_render_matches_baseline(
    tmp_path: Path,
) -> None:
    """Live widget hex text equals the test-side pinned-args baseline.

    Intent: LLR-004.3 — the baseline is computed INDEPENDENTLY here, on the
    INPUT snapshot's ``mem_map`` (captured before execution), with the
    pinned argument tuple; the compared text is read from the LIVE
    ``#operation_result_hex`` widget after the modal executed the real
    ``crc`` operation with no config. The check path never mutates
    ``mem_map``, so the two hex texts must be equal (the end-to-end
    unchanged-image acceptance demo). Status and note visibility ride along
    per the TC-012 threshold.
    """
    s19_path = _write_s19(tmp_path)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            loaded = app.current_file
            assert loaded is not None
            baseline_plain = render_hex_view_text(
                loaded.mem_map,
                focus_address=None,
                row_bases=None,
                highlight=None,
                mac_highlight_addresses=None,
                max_rows=MAX_HEX_ROWS,
            ).plain
            app.action_operations_view()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, OperationsScreen)
            screen.query_one("#operations_list", ListView).index = 0
            await pilot.pause()
            screen.query_one("#operations_execute", Button).press()
            await pilot.pause()
            widget_plain = screen.query_one(
                "#operation_result_hex", Static
            ).content.plain
            status_text = str(
                screen.query_one("#operation_result_status", Static).content
            )
            return widget_plain, baseline_plain, status_text

    widget_plain, baseline_plain, status_text = asyncio.run(_drive())
    assert widget_plain == baseline_plain, (
        "the live widget hex text must equal the independently computed "
        "pinned-args baseline"
    )
    assert "0x00001000" in widget_plain, widget_plain[:80]
    assert "status: ok" in status_text, status_text
    assert "CRC: no config supplied — nothing to check" in status_text, status_text


# ---------------------------------------------------------------------------
# TC-013 / LLR-005.2 (M-3) — KeyError scope excludes execution
# ---------------------------------------------------------------------------


def test_execute_internal_keyerror_not_masked_as_unknown_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A KeyError raised INSIDE ``.execute`` propagates; only a registry
    miss is reported as "unknown operation".

    Intent: LLR-005.2 (M-3) — the ``except KeyError`` in
    ``_execute_selected`` guards ONLY the ``operation_resolver`` registry
    resolution. Phase A: a resolver that raises ``KeyError`` (a registry
    miss) surfaces exactly one "unknown operation" status line and no crash.
    Phase B: a stub that RESOLVES cleanly but whose ``.execute`` raises
    ``KeyError`` must NOT be reported as "unknown operation" — the catch is
    narrow enough to let the execute-internal error escape (proving the
    resolve/execute split). A wide catch would mask it and fail here.
    """
    s19_path = _write_s19(tmp_path)

    # Phase A — a registry miss (resolver raises) IS reported as unknown.
    def _missing_resolver(operation_id: str):
        raise KeyError(operation_id)

    monkeypatch.setattr(
        operation_service_module, "operation_resolver", _missing_resolver
    )

    async def _drive_miss() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            app.action_operations_view()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, OperationsScreen)
            screen.query_one("#operations_list", ListView).index = 0
            await pilot.pause()
            screen.query_one("#operations_execute", Button).press()
            await pilot.pause()
            return list(app.log_lines)

    miss_log = asyncio.run(_drive_miss())
    assert any("unknown operation" in line for line in miss_log), miss_log

    # Phase B — resolve succeeds, .execute raises KeyError: NOT masked.
    class _ExecKeyErrorOperation:
        operation_id = "crc"
        title = "CRC"

        def describe(self) -> str:
            return "stub"

        def execute(self, op_input: OperationInput, *, now_fn=None) -> OperationResult:
            raise KeyError("internal lookup miss inside execute")

    monkeypatch.setattr(
        operation_service_module,
        "operation_resolver",
        lambda operation_id: _ExecKeyErrorOperation(),
    )

    async def _drive_exec_error() -> tuple[bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            app.action_operations_view()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, OperationsScreen)
            screen.query_one("#operations_list", ListView).index = 0
            await pilot.pause()
            raised = False
            try:
                screen._execute_selected()
            except KeyError:
                raised = True
            return raised, list(app.log_lines)

    raised, exec_log = asyncio.run(_drive_exec_error())
    assert raised, (
        "a KeyError raised inside .execute must propagate, not be swallowed "
        "by the registry-miss catch"
    )
    assert not any("unknown operation" in line for line in exec_log), (
        "an execute-internal KeyError must NOT be misreported as "
        f"'unknown operation': {exec_log}"
    )


# ---------------------------------------------------------------------------
# TC-012-N3 / LLR-005.1 (N-3) — screen-unique button-row id, styling intact
# ---------------------------------------------------------------------------


def test_operations_button_row_has_screen_unique_id(tmp_path: Path) -> None:
    """The OperationsScreen button row uses ``operations_buttons`` (not the
    retired shared ``load_buttons``) and keeps the ``.modal-buttons`` class.

    Intent: LLR-005.1 (N-3) — the de-collided per-screen id resolves, the
    old shared id does not, and the styling that ``.modal-buttons`` provides
    is co-applied so no layout is lost by dropping the borrowed id.
    """
    from textual.containers import Container

    s19_path = _write_s19(tmp_path)

    async def _drive() -> tuple[bool, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            app.action_operations_view()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, OperationsScreen)
            row = screen.query_one("#operations_buttons", Container)
            has_unique_id = row.id == "operations_buttons"
            has_modal_class = row.has_class("modal-buttons")
            old_id_gone = len(screen.query("#load_buttons")) == 0
            return has_unique_id, has_modal_class, old_id_gone

    has_unique_id, has_modal_class, old_id_gone = asyncio.run(_drive())
    assert has_unique_id, "the button row must use the screen-unique id"
    assert has_modal_class, ".modal-buttons styling must be preserved"
    assert old_id_gone, "the retired shared load_buttons id must be gone"
