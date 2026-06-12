"""Operations view pilot tests (batch-08 I3 — HLR-004).

Coverage map (TC-010..TC-012):

- LLR-004.1 — ``test_operations_view_lists_registry_ids`` (TC-010): the
  key-bound ``x`` action pushes ``OperationsScreen`` listing exactly the
  registry's 3 operation ids (``crc``, ``extract``, ``split_by_segment``)
  in registry order, each row labelled with its operation ``title``; the
  no-file guard (LLR-004.2) bails with one status line and pushes no
  screen and invokes no service.
- LLR-004.2 — ``test_operations_view_executes_via_service`` (TC-011):
  executing the selected operation presents ``status: placeholder`` plus
  the exact LLR-002.1 placeholder note; the service seam is observed — a
  stub injected through the LLR-003.1 ``operation_resolver`` seam is what
  executes (a view bypassing ``run_operation`` would never reach the
  stub), with the same loaded snapshot the app passed to the screen.
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
    """Execute shows the placeholder result; the service seam is observed.

    Intent: LLR-004.2 — phase A executes the real ``crc`` placeholder and
    the presented text carries ``status: placeholder`` plus the exact
    LLR-002.1 note. Phase B injects a stub through the LLR-003.1
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
    assert "status: placeholder" in status_text, status_text
    assert "placeholder: crc not yet implemented" in status_text, status_text

    calls: list[LoadedFile] = []

    class _StubOperation:
        operation_id = "crc"
        title = "CRC"

        def describe(self) -> str:
            return "stub"

        def execute(self, loaded: LoadedFile, *, now_fn=None) -> OperationResult:
            calls.append(loaded)
            return OperationResult(
                operation_id="crc",
                status="placeholder",
                input_path=loaded.path,
                variant_id=loaded.variant_id,
                output=loaded,
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
            same_snapshot = bool(calls) and calls[0] is app.current_file
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
    ``#operation_result_hex`` widget after the modal executed the ``crc``
    placeholder. For an identity-passthrough result the two must be equal
    (the end-to-end unchanged-image acceptance demo). Status and note
    visibility ride along per the TC-012 threshold.
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
    assert "status: placeholder" in status_text, status_text
    assert "placeholder: crc not yet implemented" in status_text, status_text
