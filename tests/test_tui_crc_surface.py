"""CRC TUI surface pilot tests (batch-12 CRC_F2, increment I3 — HLR-002/004).

Coverage map:

- TC-115 / LLR-002.4 (A-5 surface reachability) —
  ``test_crc_check_reaches_result_surface_via_handler``: an ``App.run_test()``
  pilot loads a synthetic S19, opens ``OperationsScreen``, selects ``crc``,
  asserts the config ``TextArea`` is pre-filled with the dummy template, then
  REPLACES it with a config matching the fixture and runs THROUGH the Execute
  handler (the shipped call-site, not a direct service call). It asserts one
  per-region row appears with the correct MATCH / MISMATCH verdict — proving
  the payload reaches the result surface through the handler.
- TC-116 / LLR-002.3 (R-6) — inspection in this file:
  ``test_crc_execute_path_uses_thread_worker`` asserts the CRC execute path is
  a Textual ``@work(thread=True)`` worker (``_run_crc_worker``), not a
  synchronous UI-thread call.
- F-L1 (carried from I3a review) —
  ``test_crc_config_error_surfaces_error_and_no_match``: a parse-error config
  surfaces the error notice and renders NO per-region row and NO "MATCH" — a
  no-config / error run must never read like a passed check.
- TC-124 / I5b two-stage confirmation —
  ``test_no_write_without_confirmation``: declining ``ConfirmWriteScreen``
  writes zero files and shows no emitted path; confirming emits exactly one
  ``*-crc.s19`` under the work area. Driven through the real button + modal.
- TC-125 / I5b through-handler (A-5) —
  ``test_crc_inject_reaches_surface_via_handler``: a confirmed write's emitted
  path + verify verdict reach the result surface via the handler; non-vacuous
  (asserts the verdict AND a real file on disk).

Harness: the ``App.run_test()`` pilot idiom of ``tests/test_tui_operations_view.py``
— ``async def _drive()`` wrapped by ``asyncio.run``, the ``_flush`` pump,
assertions via ``query_one``. All config values are SYNTHETIC.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from unittest import mock

from textual.widgets import Button, Input, ListView, Static, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.operations.crc import compute_region_crc, encode_le32
from s19_app.tui.operations.crc_config import DUMMY_CONFIG_TEXT, read_crc_config_text
from s19_app.tui.operations.model import CrcRegionResult, OperationResult
from s19_app.tui.screens import OperationsScreen

# --- Synthetic fixture geometry (all FAKE) ---------------------------------
# A contiguous CRC region [0x1000, 0x1004) of four data bytes, plus a 4-byte
# output slot at 0x2000 (a gap away) holding the stored CRC. The region and
# the output slot are emitted as two separate ranges so the output bytes
# never enter the CRC digest.
_REGION_START = 0x1000
_REGION_END = 0x1004
_OUTPUT_ADDRESS = 0x2000
_DATA = {0x1000: 0x31, 0x1001: 0x32, 0x1002: 0x33, 0x1003: 0x34}


def _config_text() -> str:
    """Build a synthetic CRC config JSON over the fixture region."""
    return (
        "{"
        '"polynomial":"0x04C11DB7","init":"0xFFFFFFFF",'
        '"reverse":true,"final_xor":"0xFFFFFFFF",'
        f'"regions":[{{"start":"0x{_REGION_START:X}","end":"0x{_REGION_END:X}",'
        f'"output_address":"0x{_OUTPUT_ADDRESS:X}"}}]'
        "}"
    )


def _write_fixture_s19(tmp_path: Path, *, stored_matches: bool) -> Path:
    """Emit a synthetic S19 whose stored CRC matches (or not) the region CRC.

    Uses the production ``emit_s19_from_mem_map`` so the file re-parses cleanly
    through the app pipeline; the stored 4 LE bytes at the output address are
    the CORRECT region CRC when ``stored_matches`` else a deliberately wrong
    value, so the through-handler verdict is deterministic.
    """
    expected = compute_region_crc(_DATA, _REGION_START, _REGION_END)
    stored = expected if stored_matches else (expected ^ 0xFFFFFFFF)
    stored_bytes = encode_le32(stored)

    mem_map = dict(_DATA)
    for offset, byte in enumerate(stored_bytes):
        mem_map[_OUTPUT_ADDRESS + offset] = byte
    ranges = [
        (_REGION_START, _REGION_END),
        (_OUTPUT_ADDRESS, _OUTPUT_ADDRESS + 4),
    ]
    text = emit_s19_from_mem_map(mem_map, ranges)
    path = tmp_path / "fixture.s19"
    path.write_text(text, encoding="utf-8")
    return path


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so the deferred apply chain + worker run."""
    for _ in range(count):
        await pilot.pause()


async def _load_file(app: S19TuiApp, pilot, path: Path) -> None:
    """Load one file through the real worker pipeline and wait for apply."""
    app.load_from_path(path)
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


async def _open_crc_screen(app: S19TuiApp, pilot) -> OperationsScreen:
    """Open OperationsScreen and select the crc row (index 0, registry order)."""
    app.action_operations_view()
    await pilot.pause()
    screen = app.screen
    assert isinstance(screen, OperationsScreen)
    screen.query_one("#operations_list", ListView).index = 0
    await _flush(pilot)
    return screen


# ---------------------------------------------------------------------------
# TC-115 / LLR-002.4 — per-region rows reach the surface THROUGH the handler
# ---------------------------------------------------------------------------


def test_crc_check_reaches_result_surface_via_handler(tmp_path: Path) -> None:
    """Dummy pre-fill, then a matching config runs through Execute → MATCH row.

    Intent (A-5 / TC-115): the config TextArea is pre-filled with the dummy
    template; replacing it with a fixture-matching config and pressing Execute
    routes the CRC check THROUGH the shipped handler (not a direct service
    call), and the per-region row appears in the result surface with the
    correct MATCH verdict. A separate mismatch fixture yields a MISMATCH row,
    so the verdict is non-vacuous (the test fails if the verdict is hardcoded).
    """

    async def _drive(stored_matches: bool) -> tuple[str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=stored_matches)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)
            prefill = screen.query_one("#operation_config", TextArea).text
            screen.query_one("#operation_config", TextArea).text = _config_text()
            screen.query_one("#operations_execute", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            return prefill, status

    # Pre-fill is the dummy template verbatim (format guidance).
    prefill_match, status_match = asyncio.run(_drive(stored_matches=True))
    assert prefill_match == DUMMY_CONFIG_TEXT, prefill_match

    # Matching stored CRC → one region row with a MATCH verdict, status ok.
    assert "status: ok" in status_match, status_match
    assert f"region @ 0x{_OUTPUT_ADDRESS:08X}" in status_match, status_match
    assert "MATCH" in status_match, status_match
    assert "MISMATCH" not in status_match, status_match

    # Mismatching stored CRC → the SAME row shows MISMATCH (non-vacuous).
    _, status_mismatch = asyncio.run(_drive(stored_matches=False))
    assert "MISMATCH" in status_mismatch, status_mismatch


# ---------------------------------------------------------------------------
# TC-116 / LLR-002.3 — CRC execute runs on a thread-worker (R-6)
# ---------------------------------------------------------------------------


def test_crc_execute_path_uses_thread_worker() -> None:
    """The CRC execute path is a @work(thread=True) worker, not a sync call.

    Intent (R-6 / LLR-002.3): inspection asserts ``_run_crc_worker`` carries
    the ``@work(thread=True)`` decorator (the ``app.py:1599`` ``execute_scope``
    precedent), so the side-effect-capable CRC execute never blocks the UI
    thread; and the CRC branch of the Execute handler dispatches to that
    worker rather than calling ``operation.execute`` synchronously. A
    regression that re-inlined a synchronous UI-thread execute on the CRC
    path would drop one of these and fail here.
    """
    # The worker method is decorated @work(thread=True) — Textual wraps it in
    # a closure with no public metadata, so the executed-at-import decorator
    # is verified at source level (the requirement's 1-hit inspection).
    worker_src = inspect.getsource(OperationsScreen)
    assert "@work(thread=True" in worker_src, (
        "OperationsScreen must carry a @work(thread=True ...) decorator"
    )
    assert "def _run_crc_worker(" in worker_src, worker_src[:200]

    # The CRC branch dispatches to the worker (not a synchronous execute).
    handler_src = inspect.getsource(OperationsScreen._execute_selected)
    assert "_run_crc_worker(" in handler_src, handler_src


# ---------------------------------------------------------------------------
# F-L1 — a config/parse error surfaces the error and shows NO matched result
# ---------------------------------------------------------------------------


def test_crc_config_error_surfaces_error_and_no_match(tmp_path: Path) -> None:
    """A parse-error config surfaces the error notice and renders no MATCH row.

    Intent (F-L1, carried from the I3a review): a no-config / parse-error run
    must NOT look like a passed check. Replacing the editor with malformed
    JSON and pressing Execute surfaces the config-error notice and renders
    zero per-region rows and no "MATCH" / "status: ok" — the green-pass
    appearance is reserved for an actual check.
    """

    async def _drive() -> tuple[str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)
            screen.query_one("#operation_config", TextArea).text = (
                "{ not valid json"
            )
            screen.query_one("#operations_execute", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            hex_widget = screen.query_one("#operation_result_hex", Static)
            hex_content = hex_widget.content
            hex_text = getattr(hex_content, "plain", str(hex_content))
            return status, hex_text

    status, hex_text = asyncio.run(_drive())
    assert OperationsScreen.NO_CONFIG_TEXT in status, status
    assert "MATCH" not in status, status
    assert "status: ok" not in status, status
    assert "region @" not in status, status
    # No hex render on the error path either (F-L1: not a completed run).
    assert hex_text == "", repr(hex_text)


# ---------------------------------------------------------------------------
# F1 — a stale in-flight worker must NOT overwrite the config-error surface
# ---------------------------------------------------------------------------


def test_stale_crc_worker_result_does_not_overwrite_error(tmp_path: Path) -> None:
    """A late worker from a superseded run cannot repaint the error surface.

    Intent (F1, I3b review): F-L1 must hold even under timing. Sequence: a
    valid CRC run completes (surface shows MATCH / status: ok), then the editor
    is set to malformed JSON and Execute pressed — the config-error branch
    paints ``NO_CONFIG_TEXT``. A thread worker cannot be interrupted once
    running, so a prior worker can still reach ``_present_result`` AFTER the
    error paint. We reproduce that exact landing deterministically by capturing
    the dispatch token from the valid run and delivering a stale ``status: ok``
    + MATCH result carrying that now-superseded token, the way the worker's
    ``call_from_thread`` would. The dispatch-token guard must DROP it, leaving
    the error surface intact.

    Pre-fix (no token guard, ``_present_result`` always painted) this stale
    result overwrites the error with ``status: ok`` + a MATCH row, defeating
    F-L1 by timing — so this test fails before the fix and passes after.
    """

    async def _drive() -> tuple[str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)

            # 1) A valid run completes and the surface shows the MATCH verdict.
            screen.query_one("#operation_config", TextArea).text = _config_text()
            screen.query_one("#operations_execute", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            stale_token = screen._crc_dispatch_token

            # 2) Drive the config-error branch — it bumps the token, cancels the
            #    worker group, and paints the F-L1 error notice.
            screen.query_one("#operation_config", TextArea).text = "{ not valid json"
            screen.query_one("#operations_execute", Button).press()
            await _flush(pilot)

            # 3) A stale worker from step (1) lands late, exactly as its
            #    ``call_from_thread(self._present_result, result, token)`` would.
            stale_result = OperationResult(
                operation_id=OperationsScreen.CRC_OPERATION_ID,
                status="ok",
                input_path=s19_path,
                variant_id=None,
                output=screen.loaded,
                notes=[],
                timestamp_utc="2026-06-16T00:00:00+00:00",
                crc_regions=[
                    CrcRegionResult(
                        output_address=_OUTPUT_ADDRESS,
                        computed_crc=0x1234,
                        stored_value=0x1234,
                        matched=True,
                        written=False,
                    )
                ],
            )
            screen._present_result(stale_result, stale_token)
            await _flush(pilot)

            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            hex_widget = screen.query_one("#operation_result_hex", Static)
            hex_content = hex_widget.content
            hex_text = getattr(hex_content, "plain", str(hex_content))
            return status, hex_text

    status, hex_text = asyncio.run(_drive())
    # The stale result was dropped: the error surface is intact.
    assert OperationsScreen.NO_CONFIG_TEXT in status, status
    assert "status: ok" not in status, status
    assert "MATCH" not in status, status
    assert "region @" not in status, status
    assert hex_text == "", repr(hex_text)


# ---------------------------------------------------------------------------
# US-013 CRC config-load helpers + fixtures (HLR-013, all 3 LLR)
# ---------------------------------------------------------------------------


def _write_config_fixture(tmp_path: Path) -> tuple[Path, str]:
    """Write a SYNTHETIC CRC config JSON; return (path, its exact file text).

    All values FAKE; NOT under examples/ (respects the examples/**/crc*.json
    tripwire, TC-114). The text is the load oracle: TC-203 asserts the editor
    text byte-equals it after a load.
    """
    text = _config_text()
    path = tmp_path / "loadable_crc.json"
    path.write_text(text, encoding="utf-8")
    return path, text


# ---------------------------------------------------------------------------
# TC-201 / LLR-013.1 — config-path Input + Load button present + display toggle
# ---------------------------------------------------------------------------


def test_crc_config_load_widgets_present_and_toggle(tmp_path: Path) -> None:
    """TC-201: the path Input + Load button show on the CRC row, hide off it.

    Intent (LLR-013.1): the new ``#operation_config_path`` Input and
    ``#operation_config_load`` Button extend the CRC compose branch and share
    the CRC row's visibility — they are ``.display==True`` while the CRC op is
    highlighted (index 0) and ``.display==False`` while a non-CRC op is
    highlighted (index 1, ``extract``), at parity with the existing
    ``#operation_config`` editor. A regression that forgot to toggle them in
    ``_sync_config_visibility`` would leave them visible off the CRC row.
    """

    async def _drive() -> tuple[bool, bool, bool, bool, bool, bool]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)

            path_input = screen.query_one("#operation_config_path", Input)
            load_button = screen.query_one("#operation_config_load", Button)
            editor = screen.query_one("#operation_config", TextArea)
            on_crc = (path_input.display, load_button.display, editor.display)

            # Highlight a non-CRC operation (index 1 = "extract").
            screen.query_one("#operations_list", ListView).index = 1
            await _flush(pilot)
            off_crc = (path_input.display, load_button.display, editor.display)
            return (*on_crc, *off_crc)

    (
        path_on,
        load_on,
        editor_on,
        path_off,
        load_off,
        editor_off,
    ) = asyncio.run(_drive())
    # On the CRC row: both new widgets displayed, at parity with the editor.
    assert path_on is True
    assert load_on is True
    assert editor_on is True
    # Off the CRC row: both new widgets hidden, at parity with the editor.
    assert path_off is False
    assert load_off is False
    assert editor_off is False


# ---------------------------------------------------------------------------
# TC-203 / LLR-013.2 — Load config through the handler populates the editor
# ---------------------------------------------------------------------------


def test_crc_config_load_ok_populates_editor_via_handler(tmp_path: Path) -> None:
    """TC-203: pressing Load config loads the file's raw text, runs no check.

    Intent (LLR-013.2, A-5 through-handler): the pilot types a valid synthetic
    config path into ``#operation_config_path`` and presses Load config — the
    press routes THROUGH ``OperationsScreen.on_button_pressed`` (the shipped
    handler, not a direct call). After the load, ``#operation_config.text``
    byte-equals the file text, and NO CRC check ran (no per-region row, no
    ``status: ok`` on the result surface). A regression that parsed-on-load or
    auto-ran the check would fail here.
    """

    async def _drive() -> tuple[str, str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        config_path, config_text = _write_config_fixture(tmp_path)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)

            # The editor pre-fills with the dummy; the load must replace it.
            assert (
                screen.query_one("#operation_config", TextArea).text
                == DUMMY_CONFIG_TEXT
            )

            screen.query_one("#operation_config_path", Input).value = str(
                config_path
            )
            screen.query_one("#operation_config_load", Button).press()
            await _flush(pilot)

            editor_text = screen.query_one("#operation_config", TextArea).text
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            return editor_text, config_text, status

    editor_text, config_text, status = asyncio.run(_drive())
    # The editor now byte-equals the loaded file text (raw, unparsed).
    assert editor_text == config_text
    # No CRC check ran on load: no per-region row, no green-pass status.
    assert "region @" not in status, status
    assert "status: ok" not in status, status
    assert "MATCH" not in status, status


# ---------------------------------------------------------------------------
# TC-204 / LLR-013.3 — load fault surfaces 1 error + no check; dummy on mount
# ---------------------------------------------------------------------------


def test_crc_config_load_fault_surfaces_error_and_no_check(tmp_path: Path) -> None:
    """TC-204: an unresolvable path AND an over-cap probe each surface 1 error.

    Intent (LLR-013.3): a load fault surfaces exactly one error on
    ``#operation_result_status``, leaves ``#operation_config.text`` UNCHANGED,
    and runs zero CRC checks (no per-region row, no ``status: ok``). Two fault
    modes are exercised through the handler: (a) an unresolvable path, and
    (b) an over-cap file via an injected oversized ``size_probe`` on
    ``read_crc_config_text``. The mount case asserts the editor pre-fills with
    ``DUMMY_CONFIG_TEXT`` and that an empty-path press leaves it untouched.
    """

    async def _drive_unresolvable() -> tuple[str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)
            before = screen.query_one("#operation_config", TextArea).text

            screen.query_one("#operation_config_path", Input).value = str(
                tmp_path / "does_not_exist.json"
            )
            screen.query_one("#operation_config_load", Button).press()
            await _flush(pilot)

            after = screen.query_one("#operation_config", TextArea).text
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            assert before == after, "editor changed on a load fault"
            return status, after

    async def _drive_over_cap() -> tuple[str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        config_path, _ = _write_config_fixture(tmp_path)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)
            before = screen.query_one("#operation_config", TextArea).text

            # Force an over-cap read via the injected size probe on the seam.
            oversized = lambda _candidate: 1 << 40  # noqa: E731 — 1 TiB stub
            with mock.patch(
                "s19_app.tui.screens.read_crc_config_text",
                side_effect=lambda path, base, _probe=oversized: read_crc_config_text(
                    path, base, _probe
                ),
            ):
                screen.query_one("#operation_config_path", Input).value = str(
                    config_path
                )
                screen.query_one("#operation_config_load", Button).press()
                await _flush(pilot)

            after = screen.query_one("#operation_config", TextArea).text
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            assert before == after, "editor changed on an over-cap load fault"
            return status, after

    async def _drive_mount_and_empty() -> tuple[str, str, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=True)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)
            mounted = screen.query_one("#operation_config", TextArea).text

            # Empty path: surface a message, leave the editor untouched.
            screen.query_one("#operation_config_path", Input).value = ""
            screen.query_one("#operation_config_load", Button).press()
            await _flush(pilot)
            after_empty = screen.query_one("#operation_config", TextArea).text
            status_empty = str(
                screen.query_one("#operation_result_status", Static).content
            )
            return mounted, after_empty, status_empty

    # (a) Unresolvable path → exactly one surfaced error, no check.
    status_unres, _ = asyncio.run(_drive_unresolvable())
    assert "CRC config load error:" in status_unres, status_unres
    assert "region @" not in status_unres, status_unres
    assert "status: ok" not in status_unres, status_unres

    # (b) Over-cap → exactly one surfaced error, no check, editor unchanged.
    status_cap, _ = asyncio.run(_drive_over_cap())
    assert "CRC config load error:" in status_cap, status_cap
    assert "region @" not in status_cap, status_cap
    assert "status: ok" not in status_cap, status_cap

    # Mount case: dummy pre-load; empty-path press surfaces a message and
    # leaves the editor untouched (LLR-013.3: empty is a fault that surfaces).
    mounted, after_empty, status_empty = asyncio.run(_drive_mount_and_empty())
    assert mounted == DUMMY_CONFIG_TEXT, mounted
    assert after_empty == DUMMY_CONFIG_TEXT, after_empty
    assert "enter a config file path" in status_empty, status_empty


# ---------------------------------------------------------------------------
# I5b write-surface helpers
# ---------------------------------------------------------------------------


def _emitted_s19_files(base_dir: Path) -> list[Path]:
    """Count surviving emitted ``*-crc.s19`` files under the work area.

    The write path stages a copy under ``.s19tool/workarea/temp/`` and unlinks
    it in a ``finally``, placing the survivor under ``.s19tool/workarea/crc/``;
    a declined write writes nothing. This globs the whole work area so a stray
    staged file would also be caught.
    """
    workarea = base_dir / ".s19tool" / "workarea"
    if not workarea.exists():
        return []
    return sorted(workarea.rglob("*-crc.s19"))


async def _press_write_and_handle_modal(app, pilot, screen, *, confirm: bool) -> None:
    """Press Write CRC, then drive the ConfirmWriteScreen confirm/cancel button."""
    screen.query_one("#operations_write", Button).press()
    await _flush(pilot)
    confirm_screen = app.screen
    button_id = "confirm_write_ok" if confirm else "confirm_write_cancel"
    confirm_screen.query_one(f"#{button_id}", Button).press()
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


# ---------------------------------------------------------------------------
# TC-124 — no write without confirmation; a confirmed write emits a file
# ---------------------------------------------------------------------------


def test_no_write_without_confirmation(tmp_path: Path) -> None:
    """Declining the confirm modal writes nothing; confirming emits a file.

    Intent (I5b two-stage confirmation): after a real check enables the
    ``Write CRC`` button, pressing it opens ``ConfirmWriteScreen``. DECLINING
    leaves ZERO emitted files under the work area and the surface shows no
    emitted path / "wrote" line. CONFIRMING (a fresh run) emits exactly one
    file under the work area and renders the write outcome. Driven through the
    real button + modal, never a direct ``write_crc_image`` call.
    """

    async def _drive(*, confirm: bool) -> tuple[int, str]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=False)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)

            # A real check first — this is what enables the Write CRC button.
            screen.query_one("#operation_config", TextArea).text = _config_text()
            screen.query_one("#operations_execute", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            assert not screen.query_one("#operations_write", Button).disabled

            await _press_write_and_handle_modal(app, pilot, screen, confirm=confirm)
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            return len(_emitted_s19_files(app.base_dir)), status

    # DECLINE: nothing written, surface carries no emitted-path / "wrote" line.
    declined_count, declined_status = asyncio.run(_drive(confirm=False))
    assert declined_count == 0, declined_status
    assert "wrote " not in declined_status, declined_status
    assert "-crc.s19" not in declined_status, declined_status

    # CONFIRM: exactly one file emitted, the write outcome renders.
    confirmed_count, confirmed_status = asyncio.run(_drive(confirm=True))
    assert confirmed_count == 1, confirmed_status
    assert "-crc.s19" in confirmed_status, confirmed_status


# ---------------------------------------------------------------------------
# TC-125 — the confirmed write outcome reaches the surface VIA the handler
# ---------------------------------------------------------------------------


def test_crc_inject_reaches_surface_via_handler(tmp_path: Path) -> None:
    """A confirmed write's emitted path + verify verdict reach the surface.

    Intent (A-5, through-handler): a real check then a CONFIRMED write routes
    THROUGH the shipped Write button + ConfirmWriteScreen + worker (not a direct
    ``write_crc_image`` call); the emitted modified-S19 outcome — the path AND
    the verify verdict — reaches ``#operation_result_status``. Non-vacuous: the
    verdict text is asserted AND the emitted file is confirmed on disk.
    """

    async def _drive() -> tuple[str, list[Path]]:
        s19_path = _write_fixture_s19(tmp_path, stored_matches=False)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _load_file(app, pilot, s19_path)
            screen = await _open_crc_screen(app, pilot)

            screen.query_one("#operation_config", TextArea).text = _config_text()
            screen.query_one("#operations_execute", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)

            await _press_write_and_handle_modal(app, pilot, screen, confirm=True)
            status = str(
                screen.query_one("#operation_result_status", Static).content
            )
            return status, _emitted_s19_files(app.base_dir)

    status, emitted = asyncio.run(_drive())
    # The emitted path + the verified verdict reached the surface.
    assert "wrote " in status, status
    assert "verified" in status, status
    assert OperationsScreen.WRITE_FAILED_TEXT not in status, status
    assert OperationsScreen.VERIFY_MISMATCH_TEXT not in status, status
    # F1 (review): the fixture's stored value MISMATCHED before the write, so a
    # check-oriented per-region row would print a stale "MISMATCH" beside the
    # "(verified)" write. The write surface must instead describe what was
    # WRITTEN — a "(4 LE bytes)" row — and carry no stale MISMATCH.
    assert "(4 LE bytes)" in status, status
    assert "MISMATCH" not in status, status
    # Non-vacuous: a real file exists on disk under the work area.
    assert len(emitted) == 1, emitted
    assert emitted[0].read_text(encoding="utf-8").strip(), "emitted S19 is empty"
