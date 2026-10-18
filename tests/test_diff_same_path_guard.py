"""A2B diff same-path guard — s19_app batch-96, BUG B7 (operator report 2026-10-18).

The operator reported: "if two files have similar names in the same folder,
only 1 file is read; renaming/moving does not help; ONLY restarting the app
fixes it." Diagnosis: the parse/compare path has NO cache. The actual cause
is ``OsClipboardInput.action_paste`` — when all three OS clipboard layers
fail (the tkinter root created/destroyed in the executor thread dies mid-
session on Windows), the B path input silently keeps its previous value, so
the compare request arrives with the A path on BOTH sides and the app
compares A against A.

Fix under test: an early guard in ``S19TuiApp._apply_compare_request``
(``app.py``) that refuses the request — with a clear panel status naming the
likely cause — when both sides resolve to the same on-disk file (identical
raw strings, or two external paths that resolve through the same
``resolve_input_path`` the compare flow uses).

Coverage map (test -> TC):

- TC-1801 — ``test_tc1801_identical_paths_are_refused``: both inputs carry
  the SAME raw path string; the shipped Compare button is pressed with
  ``compare_images`` substituted by a spy that fails the test if it runs.
  Observable proof the guard fired: ``sev-error`` status naming "same
  file", ``app._diff_last_result`` untouched (``None``), zero spy calls.
- TC-1801 — ``test_tc1801_same_file_different_spelling_is_refused``: the
  same on-disk file reached by two different spellings (absolute vs
  base-dir-relative). The resolution-based limb of the guard, same
  observables.
- TC-1801 — ``test_tc1801_distinct_paths_compare_proceeds`` (negative
  control): two genuinely different well-formed S19 images ride the REAL
  compare end to end (no ``compare_images`` substitution) and reach the
  green ``sev-ok`` display path — the guard must NOT fire.

Harness: the black-box ``App.run_test()`` pilot pattern of
``tests/test_tui_diff_compare_realpath.py`` — real button press, wait on
``app._diff_compare_generation`` (bumped in a ``finally`` on every handler
exit path, so the wait also returns on the new refusal branch).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Input, Static

import s19_app.tui.app as app_mod
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map


def _write_s19(path: Path, mem_map: dict[int, int], ranges: list[tuple[int, int]]) -> None:
    """Write a well-formed S19 file re-readable by the shipped loader."""
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="utf-8")


async def _press_compare_and_wait(app, pilot) -> None:
    """Press the shipped Compare button and wait for the HANDLER, not the queue.

    ``Pilot.pause()`` waits for message-queue idleness, but the compare
    handler suspends on awaited widget work after dequeuing its message.
    ``app._diff_compare_generation`` is bumped in a ``finally`` on every
    exit path — success, refusal, and the new same-path guard alike.
    """
    before = app._diff_compare_generation
    app.query_one("#diff_compare_button").press()
    for _ in range(500):
        if app._diff_compare_generation > before:
            return
        await pilot.pause()
    raise AssertionError(
        "the compare handler never completed: _diff_compare_generation stayed "
        f"at {before} across 500 pumped turns"
    )


def test_tc1801_identical_paths_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """TC-1801 — a compare request with the SAME path on both sides is refused.

    Intent: this is the escaped-bug proof for B7. The B input keeps its
    stale previous value after a silently-failed clipboard paste, so the
    request arrives as A-vs-A. The guard must refuse BEFORE any compare
    work: the panel shows a ``sev-error`` status naming the situation, the
    service is never invoked, and ``_diff_last_result`` stays ``None``.
    """
    image = tmp_path / "image_a.s19"
    _write_s19(image, {0x100 + i: i & 0xFF for i in range(8)}, [(0x100, 0x108)])

    calls: list[int] = []

    def _spy(*_args, **_kwargs):
        calls.append(1)
        raise AssertionError("compare_images must not run when both sides are the same file")

    monkeypatch.setattr(app_mod, "compare_images", _spy)

    async def _drive() -> tuple[bool, bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_path_a", Input).value = str(image)
            app.query_one("#diff_path_b", Input).value = str(image)
            await _press_compare_and_wait(app, pilot)
            status = app.query_one("#diff_status", Static)
            return (
                status.has_class("sev-error"),
                app._diff_last_result is not None,
                str(status.render()),
            )

    is_error, result_written, status_text = asyncio.run(_drive())

    assert calls == [], "the guard must stop the request before compare_images"
    assert is_error is True, f"same-path request must land sev-error; status={status_text!r}"
    assert "same file" in status_text, (
        f"the status must name the situation for the operator; status={status_text!r}"
    )
    assert "clipboard paste failed?" in status_text, (
        f"the status must name the likely cause (stale B input); status={status_text!r}"
    )
    assert result_written is False, (
        "_diff_last_result must stay untouched on the guard branch — the "
        "operator's 'only 1 file read' reading must never be backed by an A-vs-A result"
    )


def test_tc1801_same_file_different_spelling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-1801 — the resolution limb: same file, different raw spellings.

    Intent: the guard compares RESOLVED paths, not just raw strings —
    ``str(file)`` and the base-dir-relative ``image_a.s19`` name the same
    on-disk file and must be refused exactly like identical strings.
    """
    image = tmp_path / "image_a.s19"
    _write_s19(image, {0x100 + i: i & 0xFF for i in range(8)}, [(0x100, 0x108)])

    calls: list[int] = []
    monkeypatch.setattr(
        app_mod, "compare_images", lambda *a, **k: calls.append(1)
    )

    async def _drive() -> tuple[bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_path_a", Input).value = str(image)
            app.query_one("#diff_path_b", Input).value = "image_a.s19"
            await _press_compare_and_wait(app, pilot)
            status = app.query_one("#diff_status", Static)
            return status.has_class("sev-error"), str(status.render())

    is_error, status_text = asyncio.run(_drive())

    assert calls == [], "the guard must stop the request before compare_images"
    assert is_error is True, (
        f"two spellings of the same file must land sev-error; status={status_text!r}"
    )
    assert "same file" in status_text, (
        f"the status must name the situation for the operator; status={status_text!r}"
    )


def test_tc1801_distinct_paths_compare_proceeds(tmp_path: Path) -> None:
    """TC-1801 (negative control) — genuinely different files still compare.

    Intent: the guard must NOT widen into refusing legitimate compares.
    Two well-formed S19 images that share an address range but differ at
    four bytes ride the REAL compare end to end (no ``compare_images``
    substitution) and reach the green ``sev-ok`` display path with
    ``_diff_last_result`` written.
    """
    a = tmp_path / "image_a.s19"
    b = tmp_path / "image_b.s19"
    ranges = [(0x100, 0x108)]
    _write_s19(a, {0x100 + i: i & 0xFF for i in range(8)}, ranges)
    flipped = {0x100 + i: i & 0xFF for i in range(8)}
    for i in range(4):
        flipped[0x100 + i] = (0xF0 + i) & 0xFF
    _write_s19(b, flipped, ranges)

    async def _drive() -> tuple[bool, bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_path_a", Input).value = str(a)
            app.query_one("#diff_path_b", Input).value = str(b)
            await _press_compare_and_wait(app, pilot)
            status = app.query_one("#diff_status", Static)
            return (
                status.has_class("sev-error"),
                status.has_class("sev-ok"),
                str(status.render()),
            )

    is_error, is_ok, status_text = asyncio.run(_drive())

    assert is_error is False, (
        f"distinct files must not trip the guard; status={status_text!r}"
    )
    assert is_ok is True, (
        f"a valid differing pair must reach sev-ok; status={status_text!r}"
    )
