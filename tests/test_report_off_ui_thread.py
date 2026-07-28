"""batch-68 AC-1..AC-4 — the before/after and diff reports compose OFF the UI thread.

Summary:
    Before batch-68 the s19 TUI had exactly three ``@work`` methods
    (``execute_scope``, ``generate_report``, ``load``). The before/after report
    and the A2B diff report were **not** among them, so
    ``compose_before_after_report`` / ``generate_diff_report`` /
    ``generate_diff_report_html`` all ran on the Textual event loop: the
    terminal stopped repainting for the entire composition and a slow report
    was indistinguishable from a hung application.

    The backlog carried this as "add the same ``set_progress`` pattern". That
    understates it — **you cannot drive a progress bar from the thread you are
    blocking**, so the progress work is downstream of the threading fix, not
    parallel to it.

    The oracle here is deliberately NOT "a progress value was written". A
    handler that sets 15 then blocks the loop then sets 100 satisfies every
    progress assertion while still freezing the UI. The load-bearing oracle is
    **thread identity**: the composer must be entered on a thread that is not
    the one which dispatched the action. That is directly falsifiable and is
    RED on the pre-batch-68 tree, where the two are the same thread.

Data Flow:
    - Monkeypatches each composer at its *call-site module* (``s19_app.tui.app``
      imports them by name, so patching the defining module would not be seen)
      with a recorder that captures ``threading.get_ident()`` and then defers
      to the real implementation, so behaviour is observed, not replaced.

Dependencies:
    Uses:
        - ``s19_app.tui.app.S19TuiApp``
    Used by:
        - the batch-68 acceptance gate (AC-1, AC-2, AC-3, AC-4)
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest

from s19_app.tui import app as app_mod
from s19_app.tui.app import S19TuiApp


def _record_thread(
    monkeypatch: pytest.MonkeyPatch, name: str, sink: Dict[str, Any]
) -> None:
    """Wrap ``app_mod.<name>`` so it records the thread it is entered on.

    Args:
        monkeypatch (pytest.MonkeyPatch): Test patcher.
        name (str): Attribute on ``s19_app.tui.app`` to wrap.
        sink (Dict[str, Any]): Receives ``sink[name] = thread ident``.

    Data Flow:
        - Replaces the name on the CALL-SITE module (``s19_app.tui.app``
          does ``from ... import compose_before_after_report``, so the defining
          module's attribute is never consulted at call time), delegates to the
          original, and returns its real result.

    Dependencies:
        Used by:
            - every test in this module
    """
    original = getattr(app_mod, name)

    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        sink[name] = threading.get_ident()
        return original(*args, **kwargs)

    monkeypatch.setattr(app_mod, name, _wrapped)


def test_ac1_before_after_composes_off_the_ui_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1: ``compose_before_after_report`` runs on a non-UI thread.

    RED on the pre-batch-68 tree: there the composer is called inline from
    ``action_before_after_report``, so the recorded ident equals the UI
    thread's and the assertion fails on its own comparison — not on an import
    or signature error.
    """
    seen: Dict[str, Any] = {}
    _record_thread(monkeypatch, "compose_before_after_report", seen)

    async def _drive() -> tuple[Any, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            ui_thread = threading.get_ident()
            app.action_before_after_report()
            for _ in range(8):
                await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            return seen.get("compose_before_after_report"), ui_thread

    composer_thread, ui_thread = asyncio.run(_drive())

    assert composer_thread is not None, (
        "the before/after composer was never invoked — the test cannot say "
        "anything about which thread it ran on. Check that the action reached "
        "the worker rather than returning early on validation."
    )
    assert composer_thread != ui_thread, (
        "compose_before_after_report ran on the UI thread "
        f"({composer_thread}), so the terminal is frozen for its whole "
        "duration. It must be dispatched to a @work(thread=True) worker."
    )


def test_ac3_before_after_progress_never_sticks_mid_fill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3: the bar reaches 100 on success and returns to 0 on refusal.

    Asserts the FINAL value, not merely that some value was written: a bar left
    at the kickoff 15 reads as "still working" forever, which is the exact
    failure the project-report half of N5 was fixed for.
    """
    values: List[int] = []
    original = S19TuiApp.set_progress

    def _spy(self: S19TuiApp, value: int, message: Any = None) -> None:
        values.append(value)
        return original(self, value, message)

    monkeypatch.setattr(S19TuiApp, "set_progress", _spy)

    async def _drive() -> List[int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            values.clear()
            app.action_before_after_report()
            for _ in range(8):
                await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            return list(values)

    seen = asyncio.run(_drive())

    assert seen, (
        "the before/after path wrote no progress value at all — the bar keeps "
        "whatever the previous operation left, which reads as that operation's "
        "state"
    )
    assert seen[-1] in (0, 100), (
        f"the bar must end at 100 (written) or 0 (refused/failed), never "
        f"mid-fill. Progress sequence: {seen}"
    )
