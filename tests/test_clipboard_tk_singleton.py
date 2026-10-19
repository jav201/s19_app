"""TC-1815 — process-wide Tk clipboard root singleton (batch-96, BUG B7 root cause).

The pre-fix layer 1 (``_read_via_tk``) created and destroyed a fresh
``tk.Tk()`` on every paste, from an executor thread. On Windows, after the
first create/destroy cycle, later ``tk.Tk()`` creations in the same process
can fail PERSISTENTLY — layer 1 then died mid-session and Ctrl+V silently
kept the old text (the symptom the TC-1801 same-path guard only mitigates).

The fix: one ``tk.Tk()`` per process, created lazily in the MAIN thread
(primed by ``OsClipboardInput.action_paste`` before the cascade enters the
executor), reused for every read, destroyed once at process exit.

These tests inject a fake root / fake factory so no real GUI is ever
opened; the seam is ``_create_tk_root`` plus a fresh ``_TkRootSingleton``
patched over the module-level ``_TK_ROOT``.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from textual.widgets import Input

_FAKE_CLIPBOARD_TEXT = "C:\\from\\tk\\singleton.s19"


class _FakeTkRoot:
    """Stand-in for a withdrawn ``tkinter.Tk`` root (no real GUI)."""

    def __init__(self) -> None:
        self.get_calls = 0
        self.destroyed = False

    def clipboard_get(self) -> str:
        self.get_calls += 1
        return _FAKE_CLIPBOARD_TEXT

    def destroy(self) -> None:
        self.destroyed = True


@pytest.fixture()
def tk_singleton(monkeypatch: pytest.MonkeyPatch):
    """Fresh singleton + counting fake factory; no real tkinter, no GUI."""
    from s19_app.tui import os_clipboard_input as mod

    state = {"creations": 0}
    roots: list[_FakeTkRoot] = []

    def _fake_create() -> _FakeTkRoot:
        state["creations"] += 1
        root = _FakeTkRoot()
        roots.append(root)
        return root

    fresh = mod._TkRootSingleton()
    monkeypatch.setattr(mod, "_TK_ROOT", fresh)
    monkeypatch.setattr(mod, "_create_tk_root", _fake_create)
    return mod, fresh, state, roots


def test_tc1815_root_created_once_across_repeated_pastes(
    tk_singleton: tuple, tmp_path: Path
) -> None:
    """TC-1815: N Ctrl+V presses create the Tk root exactly once.

    Drives the REAL key path (focus + ctrl+v through ``action_paste`` and
    the real ``read_os_clipboard`` cascade) with only the root factory
    faked. Every paste reads through the one shared root — the pre-fix
    behavior would have created/destroyed a root per paste from the
    executor thread.
    """
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.screens import LoadFileScreen

    mod, fresh, state, roots = tk_singleton
    paste_count = 3

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        values: list[str] = []
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            input_widget = app.screen.query_one("#load_path", Input)
            for _ in range(paste_count):
                input_widget.value = ""
                input_widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+v")
                await pilot.pause()
                values.append(input_widget.value)
        return values

    values = asyncio.run(_drive())
    assert values == [_FAKE_CLIPBOARD_TEXT] * paste_count, (
        f"Every Ctrl+V must paste the (fake) OS clipboard text; got {values!r}"
    )
    assert state["creations"] == 1, (
        f"The Tk root must be created exactly once across {paste_count} "
        f"pastes; the factory ran {state['creations']} times — the "
        "create/destroy-per-paste bug is back."
    )
    assert len(roots) == 1
    assert roots[0].get_calls >= paste_count, (
        "Every paste must read clipboard_get through the SAME shared root; "
        f"got {roots[0].get_calls} reads on the single root."
    )


def test_tc1815_creation_is_main_thread_only(tk_singleton: tuple) -> None:
    """TC-1815: the executor thread never creates the root; the main thread does.

    A worker thread asking for the root before it exists gets ``None`` and
    must NOT trigger a creation (the seam ``creator_thread`` then records
    the main thread once the root is created there).
    """
    mod, fresh, state, roots = tk_singleton

    with ThreadPoolExecutor(max_workers=1) as pool:
        off_main = pool.submit(mod._TK_ROOT.get_or_create).result()
    assert off_main is None, (
        "Off-main-thread get_or_create before the root exists must return "
        "None (fall through to the next cascade layer), never create."
    )
    assert state["creations"] == 0, (
        "The Tk root must never be created from an executor/worker thread; "
        f"the factory already ran {state['creations']} time(s)."
    )

    root = mod._TK_ROOT.get_or_create()
    assert root is roots[0]
    assert state["creations"] == 1
    assert mod._TK_ROOT.creator_thread == threading.main_thread().name, (
        f"Root creation must be requested by the main thread; recorded "
        f"creator={mod._TK_ROOT.creator_thread!r}."
    )

    # Once the root exists, an executor thread can READ through it — same
    # object, no second creation.
    with ThreadPoolExecutor(max_workers=1) as pool:
        again = pool.submit(mod._TK_ROOT.get_or_create).result()
    assert again is root
    assert state["creations"] == 1


def test_tc1815_tk_unavailable_falls_through_to_other_layers(
    tk_singleton: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-1815: without tk (headless / no display), the cascade is unchanged.

    ``_create_tk_root`` returning ``None`` (sticky "unavailable") makes the
    tkinter layer yield immediately and the ctypes/PowerShell layers keep
    working exactly as before the fix.
    """
    mod, fresh, state, roots = tk_singleton

    def _unavailable_create():
        state["creations"] += 1
        return None

    monkeypatch.setattr(mod, "_create_tk_root", _unavailable_create)

    assert mod._read_via_tk() is None
    assert state["creations"] == 1  # one attempt, then sticky unavailable

    calls: list[str] = []
    result = mod.read_os_clipboard(
        strategies=(
            ("tkinter", mod._read_via_tk),
            ("ctypes-win32", lambda: (calls.append("ct") or "CT_FALLBACK")),
            ("powershell", lambda: (calls.append("ps") or "PS_FALLBACK")),
        )
    )
    assert result == "CT_FALLBACK", (
        f"With tk unavailable the cascade must reach the ctypes layer; "
        f"got {result!r}"
    )
    assert calls == ["ct"], (
        f"Cascade must stop at the first non-None layer; got calls={calls}"
    )


def test_tc1815_shared_root_destroyed_once_at_exit(
    tk_singleton: tuple,
) -> None:
    """TC-1815: exit-time destruction is single, idempotent, best-effort."""
    mod, fresh, state, roots = tk_singleton
    root = mod._TK_ROOT.get_or_create()
    assert root is roots[0]

    mod._destroy_tk_root_singleton()
    assert root.destroyed is True
    assert mod._TK_ROOT.get_existing() is None

    # Second call with no live root must be a harmless no-op.
    mod._destroy_tk_root_singleton()
    assert state["creations"] == 1
