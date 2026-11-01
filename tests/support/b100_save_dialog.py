"""Batch-100 Inc 11 — drivers and readers for the Save project dialog.

Written by the independent tester from the fixed interfaces of
``inc-11/codewire/interfaces-11.md`` (``SaveProjectScreen(preview=,
confirm=, initial_name=, variants=, candidate_files=)``, its read-only
``plan`` and the widget ids ``#save_box``, ``#project_name``,
``#save_where``, ``#save_summary``, ``#saveproject_buttons``, ``#save_ok``,
``#save_cancel``), never from the implementation.

Every Inc 11 symbol is read lazily, so a test file that uses these helpers
still COLLECTS on the base revision (before Inc 11) and each test fails
there on its own, for the behavioural reason: the base dialog has no
``#save_where`` / ``#save_summary`` (the readers return ``""`` / ``[]``),
no ``plan`` and no ``alt+s``.

The re-pinned drives of other test files use :func:`save_through_dialog`
and :func:`refuse_through_dialog`: they keep the old gestures (``ctrl+s``,
the name typed key by key, a click on ``#save_ok``) and add the one step
the new dialog needs — wait for the summary of the typed name to be painted
before Save (LLR-175.4b: a Save pressed before the 150 ms recompute is
repainted, not saved).
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Callable, Optional

#: The four action words the summary paints (LLR-175.4; ``replace`` is
#: never produced, E3 R1).
ACTION_WORDS = ("new", "keep", "merge", "rewrite")

#: The 150 ms debounce (LLR-175.5a) plus margin: a recompute has run after
#: this long without a keystroke.
RECOMPUTE_WAIT = 0.4

#: The §3 token pair of the out-of-date summary (LLR-175.4b).
SUMMARY_CHANGED = ("the summary changed", "check it, then save again")


def save_dialog_cls():
    """``s19_app.tui.screens.SaveProjectScreen``."""
    from s19_app.tui.screens import SaveProjectScreen

    return SaveProjectScreen


def is_save_dialog(screen) -> bool:
    return isinstance(screen, save_dialog_cls())


def plain(widget) -> str:
    """The plain text of a ``Static``'s content (not clipped by the width)."""
    visual = getattr(widget, "visual", None)
    if visual is None:
        visual = widget.render()
    return str(getattr(visual, "plain", visual))


def spans(widget) -> int:
    """The number of style spans of a ``Static``'s content (0 = painted
    literally, no markup parsed)."""
    visual = getattr(widget, "visual", None)
    if visual is None:
        visual = widget.render()
    return len(getattr(visual, "spans", ()) or ())


def where_widget(screen):
    found = screen.query("#save_where")
    return found.first() if len(found) else None


def where_text(screen) -> str:
    """The painted text of ``#save_where`` (``""`` when the dialog has
    none — the base revision)."""
    widget = where_widget(screen)
    return plain(widget) if widget is not None else ""


def summary_widgets(screen) -> list:
    from textual.widgets import Static

    found = screen.query("#save_summary")
    if not len(found):
        return []
    return list(found.first().query(Static))


def summary_rows(screen) -> list:
    """The painted summary rows, in order (``[]`` when the dialog has no
    ``#save_summary`` — the base revision)."""
    return [plain(w) for w in summary_widgets(screen)]


def painted(screen) -> str:
    """``#save_where`` and every summary row, one per line."""
    return "\n".join([where_text(screen)] + summary_rows(screen))


def name_input(screen):
    from textual.widgets import Input

    return screen.query_one("#project_name", Input)


def flat(text: str) -> str:
    return " ".join(text.split())


async def settle(pilot, n: int = 6) -> None:
    for _ in range(n):
        await pilot.pause()


async def wait_for(
    pilot, predicate: Callable[[], bool], description: str, timeout: float = 6.0
) -> None:
    """Wait (by the wall clock: the dialog's 150 ms recompute is a real
    timer) until ``predicate()`` holds."""
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {description}")
        await pilot.pause(0.01)


async def wait_recompute(pilot) -> None:
    """Let the 150 ms recompute run and its paint settle."""
    await pilot.pause(RECOMPUTE_WAIT)
    await settle(pilot, 4)


async def open_save_dialog(pilot, app, key: str = "ctrl+s") -> None:
    """Open the Save project dialog with ``key`` and let its first frame
    and first preview settle."""
    await pilot.press(key)
    await wait_for(pilot, lambda: is_save_dialog(app.screen), "the Save project dialog")
    await wait_recompute(pilot)


async def clear_name(pilot, app) -> None:
    """Empty ``#project_name`` by keys (``end`` then one ``backspace`` per
    character), the focus in the field."""
    field = name_input(app.screen)
    if app.focused is not field:
        app.screen.set_focus(field)
        await settle(pilot, 2)
    await pilot.press("end", *(["backspace"] * len(field.value)))


async def type_name(pilot, app, text: str) -> None:
    """Clear ``#project_name`` and type ``text`` key by key."""
    await clear_name(pilot, app)
    if text:
        await pilot.press(*text)


async def set_name(pilot, app, text: str) -> None:
    """Replace the field's value (for characters a key name cannot carry:
    ``¹``, ``ß``, U+202E, brackets). The change posts ``Input.Changed`` as a
    keystroke does."""
    field = name_input(app.screen)
    app.screen.set_focus(field)
    field.value = text
    await settle(pilot, 2)


async def wait_painted(pilot, app, *tokens: str, timeout: float = 6.0) -> str:
    """Wait until every token is painted in ``#save_where`` or the summary,
    then let one more refresh pass (the dialog's "shown" mark, S11-04);
    return the painted text."""
    await wait_for(
        pilot,
        lambda: all(token in painted(app.screen) for token in tokens),
        f"the dialog to paint {tokens!r} (painted: {painted(app.screen)!r})",
        timeout,
    )
    await settle(pilot, 4)
    return painted(app.screen)


def sanitised(name: str) -> str:
    from s19_app.tui.workspace import sanitize_project_name

    return sanitize_project_name(name) or ""


async def save_through_dialog(
    pilot, app, name: str, *, confirm: str = "click", folder: Optional[str] = None,
    wait_closed: bool = True,
) -> None:
    """``ctrl+s``, type ``name``, wait for the summary of ``name`` (its
    folder in ``#save_where``), then confirm by a click on ``#save_ok``
    (``confirm="click"``) or ``alt+s``; wait for the dialog to close.

    A Save the dialog repaints with ``the summary changed`` (a recompute
    that landed between the wait and the press) is pressed once more, as
    the engineer would (R2-01)."""
    await open_save_dialog(pilot, app)
    await type_name(pilot, app, name)
    expected = folder if folder is not None else sanitised(name)
    await wait_for(
        pilot,
        lambda: expected.casefold() in where_text(app.screen).casefold(),
        f"the target line naming {expected!r} (painted: {where_text(app.screen)!r})",
    )
    await settle(pilot, 4)
    for _attempt in range(2):
        if confirm == "click":
            assert await pilot.click("#save_ok"), "click missed #save_ok"
        else:
            await pilot.press("alt+s")
        await settle(pilot, 4)
        if not is_save_dialog(app.screen):
            break
        if SUMMARY_CHANGED[0] not in where_text(app.screen):
            break
        await settle(pilot, 4)
    if wait_closed:
        await wait_for(
            pilot,
            lambda: not is_save_dialog(app.screen),
            f"the Save project dialog to close (painted: {painted(app.screen)!r})",
        )


async def refuse_through_dialog(pilot, app, name: str, *tokens: str, close: bool = True) -> str:
    """``ctrl+s``, type ``name``, wait for the refusal ``tokens`` in
    ``#save_where`` with the dialog open (ruling Q5), press ``alt+s`` and
    check the dialog stays with the tokens painted; then close it with
    ``escape`` (``close``). Returns the painted ``#save_where`` text."""
    await open_save_dialog(pilot, app)
    return await refuse_in_open_dialog(pilot, app, name, *tokens, close=close)


async def refuse_in_open_dialog(pilot, app, name: str, *tokens: str, close: bool = True) -> str:
    """With the Save dialog open: type ``name``, wait for the refusal
    ``tokens`` in ``#save_where``, press ``alt+s`` and check the dialog
    stays with the tokens painted; then ``escape`` (``close``). Returns the
    painted ``#save_where`` text."""
    await type_name(pilot, app, name)
    await wait_for(
        pilot,
        lambda: all(token in where_text(app.screen) for token in tokens),
        f"the refusal {tokens!r} in #save_where (painted: {where_text(app.screen)!r})",
    )
    await settle(pilot, 4)
    await pilot.press("alt+s")
    await settle(pilot, 6)
    assert is_save_dialog(app.screen), "a refused Save closed the dialog"
    text = where_text(app.screen)
    assert all(token in text for token in tokens), text
    if close:
        await pilot.press("escape")
        await wait_for(pilot, lambda: not is_save_dialog(app.screen), "the dialog to close on escape")
    return text


def workarea_listing(workarea: Path) -> set:
    """Every path under the work area (relative POSIX text)."""
    if not workarea.exists():
        return set()
    return {p.relative_to(workarea).as_posix() for p in workarea.rglob("*")}


def tree_digests(root: Path) -> dict:
    """Every file under ``root`` (relative POSIX, case-folded) -> SHA-256."""
    if not root.exists():
        return {}
    return {
        p.relative_to(root).as_posix().casefold(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def session_digest(app) -> tuple:
    """The E1 session digest: (current file path, SHA-256 of the image file,
    current project, current A2L path, MAC path)."""
    cur = app.current_file
    image = None
    if cur is not None and cur.path is not None and Path(cur.path).is_file():
        image = hashlib.sha256(Path(cur.path).read_bytes()).hexdigest()
    return (
        str(cur.path) if cur is not None else None,
        image,
        app.current_project,
        str(app.current_a2l_path) if app.current_a2l_path is not None else None,
        str(cur.mac_path) if cur is not None and cur.mac_path is not None else None,
    )


def run(base: Path, scenario, size: tuple = (118, 54), notifications: bool = False):
    """Run ``await scenario(app, pilot, log)`` in a fresh ``S19TuiApp``
    rooted at ``base``; return what it returns."""
    from s19_app.tui.app import S19TuiApp
    from tests.support.b100_projects import StatusLog

    async def _drive():
        app = S19TuiApp(base_dir=base)
        log = StatusLog(app)
        async with app.run_test(size=size, notifications=notifications) as pilot:
            await pilot.pause()
            return await scenario(app, pilot, log)

    return asyncio.run(_drive())


class SaveDialogFakes:
    """Stand-ins for the app's two callables of the fixed S-a / S-b seam,
    for tests about the dialog alone (re-pinned census A): ``preview(text)``
    paints a one-line target and one row per name, with one memoised
    ``SavePlan`` per name under ``workarea``; ``confirm(text, plan)`` says
    go (``None``) only for the plan it painted for that name."""

    def __init__(self, workarea: Path) -> None:
        self.workarea = Path(workarea)
        self.plans: dict = {}

    def _types(self):
        from s19_app.tui.screens import SavePreview
        from s19_app.tui.services.project_gather_service import SavePlan

        return SavePreview, SavePlan

    def _plan(self, name: str):
        _SavePreview, SavePlan = self._types()
        if name not in self.plans:
            self.plans[name] = SavePlan(
                target=self.workarea / name, target_kind="new", rows=(), image="", manifest_keys=()
            )
        return self.plans[name]

    def preview(self, text: str):
        SavePreview, _SavePlan = self._types()
        if not text.strip():
            return SavePreview(where=(), rows=(), plan=None, refused=False)
        return SavePreview(where=((f"{text} - new folder", "info"),), rows=(f"{text}/project.json - new",),
                           plan=self._plan(text), refused=False)

    def confirm(self, text: str, plan):
        if text.strip() and plan is not None and plan is self.plans.get(text):
            return None
        return self.preview(text)


def bare_save_dialog(workarea: Path, **overrides):
    """A ``SaveProjectScreen`` fed by :class:`SaveDialogFakes` (the keyword
    constructor of Inc 11, S-b)."""
    fakes = SaveDialogFakes(workarea)
    kwargs = dict(preview=fakes.preview, confirm=fakes.confirm)
    kwargs.update(overrides)
    return save_dialog_cls()(**kwargs)


async def type_and_await_summary(pilot, app, name: str) -> str:
    """The re-pin step of the Save drives (census D / F): clear the name
    field (the open project's name is prefilled and selected, LLR-175.3h),
    type ``name`` key by key, and wait until ``#save_where`` names its
    folder (the summary of ``name`` is painted, LLR-175.4b) plus one more
    refresh. Returns the painted ``#save_where`` text."""
    await type_name(pilot, app, name)
    expected = sanitised(name).casefold() or name.casefold()
    await wait_for(
        pilot,
        lambda: expected in where_text(app.screen).casefold(),
        f"the summary of {name!r} (painted: {where_text(app.screen)!r})",
    )
    await settle(pilot, 4)
    return where_text(app.screen)
