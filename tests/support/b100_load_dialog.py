"""Batch-100 Inc 9b — drivers and readers for the one Load dialog.

Written by the independent tester from the fixed interfaces of
``inc-9b/codewire/interfaces-9b.md`` (``LoadChoice``, ``LoadDialog`` and the
widget ids ``#load_box``, ``#load_path``, ``#load_list``, ``#load_preview``,
``#load_reason``, ``#load_ok``, ``#load_cancel``), never from the
implementation.

Every Inc 9b symbol is imported lazily, inside the helper that needs it, so a
test file that uses these helpers still COLLECTS on the base revision (before
9b), and each test fails there on its own, for the behavioural reason (an
assertion, or the ``ImportError`` of a symbol the new design adds).

The project drivers (:func:`open_project_through_dialog`) and the file
driver (:func:`load_path_through_dialog`) replace the drivers of the retired
``LoadProjectScreen`` / ``LoadFileScreen`` (Inc 9b re-pins, ruling Q9). They
keep the old drivers' gestures where the new dialog still has them (the
shown key that opens it, a typed path, a click on the confirm button) and
move only what the new widgets changed:

  - ``#project_list`` (a ``ListView``) -> ``#load_list`` (an ``OptionList``
    with section headings): a row is reached with the arrow keys, never by
    a click on a ``ListItem``;
  - ``#project_ok`` / ``#project_cancel`` -> ``#load_ok`` / ``#load_cancel``.
"""
from __future__ import annotations

from typing import Callable, Optional


def load_dialog_cls():
    """``s19_app.tui.screens.LoadDialog`` (lazy: absent before Inc 9b)."""
    from s19_app.tui.screens import LoadDialog

    return LoadDialog


def load_choice_cls():
    """``s19_app.tui.screens.LoadChoice`` (lazy: absent before Inc 9b)."""
    from s19_app.tui.screens import LoadChoice

    return LoadChoice


def is_load_dialog(screen) -> bool:
    """True when ``screen`` is the one Load dialog. Before Inc 9b the class
    does not exist, so this is ``False`` for every screen (the base revision
    has no such dialog)."""
    try:
        cls = load_dialog_cls()
    except ImportError:
        return False
    return isinstance(screen, cls)


def bare_path_dialog(**overrides):
    """A ``LoadDialog`` in path mode fed by inert callables (no rows, every
    verdict ``None``, no preview lines): the dialog alone, for tests about
    the ``#load_path`` field itself."""
    LoadDialog = load_dialog_cls()
    kwargs = dict(
        mode="path",
        highlight=None,
        rows=lambda: [],
        verdict=lambda choice: None,
        preview=lambda choice: [],
    )
    kwargs.update(overrides)
    return LoadDialog(**kwargs)


async def wait_for(pilot, predicate: Callable[[], bool], description: str, attempts: int = 400) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


async def wait_for_dialog(pilot, app, attempts: int = 400) -> None:
    await wait_for(pilot, lambda: is_load_dialog(app.screen), "the Load dialog", attempts)


async def wait_for_dialog_closed(pilot, app, attempts: int = 400) -> None:
    await wait_for(
        pilot, lambda: not is_load_dialog(app.screen), "the Load dialog to close", attempts
    )


def option_prompts(screen) -> list:
    """The plain prompt text of every ``#load_list`` option, in list order."""
    from textual.widgets import OptionList

    lst = screen.query_one("#load_list", OptionList)
    return [str(lst.get_option_at_index(i).prompt) for i in range(lst.option_count)]


def highlighted_prompt(screen) -> Optional[str]:
    from textual.widgets import OptionList

    lst = screen.query_one("#load_list", OptionList)
    if lst.highlighted is None:
        return None
    return str(lst.get_option_at_index(lst.highlighted).prompt)


#: The three section headings of ``#load_list`` (LLR-173.4l: "the headings
#: read Projects, Work area and Recent").
HEADINGS = ("Projects", "Work area", "Recent")


def section_prompts(screen, heading: str, *, loadable_only: bool = True) -> list:
    """The prompts of the ``#load_list`` section under ``heading``, in list
    order, up to the next heading. With ``loadable_only`` the disabled lines
    (the heading itself, an empty-section or problem token line) are left
    out, so the result is exactly the rows a user can load."""
    from textual.widgets import OptionList

    lst = screen.query_one("#load_list", OptionList)
    out: list = []
    inside = False
    for i in range(lst.option_count):
        option = lst.get_option_at_index(i)
        prompt = str(option.prompt)
        if prompt in HEADINGS and option.disabled:
            inside = prompt == heading
            continue
        if inside and (not loadable_only or not option.disabled):
            out.append(prompt)
    return out


async def click_row(pilot, app, label: str, times: int = 1) -> bool:
    """Click the ``#load_list`` row painted ``label`` (``times`` clicks at
    one spot: 2 is a double click). Returns what ``pilot.click`` returned."""
    from textual.widgets import OptionList

    screen = app.screen
    prompts = option_prompts(screen)
    assert label in prompts, f"no #load_list row painted {label!r}; rows: {prompts!r}"
    lst = screen.query_one("#load_list", OptionList)
    index = prompts.index(label)
    lst.scroll_to(y=0, animate=False, immediate=True)
    await pilot.pause()
    top = lst.styles.border_top[0] != ""
    y = (1 if top else 0) + index
    return await pilot.click("#load_list", offset=(3, y), times=times)


async def highlight_row(pilot, app, label: str) -> None:
    """Move the ``#load_list`` highlight onto the row painted ``label`` with
    the arrow keys only (the list must hold the focus). Fails with the
    painted rows when no such row exists."""
    from textual.widgets import OptionList

    screen = app.screen
    prompts = option_prompts(screen)
    assert label in prompts, f"no #load_list row painted {label!r}; rows: {prompts!r}"
    target = prompts.index(label)
    lst = screen.query_one("#load_list", OptionList)
    if lst.highlighted is None:
        await pilot.press("down")
        await pilot.pause()
    for _ in range(2 * len(prompts) + 2):
        current = lst.highlighted
        if current == target:
            return
        await pilot.press("down" if current is None or current < target else "up")
        await pilot.pause()
    raise AssertionError(
        f"the arrow keys did not reach the row {label!r} (highlighted "
        f"{highlighted_prompt(screen)!r})"
    )


async def open_project_through_dialog(
    pilot,
    app,
    name: str,
    *,
    open_key: str = "p",
    confirm: str = "click",
    wait_closed: bool = True,
) -> None:
    """Open the Load dialog with ``open_key`` (``p`` focuses the list), move
    the highlight to the project row painted ``name`` and load it, by a
    click on ``#load_ok`` (``confirm="click"``) or ``enter``
    (``confirm="enter"``)."""
    await pilot.press(open_key)
    await wait_for_dialog(pilot, app)
    for _ in range(4):
        await pilot.pause()
    await highlight_row(pilot, app, name)
    if confirm == "click":
        assert await pilot.click("#load_ok"), "click missed #load_ok"
    else:
        await pilot.press("enter")
    if wait_closed:
        await wait_for_dialog_closed(pilot, app)


async def type_into_path(pilot, app, text: str) -> None:
    """Click ``#load_path``, clear it and type ``text`` key by key."""
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(text))


async def load_path_through_dialog(
    pilot,
    app,
    path,
    *,
    open_key: str = "l",
    confirm: str = "click",
    until: Optional[Callable[[], bool]] = None,
    what: str = "the load",
) -> None:
    """Open the Load dialog with ``open_key``, type ``path`` into
    ``#load_path`` and load it (click ``#load_ok`` or ``enter``); then wait
    for the dialog to close and, when given, for ``until()``."""
    await pilot.press(open_key)
    await wait_for_dialog(pilot, app)
    await type_into_path(pilot, app, str(path))
    if confirm == "click":
        assert await pilot.click("#load_ok"), "click missed #load_ok"
    else:
        await pilot.press("enter")
    await wait_for(
        pilot,
        lambda: not is_load_dialog(app.screen) and (until is None or until()),
        what,
    )
