"""Batch-101 Inc 6 (group "lifecycle") - what a replaced document, a loaded
image and an in-place write leave behind in the Patch Editor.

Covers (cases of ``.dev-flow/2026-11-01-batch-101/inc-6/02-test-cases.md``):

  - R-BEFORE-AFTER-REPORT-001.1/1 and .36/1 - the "press b" offer exists only
    with a project open, and its text carries no developer action name.
  - R-TUI-049.3.1/1 .. /9 - the before/after control is hidden when the
    document is replaced (Load, dropdown pick, accept of the unsaved-changes
    popup, project load, paste, undo, redo) or another image is loaded, and
    kept by a Save project.
  - R-TUI-049.3.2/1 .. /9 - the same for the save-back prompt (a redo with no
    step keeps it).
  - R-CHK-PE-008 .. 012, 014 - the Checks tab (subtitle, status, strip, result
    rows, ledger glyphs) shows a run only while it is current.
  - R-CHKS-001, -004, -009 - the Checks screen does the same, also while it
    stays displayed.

Written from the requirements (``01-requirements.md``) and the cases, never
from the implementation. Every node drives the shipped controls (keys, the
Load dialog, buttons, the dropdown's value) and reads what the product paints
(the compositor's strips of the Patch Editor / the Checks screen). The hidden
class of a row serves only as a wait predicate. Every read that follows a press
waits through the shared ``tests.b97_probes.settled`` for a sign that the app
handled the press (engineering rule 7), also when it asserts that nothing is
painted; a negative read first proves the surface it reads is displayed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input, Select, Static, TextArea

from s19_app.tui.screens_directionb import LoadGuardScreen, PatchEditorPanel
from tests.b97_probes import painted_rows, settled
from tests.support import b100_load_dialog as ld
from tests.support import b100_projects as projects

SIZE = (118, 54)
#: Bound for a read that waits for something to DISAPPEAR (fails fast on base).
GONE = 6.0

PROMPT = "Save patched image as:"
CONTROL = "Before/after report available:"
OFFER = "Before/after report ready - press b to write it to the project reports directory."
NO_RUN_NOTE = "No check run yet — run checks from the Patch Editor."
ZERO_LINE = "Pass 0 / Fail 0 / Uncheck 0 ░░░░░░░░"
RUN_STATUS_K = "Checks: 1 passed, 1 failed, 0 uncheckable"
NO_RUN_STATUS = "No check run yet: press Run checks."

CHG = [projects.address_entry(0x8003, b"\xAA")]
CHG2 = [projects.address_entry(0x8005, b"\xBB")]
CHK = [projects.address_entry(0x8000, b"\x00"), projects.address_entry(0x8001, b"\xFF")]
CHK1 = [projects.address_entry(0x8003, b"\xAA")]


# --------------------------------------------------------------------------- #
# Fixtures: files
# --------------------------------------------------------------------------- #


def _s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_image(path: Path, fill: int = 0) -> Path:
    """Fixture image: one S1 record, 16 bytes ``fill .. fill+15`` at 0x8000."""
    data = bytes((fill + i) & 0xFF for i in range(16))
    path.write_text("\n".join(["S0030000FC", _s1(0x8000, data), "S9030000FC"]) + "\n", encoding="ascii")
    return path


def write_doc(path: Path, entries, kind: str = "change") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(projects.change_document_bytes(entries, kind=kind))
    return path


def make_project(app) -> Path:
    """Project ``proj`` in the work area, holding the variant ``v.s19`` (10..1F)."""
    folder = app.workarea / "proj"
    folder.mkdir(parents=True, exist_ok=True)
    write_image(folder / "v.s19", fill=0x10)
    return folder


# --------------------------------------------------------------------------- #
# Readers (painted state) and drivers (shipped controls)
# --------------------------------------------------------------------------- #


def panel(app) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


def service(app):
    return app._change_service


def pe_text(app) -> str:
    """Everything the Patch Editor paints right now (compositor strips)."""
    return "\n".join(painted_rows(app, panel(app)))


def flat(text: str) -> str:
    return " ".join(text.split())


def plain(widget) -> str:
    rendered = widget.render()
    return getattr(rendered, "plain", str(rendered))


def doc_name(app):
    source = service(app).document.source_path
    return None if source is None else source.name


def ledger_rows(app) -> int:
    return panel(app).query_one("#patch_doc_entries_table", DataTable).row_count


def kind_glyph(app) -> str:
    cell = panel(app).query_one("#patch_doc_entries_table", DataTable).get_cell_at(Coordinate(0, 0))
    return getattr(cell, "plain", str(cell))[0]


def checks_subtitle(app):
    """The Checks tab's run-state token as painted on the inspector's border."""
    found = re.search(r"(\d+ checked|no run yet)", " ".join(painted_rows(app, app.query_one("#patch_inspector"))))
    return None if found is None else found.group(1)


def strip_lines(app) -> list:
    return plain(panel(app).query_one("#patch_checks_strip", Static)).split("\n")


def notices(app) -> list:
    """``(title, message)`` of every ``notify`` call from now on."""
    seen: list = []
    original = app.notify

    def record(message, *args, title="", **kwargs):
        seen.append((title, str(message)))
        return original(message, *args, title=title, **kwargs)

    app.notify = record
    return seen


async def await_text(pilot, app, needle: str, what: str) -> None:
    await settled(pilot, lambda: needle in pe_text(app), f"{what}: {needle!r} painted in the Patch Editor")


async def await_gone(pilot, app, needle: str, what: str) -> None:
    assert "LOADED DOCUMENT" in pe_text(app), f"{what}: the JSON tab is not shown, so an absence proves nothing"
    await settled(
        pilot,
        lambda: needle not in pe_text(app),
        f"{what}: {needle!r} is still painted in the Patch Editor",
        timeout=GONE,
    )


async def show_tab(pilot, app, name: str) -> None:
    pane = {"json": "patch_win_json", "checks": "patch_win_checks", "inspector": "patch_pane_inspector"}[name]
    assert await pilot.click(f"#patch_tab_{name}"), f"click missed #patch_tab_{name}"
    await settled(
        pilot,
        lambda: panel(app).query_one("#patch_tab_switcher").current == pane,
        f"the {name} tab",
    )
    await settled(pilot, lambda: panel(app).query_one(f"#{pane}").region.area > 0, f"the {name} tab painted")


async def start(app, pilot, base: Path, tab: str = "json") -> Path:
    """Fixture image loaded, Patch Editor opened with key ``6``."""
    await pilot.pause()
    image = write_image(base / "img.s19")
    await projects.load_image(pilot, app, image)
    app.set_focus(None)
    await pilot.press("6")
    await settled(pilot, lambda: len(app.query("#patch_editor_panel")) > 0 and panel(app).region.area > 0, "the Patch Editor")
    await show_tab(pilot, app, tab)
    return image


async def load_doc(pilot, app, path: Path) -> None:
    """Type the path, press Load, wait for the document to be that file."""
    p = panel(app)
    p.query_one("#patch_doc_path_input", Input).value = str(path)
    p.query_one("#patch_doc_load_button", Button).press()
    await settled(pilot, lambda: doc_name(app) == path.name, f"the load of {path.name}")


async def add_entry(pilot, app, address: str, data: str) -> None:
    before = ledger_rows(app)
    p = panel(app)
    p.query_one("#patch_entry_address_input", Input).value = address
    p.query_one("#patch_entry_bytes_input", Input).value = data
    p.query_one("#patch_entry_add_button", Button).press()
    await settled(pilot, lambda: ledger_rows(app) == before + 1, f"entry {address} added")


async def remove_entry(pilot, app, address: str) -> None:
    before = ledger_rows(app)
    p = panel(app)
    p.query_one("#patch_entry_address_input", Input).value = address
    p.query_one("#patch_entry_remove_button", Button).press()
    await settled(pilot, lambda: ledger_rows(app) == before - 1, f"entry {address} removed")


async def paste_doc(pilot, app, entries) -> None:
    """Fill the paste buffer and press Parse pasted (no OS clipboard)."""
    p = panel(app)
    p.query_one("#patch_paste_text", TextArea).load_text(projects.change_document_bytes(entries).decode("utf-8"))
    p.query_one("#patch_paste_parse_button", Button).press()
    await settled(
        pilot,
        lambda: doc_name(app) is None and ledger_rows(app) == len(entries),
        "the parsed paste as the document",
    )


async def apply_doc(pilot, app, log, expect: str = r"Apply: [1-9]\d* applied, 0 skipped, 0 blocked") -> None:
    mark = len(log.messages)
    panel(app).query_one("#patch_doc_apply_button", Button).press()
    await settled(pilot, lambda: any(re.search(expect, m) for m in log.since(mark)), f"status {expect!r}")


async def apply_to_prompt(pilot, app, log) -> None:
    await apply_doc(pilot, app, log)
    await await_text(pilot, app, PROMPT, "after Apply")


async def write_file(pilot, app, log) -> None:
    """Press Write file; wait for the save line and for the control to paint."""
    mark = len(log.messages)
    panel(app).query_one("#patch_saveback_confirm_button", Button).press()
    await settled(
        pilot,
        lambda: any("Patched image saved as" in m for m in log.since(mark)),
        "the status line 'Patched image saved as ...'",
    )
    await app.workers.wait_for_complete()


async def run_checks(pilot, app, expect: str) -> None:
    panel(app).query_one("#patch_checks_run_button", Button).press()
    await settled(
        pilot,
        lambda: plain(panel(app).query_one("#patch_checks_status")) == expect,
        f"the run status {expect!r}",
    )


async def load_image_through_dialog(pilot, app, path: Path) -> None:
    """``ctrl+l``, type the path, load; answer Replace (``y``) when the load
    question asks about an image with unsaved bytes."""
    from s19_app.tui.screens import ConfirmQuestionScreen

    def loaded() -> bool:
        return app.current_file is not None and app.current_file.path.name == path.name

    await ld.load_path_through_dialog(
        pilot,
        app,
        path,
        open_key="ctrl+l",
        until=lambda: loaded() or isinstance(app.screen, ConfirmQuestionScreen),
        what=f"the load (or the load question) of {path.name}",
    )
    if isinstance(app.screen, ConfirmQuestionScreen):
        await pilot.press("y")
        await settled(pilot, loaded, f"the load of {path.name} after Replace")


async def open_checks_screen(pilot, app) -> None:
    app.set_focus(None)
    await pilot.press("9")
    await settled(pilot, lambda: len(app.query("#checks_grouped")) > 0 and app.query_one("#checks_grouped").region.area > 0, "the Checks screen")


def checks_screen_text(app) -> str:
    return flat(" ".join(painted_rows(app, app.query_one("#checks_grouped"))))


def checks_strip_text(app) -> str:
    return flat(" ".join(painted_rows(app, app.query_one("#checks_aggregate_strip"))))


async def checks_ready(app, pilot, log, base: Path, entries=CHK, name: str = "k.chk.json", expect: str = RUN_STATUS_K):
    """Image loaded, Patch Editor open, check document loaded and run on the
    Checks tab; the subtitle reads as the run's count."""
    image = await start(app, pilot, base, tab="inspector")
    await load_doc(pilot, app, write_doc(base / name, entries, kind="check"))
    await show_tab(pilot, app, "checks")
    await run_checks(pilot, app, expect)
    if entries:
        await settled(pilot, lambda: checks_subtitle(app) == f"{len(entries)} checked", "the run's subtitle")
    return image


# --------------------------------------------------------------------------- #
# R-BEFORE-AFTER-REPORT-001.1 / .36
# --------------------------------------------------------------------------- #


def test_r_before_after_report_001_1_1_offer_text_in_a_project(tmp_path: Path) -> None:
    """R-BEFORE-AFTER-REPORT-001.1/1: a save-back with a project open shows
    exactly one offer, titled ``Before/after report``, with the text that
    names no developer action. Base: the text ends ``(action: ...)``."""

    async def scenario(app, pilot, log):
        seen = notices(app)
        make_project(app)
        await start(app, pilot, tmp_path)
        await projects.load_project(pilot, app, "proj")
        assert app._active_project_dir() is not None
        await load_doc(pilot, app, write_doc(tmp_path / "c.json", CHG))
        await apply_to_prompt(pilot, app, log)
        await write_file(pilot, app, log)
        await await_text(pilot, app, CONTROL, "after the save-back")
        return [m for t, m in seen if t == "Before/after report"]

    offers = projects.run_app(tmp_path, scenario, size=SIZE)
    assert offers == [OFFER], offers


def test_r_before_after_report_001_36_1_no_offer_without_a_project(tmp_path: Path) -> None:
    """R-BEFORE-AFTER-REPORT-001.36/1: with no project open a save-back shows
    no before/after offer. The sign that the save-back ended is the status line
    ``Patched image saved as img-patched.s19``; the control (painted in the
    same handler as the offer would be notified) proves the handler finished.
    Base: one offer is shown."""

    async def scenario(app, pilot, log):
        seen = notices(app)
        await start(app, pilot, tmp_path)
        assert app.current_project is None
        await load_doc(pilot, app, write_doc(tmp_path / "c.json", CHG))
        await apply_to_prompt(pilot, app, log)
        mark = len(log.messages)
        await write_file(pilot, app, log)
        assert any(m.startswith("Patched image saved as img-patched.s19") for m in log.since(mark)), log.since(mark)
        await await_text(pilot, app, CONTROL, "after the save-back")
        for _ in range(4):
            await pilot.pause()
        return [m for t, m in seen if t == "Before/after report"]

    offers = projects.run_app(tmp_path, scenario, size=SIZE)
    assert offers == [], offers


# --------------------------------------------------------------------------- #
# R-TUI-049.3.1 / R-TUI-049.3.2 - what a replaced document leaves
# --------------------------------------------------------------------------- #

ALTERNATIVES = ["load", "pick", "guarded", "project", "paste", "undo", "redo", "image"]


async def _replace_scenario(app, pilot, log, base: Path, alt: str, shown: str):
    """Prepare "``shown`` is painted", then trigger the alternative and wait for
    its own sign. Returns nothing; the caller reads the painted state."""
    patches = app.workarea / "patches"
    c = write_doc(patches / "c.json", CHG)
    c2 = write_doc(patches / "c2.json", CHG2)
    if alt == "project":
        make_project(app)
    await start(app, pilot, base)
    needle = CONTROL if shown == "control" else PROMPT
    drafted = alt in ("undo", "redo")
    if drafted:
        await paste_doc(pilot, app, CHG2)
        await add_entry(pilot, app, "0x8007", "CC")
    else:
        await load_doc(pilot, app, c)
        if alt == "guarded":
            await add_entry(pilot, app, "0x8007", "CC")
    await apply_to_prompt(pilot, app, log)
    if shown == "control":
        await write_file(pilot, app, log)
    await await_text(pilot, app, needle, "the precondition")

    if alt == "redo":
        app.set_focus(None)
        await pilot.press("ctrl+z")
        await settled(pilot, lambda: ledger_rows(app) == 1, "the undo step")
        await apply_to_prompt(pilot, app, log)
        if shown == "control":
            await write_file(pilot, app, log)
        await await_text(pilot, app, needle, "the precondition before redo")

    p = panel(app)
    if alt == "load":
        await load_doc(pilot, app, c2)
    elif alt == "pick":
        p.query_one("#patch_doc_file_select", Select).value = "c2.json"
        await settled(pilot, lambda: doc_name(app) == "c2.json", "the pick of c2.json")
    elif alt == "guarded":
        p.query_one("#patch_doc_path_input", Input).value = str(c2)
        p.query_one("#patch_doc_load_button", Button).press()
        await settled(pilot, lambda: isinstance(app.screen, LoadGuardScreen), "the unsaved-changes popup")
        app.screen.query_one("#load_guard_accept", Button).press()
        await settled(pilot, lambda: doc_name(app) == "c2.json", "the accepted load of c2.json")
    elif alt == "project":
        await projects.load_project(pilot, app, "proj")
        await settled(
            pilot,
            lambda: app.current_file is not None and app.current_file.path.name == "v.s19",
            "the project's variant installed",
        )
    elif alt == "paste":
        await paste_doc(pilot, app, CHG2)
    elif alt == "undo":
        app.set_focus(None)
        await pilot.press("ctrl+z")
        await settled(pilot, lambda: ledger_rows(app) == 1, "the undo step")
    elif alt == "redo":
        app.set_focus(None)
        await pilot.press("ctrl+y")
        await settled(pilot, lambda: ledger_rows(app) == 2, "the redo step")
    elif alt == "image":
        await load_image_through_dialog(pilot, app, write_image(base / "img2.s19", fill=0x40))
    for _ in range(4):
        await pilot.pause()
    await show_tab(pilot, app, "json")
    return needle


@pytest.mark.parametrize("alt", ALTERNATIVES)
def test_r_tui_049_3_1_control_hidden(tmp_path: Path, alt: str) -> None:
    """R-TUI-049.3.1/1 .. /8 (``load``, ``pick``, ``guarded``, ``project``,
    ``paste``, ``undo``, ``redo``, ``image``): after the document is replaced
    (or another image loaded) ``Before/after report available:`` is not
    painted. Base: stays after every alternative but ``load`` and ``paste``
    (those two are standing guards)."""

    async def scenario(app, pilot, log):
        needle = await _replace_scenario(app, pilot, log, tmp_path, alt, "control")
        await await_gone(pilot, app, needle, f"after {alt}")

    projects.run_app(tmp_path, scenario, size=SIZE)


@pytest.mark.parametrize("alt", ALTERNATIVES)
def test_r_tui_049_3_2_prompt_hidden(tmp_path: Path, alt: str) -> None:
    """R-TUI-049.3.2/1 .. /8: after the document is replaced (or another image
    loaded) ``Save patched image as:`` is not painted, and no file is written
    (/8: no ``img-patched.s19`` under the work area; base: a confirm would write
    image 2 under that name). Base: stays after every alternative."""

    async def scenario(app, pilot, log):
        needle = await _replace_scenario(app, pilot, log, tmp_path, alt, "prompt")
        await await_gone(pilot, app, needle, f"after {alt}")
        assert not list(app.workarea.rglob("img-patched*.s19")), "a save-back file exists"

    projects.run_app(tmp_path, scenario, size=SIZE)


async def _save_project_keeps(app, pilot, log, base: Path, shown: str):
    make_project(app)
    await start(app, pilot, base)
    await projects.load_project(pilot, app, "proj")
    await paste_doc(pilot, app, CHG2)
    await apply_to_prompt(pilot, app, log)
    if shown == "control":
        await write_file(pilot, app, log)
    needle = CONTROL if shown == "control" else PROMPT
    await await_text(pilot, app, needle, "the precondition")
    messages = await projects.save_project(pilot, app, log, "proj")
    assert any(m.startswith("Saved project to ") for m in messages), messages
    for _ in range(6):
        await pilot.pause()
    await show_tab(pilot, app, "json")
    assert needle in pe_text(app), f"{needle!r} was hidden by a Save project: {pe_text(app)}"


def test_r_tui_049_3_1_control_kept_on_save_project(tmp_path: Path) -> None:
    """R-TUI-049.3.1/9 (negative arm): a Save project places the pasted
    document and replaces none, so the control stays painted. Standing guard on
    base (base hides nothing there)."""
    projects.run_app(
        tmp_path, lambda app, pilot, log: _save_project_keeps(app, pilot, log, tmp_path, "control"), size=SIZE
    )


def test_r_tui_049_3_2_prompt_kept_on_save_project(tmp_path: Path) -> None:
    """R-TUI-049.3.2/9 (negative arm): a Save project keeps the save-back
    prompt painted. Standing guard on base."""
    projects.run_app(
        tmp_path, lambda app, pilot, log: _save_project_keeps(app, pilot, log, tmp_path, "prompt"), size=SIZE
    )


def test_r_tui_049_3_2_prompt_redo_with_no_step_keeps_it(tmp_path: Path) -> None:
    """R-TUI-049.3.2/7 (negative arm of the redo case): a redo that finds no
    step leaves the prompt of a fresh Apply painted. The sign that both presses
    were handled is the later Refresh's status line."""

    async def scenario(app, pilot, log):
        await _replace_scenario(app, pilot, log, tmp_path, "redo", "prompt")
        await await_gone(pilot, app, PROMPT, "after the redo")
        await apply_to_prompt(pilot, app, log)  # the redo stack is empty now
        app.set_focus(None)
        await pilot.press("ctrl+y")
        mark = len(log.messages)
        panel(app).query_one("#patch_doc_refresh_button", Button).press()
        await settled(
            pilot,
            lambda: any("Patch Editor: file list refreshed." in m for m in log.since(mark)),
            "the Refresh status line",
        )
        for _ in range(4):
            await pilot.pause()
        assert PROMPT in pe_text(app), "a redo with no step hid the save-back prompt"

    projects.run_app(tmp_path, scenario, size=SIZE)


# --------------------------------------------------------------------------- #
# R-CHK-PE-008 .. 014 - the Checks tab shows a current run only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ["two", "zero", "revert"])
def test_r_chk_pe_008_subtitle(tmp_path: Path, case: str) -> None:
    """R-CHK-PE-008/1 (``two``): a current 2-entry run reads ``2 checked``;
    /2 (``zero``): a current 0-entry run reads ``0 checked`` (base:
    ``no run yet``); /3 (``revert``): an Add ends the current state
    (``no run yet``) and the Remove that undoes it restores ``2 checked`` with
    its 2 result rows and the same status."""

    async def scenario(app, pilot, log):
        if case == "zero":
            await checks_ready(app, pilot, log, tmp_path, entries=[], name="e.chk.json",
                               expect="Checks: 0 passed, 0 failed, 0 uncheckable")
            await settled(pilot, lambda: checks_subtitle(app) == "0 checked", "the 0-entry run's subtitle")
            return
        await checks_ready(app, pilot, log, tmp_path)
        assert checks_subtitle(app) == "2 checked"
        if case == "revert":
            await add_entry(pilot, app, "0x8007", "CC")
            await settled(pilot, lambda: checks_subtitle(app) == "no run yet", "no run yet after Add", timeout=GONE)
            await remove_entry(pilot, app, "0x8007")
            await settled(pilot, lambda: checks_subtitle(app) == "2 checked", "2 checked after Remove", timeout=GONE)
            assert len(panel(app).query_one("#patch_checks_results").children) == 2
            assert plain(panel(app).query_one("#patch_checks_status")) == RUN_STATUS_K

    projects.run_app(tmp_path, scenario, size=SIZE)


async def _end_run(pilot, app, log, base: Path, how: str) -> None:
    """Trigger ``how`` after a current 2-entry run; wait for its own sign."""
    mark = len(log.messages)
    if how == "load":
        await load_doc(pilot, app, write_doc(base / "c.json", CHG))
    elif how == "image":
        await load_image_through_dialog(pilot, app, write_image(base / "img2.s19", fill=0x40))
    elif how == "project":
        await projects.load_project(pilot, app, "proj")
    elif how == "add":
        await add_entry(pilot, app, "0x8007", "CC")
    elif how == "mac":
        mac = base / "m.mac"
        mac.write_text("T=0x8000\n", encoding="ascii")
        await ld.load_path_through_dialog(
            pilot, app, mac, open_key="ctrl+l", until=lambda: any(m.startswith("Loaded m.mac") for m in log.since(mark)),
            what="the load of m.mac",
        )
    for _ in range(4):
        await pilot.pause()


def _no_run_shown(app) -> bool:
    return checks_subtitle(app) == "no run yet"


@pytest.mark.parametrize("how", ["load", "image", "project", "add", "apply", "mac"])
def test_r_chk_pe_009_no_run(tmp_path: Path, how: str) -> None:
    """R-CHK-PE-009/1 .. /6: the subtitle reads ``no run yet`` after another
    document load, an image load, a project load, an Add, an apply of a check
    document that writes the image in place (/5, E3A-03), and a MAC load (/6).
    Base: ``2 checked`` (``1 checked`` for /5) stays."""

    async def scenario(app, pilot, log):
        if how == "apply":
            await start(app, pilot, tmp_path)
            await load_doc(pilot, app, write_doc(tmp_path / "c.json", CHG))
            await apply_to_prompt(pilot, app, log)
            await load_doc(pilot, app, write_doc(tmp_path / "k1.chk.json", CHK1, kind="check"))
            await show_tab(pilot, app, "checks")
            await run_checks(pilot, app, "Checks: 1 passed, 0 failed, 0 uncheckable")
            await settled(pilot, lambda: checks_subtitle(app) == "1 checked", "1 checked")
            await apply_doc(pilot, app, log, expect=r"Apply: 0 applied, 0 skipped, 1 blocked")
        else:
            if how == "project":
                make_project(app)
            await checks_ready(app, pilot, log, tmp_path)
            await _end_run(pilot, app, log, tmp_path, how)
        await settled(pilot, lambda: _no_run_shown(app), f"no run yet after {how} (painted: {checks_subtitle(app)!r})", timeout=GONE)
        if how == "mac":
            await settled(
                pilot,
                lambda: len(panel(app).query_one("#patch_checks_results").children) == 0,
                "no result row after the MAC load",
                timeout=GONE,
            )
        if how == "apply":
            assert plain(panel(app).query_one("#patch_checks_status")) == NO_RUN_STATUS

    projects.run_app(tmp_path, scenario, size=SIZE)


@pytest.mark.parametrize("how", ["load", "project"])
def test_r_chk_pe_010_status(tmp_path: Path, how: str) -> None:
    """R-CHK-PE-010/1, /2: after another document load / a project load the
    Checks tab status is ``No check run yet: press Run checks.``."""

    async def scenario(app, pilot, log):
        if how == "project":
            make_project(app)
        await checks_ready(app, pilot, log, tmp_path)
        await _end_run(pilot, app, log, tmp_path, how)
        await settled(
            pilot,
            lambda: plain(panel(app).query_one("#patch_checks_status")) == NO_RUN_STATUS,
            "the no-run status",
            timeout=GONE,
        )

    projects.run_app(tmp_path, scenario, size=SIZE)


@pytest.mark.parametrize("how", ["load", "project"])
def test_r_chk_pe_011_strip(tmp_path: Path, how: str) -> None:
    """R-CHK-PE-011/1, /2: after another document load / a project load the
    patch strip reads ``✓0 ✗0 ◐0`` over an empty bar ``░░░░░░░░``."""

    async def scenario(app, pilot, log):
        if how == "project":
            make_project(app)
        await checks_ready(app, pilot, log, tmp_path)
        await _end_run(pilot, app, log, tmp_path, how)
        await settled(
            pilot, lambda: strip_lines(app) == ["✓0 ✗0 ◐0", "░░░░░░░░"], f"the zero strip (now {strip_lines(app)!r})", timeout=GONE
        )

    projects.run_app(tmp_path, scenario, size=SIZE)


@pytest.mark.parametrize("how", ["load", "project"])
def test_r_chk_pe_012_rows(tmp_path: Path, how: str) -> None:
    """R-CHK-PE-012/1, /2: after another document load / a project load the
    Checks tab holds no result row."""

    async def scenario(app, pilot, log):
        if how == "project":
            make_project(app)
        await checks_ready(app, pilot, log, tmp_path)
        assert len(panel(app).query_one("#patch_checks_results").children) == 2
        await _end_run(pilot, app, log, tmp_path, how)
        await settled(
            pilot,
            lambda: len(panel(app).query_one("#patch_checks_results").children) == 0,
            "no result row",
            timeout=GONE,
        )

    projects.run_app(tmp_path, scenario, size=SIZE)


def test_r_chk_pe_014_glyph_after_save_back(tmp_path: Path) -> None:
    """R-CHK-PE-014/1: a save-back that ends a run repaints the ledger: the Kind
    cell leads with ``·`` and the subtitle reads ``no run yet``. Before it the
    blocked run's entries read ``◐``. Base: ``◐`` stays."""

    async def scenario(app, pilot, log):
        await start(app, pilot, tmp_path)
        await load_doc(pilot, app, write_doc(tmp_path / "c.json", CHG))
        await apply_to_prompt(pilot, app, log)
        await show_tab(pilot, app, "checks")
        panel(app).query_one("#patch_checks_run_button", Button).press()
        await settled(
            pilot,
            lambda: plain(panel(app).query_one("#patch_checks_status")).startswith("Checks: not run — "),
            "the blocked run's status",
        )
        await settled(pilot, lambda: kind_glyph(app) == "◐", "the ledger's ◐ after the run")
        await write_file(pilot, app, log)
        await settled(pilot, lambda: kind_glyph(app) == "·", f"the ledger's · after the save-back (now {kind_glyph(app)!r})", timeout=GONE)
        assert checks_subtitle(app) == "no run yet"

    projects.run_app(tmp_path, scenario, size=SIZE)


# --------------------------------------------------------------------------- #
# R-CHKS-001 / -004 / -009 - the Checks screen shows a current run only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ["current", "stale"])
def test_r_chks_001_screen(tmp_path: Path, case: str) -> None:
    """R-CHKS-001/1 (``current``): the Checks screen shows the failed group
    then the passed group with their rows. /2 (``stale``): after another
    document load it shows no group, only the no-run note. Base: the stale
    groups stay."""

    async def scenario(app, pilot, log):
        await checks_ready(app, pilot, log, tmp_path)
        if case == "stale":
            await load_doc(pilot, app, write_doc(tmp_path / "c.json", CHG))
        await open_checks_screen(pilot, app)
        if case == "current":
            await settled(pilot, lambda: "✗ FAILED (1)" in checks_screen_text(app), "the failed group")
            text = checks_screen_text(app)
            assert text.index("✗ FAILED (1)") < text.index("✓ PASSED (1)"), text
            assert "expected [FF] actual [01]" in text and "expected [00] actual [00]" in text, text
        else:
            await settled(pilot, lambda: NO_RUN_NOTE in checks_screen_text(app), "the no-run note", timeout=GONE)
            assert "FAILED" not in checks_screen_text(app) and "PASSED" not in checks_screen_text(app)

    projects.run_app(tmp_path, scenario, size=SIZE)


def test_r_chks_004_note_after_image_load(tmp_path: Path) -> None:
    """R-CHKS-004/1: after a run and another image's load, opening the Checks
    screen shows ``No check run yet — run checks from the Patch Editor.``."""

    async def scenario(app, pilot, log):
        await checks_ready(app, pilot, log, tmp_path)
        await load_image_through_dialog(pilot, app, write_image(tmp_path / "img2.s19", fill=0x40))
        await open_checks_screen(pilot, app)
        await settled(pilot, lambda: NO_RUN_NOTE in checks_screen_text(app), "the no-run note", timeout=GONE)
        assert "FAILED" not in checks_screen_text(app)

    projects.run_app(tmp_path, scenario, size=SIZE)


def test_r_chks_004_note_while_displayed(tmp_path: Path) -> None:
    """R-CHKS-004/2: the Checks screen stays displayed while another image
    loads; once the load's file status is painted the note is painted without
    reopening the screen, and no group header. Base: the groups stay."""

    async def scenario(app, pilot, log):
        await checks_ready(app, pilot, log, tmp_path)
        await open_checks_screen(pilot, app)
        await settled(pilot, lambda: "✗ FAILED (1)" in checks_screen_text(app) and "✓ PASSED (1)" in checks_screen_text(app), "both groups")
        mark = len(log.messages)
        await load_image_through_dialog(pilot, app, write_image(tmp_path / "img2.s19", fill=0x40))
        await settled(pilot, lambda: any(m.startswith("Loaded img2.s19") for m in log.since(mark)), "the load's file status")
        await settled(pilot, lambda: NO_RUN_NOTE in checks_screen_text(app), "the note without reopening", timeout=GONE)
        assert "FAILED" not in checks_screen_text(app)

    projects.run_app(tmp_path, scenario, size=SIZE)


def test_r_chks_009_zero_line(tmp_path: Path) -> None:
    """R-CHKS-009/1: after a run and another document's load, the Checks
    screen's aggregate line reads ``Pass 0 / Fail 0 / Uncheck 0 ░░░░░░░░``."""

    async def scenario(app, pilot, log):
        await checks_ready(app, pilot, log, tmp_path)
        await load_doc(pilot, app, write_doc(tmp_path / "c.json", CHG))
        await open_checks_screen(pilot, app)
        await settled(pilot, lambda: checks_strip_text(app) == ZERO_LINE, f"the zero line (now {checks_strip_text(app)!r})", timeout=GONE)

    projects.run_app(tmp_path, scenario, size=SIZE)


def test_r_chks_009_zero_line_while_displayed(tmp_path: Path) -> None:
    """R-CHKS-009/2: the Checks screen stays displayed while a project loads
    through the Load dialog (key ``p``); once the project is installed and the
    load-result panel is closed, the aggregate line reads zero without
    reopening the screen. Base: ``Pass 1 / Fail 1 / Uncheck 0``. Deviation from
    E3A-16 (no variant): a project must hold a data or A2L file, and an A2L-only
    project installs no image, so the Checks content is hidden (empty state) and
    nothing is painted to read; the variant's project is used, and base still
    shows the stale line."""

    async def scenario(app, pilot, log):
        make_project(app)
        await checks_ready(app, pilot, log, tmp_path)
        await open_checks_screen(pilot, app)
        await settled(pilot, lambda: checks_strip_text(app).startswith("Pass 1 / Fail 1"), "the run's aggregate line")
        await ld.open_project_through_dialog(pilot, app, "proj")
        await settled(
            pilot,
            lambda: app.current_project == "proj" and app._last_load_announcement is not None,
            "the project-load summary",
        )
        await projects.dismiss_load_result_panel(pilot, app)
        for _ in range(4):
            await pilot.pause()
        await settled(pilot, lambda: checks_strip_text(app) == ZERO_LINE, f"the zero line (now {checks_strip_text(app)!r})", timeout=GONE)

    projects.run_app(tmp_path, scenario, size=SIZE)
