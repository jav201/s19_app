"""batch-101 Inc 6 - document homes and lists (tester 2 of E4).

Written by an independent tester from the approved design only:
``inc-6/01-requirements.md`` (rows and thresholds), ``02-test-cases.md`` (the
cases), ``E1-rulings.md`` (D-1 .. D-6, revised D-3) and ``E3-rulings.md``
(S-2 .. S-6, E3A-04, E3A-18). No line of the Inc 6 implementation was read to
decide what to assert.

Group: where a document lives and what the three lists show.

  - R-PATCH-DOC-DROPDOWN-001.1 .. .4 - the Patch Editor File dropdown in a
    project: ``checks/<n>``, ``patches/<n>``, then the common library as
    ``library/<n>``; a library pick opens it; links and linked folders are
    refused with the row's exact text; the unsaved-changes popup checks again.
  - R-CHKED-031 / -034 / -040 / -042 / -044 - the Check Editor writes into the
    check home, lists it, sets Write as to the bare name, refuses links.
  - R-DIFF-CHK.1 / .3 / .5 / .8 - the A2B Diff check-spec list follows the
    spec list.

Coverage of ``02-test-cases.md`` (one node per case; the case id is in each
docstring). Cases owned by other nodes: R-PATCH-DOC-DROPDOWN-001.3/2 and
R-DIFF-CHK.1/2 (existing ``covered`` nodes).

Oracles: the option values the app painted into each dropdown, the status
lines the app wrote (read with ``StatusLog.since(mark)``), the panel's own
painted status widgets, and the files on disk. Every wait polls a sign that the
app handled the press or message (the shared ``settled`` / ``wait_until``);
a negative arm waits for the refusal line itself. Black-box: dropdown picks go
through the click-and-arrow-keys route of ``test_b101_symbol_reads``; the
project load goes through the ``p`` dialog where a case names the trigger;
refusal arms post the panel's own selection message.

Platform: file symbolic links need no privilege on POSIX; on Windows a file
link needs one, so the file-link arms skip with that named reason there. Folder
links are directory junctions on Windows and symbolic links elsewhere. Every
link lives under ``tmp_path``. ``LOCALAPPDATA`` is isolated by
``tests/conftest.py``; no case touches the OS clipboard.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input, Label, Select

from s19_app.tui.screens_directionb import (
    AbDiffPanel,
    CheckEditorPanel,
    PatchEditorPanel,
)
from tests.b97_probes import is_displayed, painted_rows, settled
from tests.support import b100_load_dialog as ld
from tests.support import b100_projects as projects
from tests.support.b100_projects import LOAD_RESULT_CLOSE
from tests.support import b100_save_dialog as sd
from tests.support.b100_workers import settle_workers
from tests.support.timing import wait_until

SIZE = (118, 54)

# ---------------------------------------------------------------------------
# Fixtures: images, documents, projects, links
# ---------------------------------------------------------------------------


def _s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_image(path: Path, fill: int = 0) -> Path:
    """One S1 record: 16 bytes ``fill .. fill+15`` at ``0x8000``."""
    data = bytes((fill + i) & 0xFF for i in range(16))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(["S0030000FC", _s1(0x8000, data), "S9030000FC"]) + "\n",
        encoding="ascii",
    )
    return path


#: Document C (one bytes entry), Check K (one pass, one fail), Check W.
ENTRY_C = [projects.address_entry(0x8003, b"\xAA")]
ENTRIES_K = [
    projects.address_entry(0x8000, b"\x00"),
    projects.address_entry(0x8001, b"\xFF"),
]
ENTRY_W = [projects.address_entry(0x8000, b"\x00")]


def write_doc(path: Path, entries, kind: str = "change") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(projects.change_document_bytes(entries, kind=kind))
    return path


def make_project(workarea: Path, name: str = "proj") -> Path:
    """Project ``name``: a variant ``v.s19`` (bytes ``10 .. 1F`` at
    ``0x8000``) and a manifest recording it. Its ``patches/`` and ``checks/``
    folders are NOT created here: a case adds the ones it needs."""
    folder = workarea / name
    image = write_image(folder / "v.s19", fill=0x10)
    (folder / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "v",
                "files": {"v.s19": projects.file_record_of(image)},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return folder


def make_link(link: Path, target: Path) -> None:
    """``link`` -> ``target`` (a folder or a file), under ``tmp_path`` only.
    Folder links are junctions on Windows; a file link needs a privilege there
    and the calling test skips with that reason when it is missing."""
    link.parent.mkdir(parents=True, exist_ok=True)
    if target.is_dir():
        if sys.platform == "win32":
            from tests.support.b100_links import create_junction

            create_junction(link, target)
        else:
            link.symlink_to(target, target_is_directory=True)
        return
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("a file symbolic link needs a privilege this platform does not grant here")


def run(tmp_path: Path, scenario, name: str = "app", base: Path | None = None):
    root = base if base is not None else tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return projects.run_app(root, scenario, size=SIZE)


# ---------------------------------------------------------------------------
# Readers and waits
# ---------------------------------------------------------------------------


def option_values(select: Select) -> list:
    """The concrete option values of a dropdown, in order (blank and the
    A2B Diff's ``(no check spec)`` entry left out)."""
    return [
        value
        for _label, value in select._options
        if value is not Select.BLANK and value is not Select.NULL and value != ""
    ]


def option_labels(select: Select) -> list:
    return [
        getattr(label, "plain", str(label))
        for label, value in select._options
        if value is not Select.BLANK and value is not Select.NULL and value != ""
    ]


def patch_select(app) -> Select:
    return app.query_one("#patch_doc_file_select", Select)


def spec_select(app) -> Select:
    return app.query_one("#check_spec_file_select", Select)


def diff_select(app) -> Select:
    return app.query_one("#diff_check_select", Select)


def patch_panel(app) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


def table_rows(app) -> int:
    return app.query_one("#patch_doc_entries_table", DataTable).row_count


def source_of(app):
    return app._change_service.document.source_path


def doc_snapshot(app) -> tuple:
    document = app._change_service.document
    return (
        document.source_path,
        document.kind,
        tuple((e.address, tuple(e.encoded_bytes)) for e in document.entries),
    )


def diff_status(app) -> str:
    return str(app.query_one("#diff_status").render())


def check_status(app) -> str:
    return str(app.query_one("#check_status", Label).render())


async def show_patch_editor(pilot, app) -> None:
    await pilot.press("6")
    await settled(
        pilot,
        lambda: len(app.query("#patch_doc_file_select")) > 0
        and patch_select(app).region.width > 0,
        "the Patch Editor and its File dropdown after key 6",
    )


async def show_check_editor(pilot, app) -> None:
    await pilot.press("equals_sign")
    await settled(
        pilot,
        lambda: len(app.query("#check_spec_file_select")) > 0
        and spec_select(app).region.width > 0,
        "the Check Editor and its Spec dropdown after key =",
    )


async def show_diff(pilot, app, expect_row: bool = True) -> None:
    await pilot.press("7")
    await settled(
        pilot,
        lambda: len(app.query("#ab_diff_panel")) > 0
        and app.query_one("#ab_diff_panel").region.width > 0
        and is_displayed(app.query_one("#ab_diff_panel")),
        "the A2B Diff after key 7",
    )
    if expect_row:
        await settled(
            pilot, lambda: len(app.query("#diff_check_select")) > 0,
            "the check-spec row of the A2B Diff",
        )


async def wait_line(pilot, log, mark: int, predicate, what: str, timeout: float = 60.0) -> list:
    """Wait until a status line written after ``mark`` satisfies ``predicate``;
    return the lines written since ``mark``."""
    await wait_until(
        pilot,
        lambda: any(predicate(line) for line in log.since(mark)),
        lambda: f"timed out waiting for {what}; lines: {log.since(mark)!r}",
        timeout=timeout,
        pause_first=True,
    )
    return log.since(mark)


async def pick(pilot, app, select_id: str, value: str) -> None:
    """Pick ``value`` the way the operator does: click the dropdown open, move
    with the arrow keys, press enter (no ``Select.value`` write)."""
    from textual.widgets._select import SelectCurrent, SelectOverlay

    select = app.query_one(select_id, Select)
    values = [option_value for _prompt, option_value in select._options]
    assert value in values, (
        f"{value!r} is not offered by {select_id}; the dropdown lists {option_values(select)!r}"
    )
    target = values.index(value)
    face = select.query_one(SelectCurrent)
    under, _region = app.get_widget_at(face.region.x, face.region.y)
    assert under is face or face in under.ancestors, (select_id, under)
    await pilot.click(face)
    overlay = select.query_one(SelectOverlay)
    await wait_until(
        pilot,
        lambda: select.expanded and app.focused is overlay,
        f"timed out waiting for the {select_id} dropdown to open",
    )
    for _ in range(len(values) + 1):
        if overlay.highlighted == target:
            break
        current = -1 if overlay.highlighted is None else overlay.highlighted
        await pilot.press("down" if current < target else "up")
    assert overlay.highlighted == target, (overlay.highlighted, target, values)
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: not select.expanded and select.value == value,
        f"timed out waiting for {select_id} to take {value!r}",
    )


async def open_project_shipped(pilot, app, name: str = "proj") -> None:
    """Open ``name`` through the shipped project handler (a precondition)."""
    await projects.load_project(pilot, app, name)
    await close_result_panel(pilot, app)


async def open_project_by_dialog(pilot, app, name: str = "proj") -> None:
    """The ``p`` key, the row of ``name``, Load - the trigger a case names."""
    app.set_focus(None)
    await ld.open_project_through_dialog(pilot, app, name)
    await wait_until(
        pilot,
        lambda: app.current_project == name and app.current_file is not None,
        f"timed out waiting for the project install of {name}",
    )
    await settle_workers(pilot)
    await close_result_panel(pilot, app)


async def close_result_panel(pilot, app) -> None:
    for _ in range(4):
        await pilot.pause()
    if len(app.screen.query(LOAD_RESULT_CLOSE)) > 0:
        await projects.dismiss_load_result_panel(pilot, app)
    await settle_workers(pilot)


async def save_project_by_dialog(pilot, app, log, name: str) -> None:
    """``ctrl+s``, type ``name``, Save; wait for the ``Saved project to`` line."""
    mark = len(log.messages)
    app.set_focus(None)
    await sd.save_through_dialog(pilot, app, name)
    await wait_line(
        pilot, log, mark, lambda line: line.startswith("Saved project to "),
        "the Save project outcome",
    )
    await settle_workers(pilot)


async def add_patch_entry(pilot, app, address: str, bytes_text: str) -> None:
    app.query_one("#patch_entry_address_input", Input).value = address
    app.query_one("#patch_entry_bytes_input", Input).value = bytes_text
    before = table_rows(app)
    app.query_one("#patch_entry_add_button", Button).press()
    await settled(pilot, lambda: table_rows(app) == before + 1, f"the entry {address} in the table")


async def add_check_row(pilot, app, address: str = "0x8000", size: str = "2") -> None:
    app.query_one("#check_mem_address_input", Input).value = address
    app.query_one("#check_mem_label_input", Input).value = "m0"
    app.query_one("#check_mem_size_input", Input).value = size
    table = app.query_one("#check_mem_table", DataTable)
    before = table.row_count
    app.query_one("#check_mem_add_button", Button).press()
    await settled(pilot, lambda: table.row_count == before + 1, "the memory row in the table")


async def write_spec(pilot, app, log, name: str) -> list:
    """Write as ``name`` and wait for the writer's outcome line."""
    app.query_one("#check_file_name_input", Input).value = name
    mark = len(log.messages)
    app.query_one("#check_write_button", Button).press()
    return await wait_line(
        pilot,
        log,
        mark,
        lambda line: line.startswith("Check Editor: wrote ") or line == "Check Editor: spec NOT written.",
        "the Check Editor Write outcome",
    )


def files_under(folder: Path) -> dict:
    """Relative POSIX name -> bytes, for every file under ``folder``."""
    return projects.tree_files(folder)


async def load_image_fixture(pilot, app, base: Path) -> None:
    await projects.load_image(pilot, app, write_image(base / "img.s19"))


def lib(app) -> Path:
    """The common library folder (``workarea/patches``)."""
    return app.workarea / "patches"


# ===========================================================================
# R-PATCH-DOC-DROPDOWN-001.1 - the change list
# ===========================================================================


@pytest.mark.parametrize(
    "arm", ["open", "save", "refresh", "no-project", "project-load", "save-project"]
)
def test_r_patch_doc_dropdown_001_1_change_list(tmp_path: Path, arm: str) -> None:
    """Cases R-PATCH-DOC-DROPDOWN-001.1/1 .. /6: the File dropdown's option
    values equal the change list exactly, in order.

    /1 open: project with ``patches/a.json``, ``checks/k.chk.json`` and a
    library ``w.json`` -> ``checks/k.chk.json``, ``patches/a.json``,
    ``library/w.json``. /2 save: Add + Save in an empty project ->
    ``patches/changes.json``. /3 refresh: a spec written into ``checks/`` after
    the screen opened shows after Refresh. /4 no project: bare names, unchanged.
    /5 project load while the Patch Editor stays displayed (E3A-04).
    /6 Save project that creates the project, Patch Editor displayed (E3A-04).

    Why: F-06 - what Save writes into the project must be what the dropdown
    lists, and the library must stay reachable (revised D-3). Negative control:
    the scan of ``workarea/patches/`` only -> the project arms list the wrong
    values -> RED; no refill after the project install -> /5, /6 keep the old
    values -> RED."""

    async def scenario(app, pilot, log):
        if arm == "open":
            project = make_project(app.workarea)
            write_doc(project / "patches" / "a.json", ENTRY_C)
            write_doc(project / "checks" / "k.chk.json", ENTRIES_K, kind="check")
            write_doc(lib(app) / "w.json", ENTRY_C)
            await open_project_shipped(pilot, app)
            await show_patch_editor(pilot, app)
            assert option_values(patch_select(app)) == [
                "checks/k.chk.json",
                "patches/a.json",
                "library/w.json",
            ]
        elif arm == "save":
            make_project(app.workarea)
            await open_project_shipped(pilot, app)
            await show_patch_editor(pilot, app)
            await add_patch_entry(pilot, app, "0x8002", "11")
            mark = len(log.messages)
            app.query_one("#patch_doc_save_button", Button).press()
            lines = await wait_line(
                pilot, log, mark, lambda line: line.startswith("Saved change-set to "),
                "the Save status",
            )
            assert "Saved change-set to changes.json" in lines, lines
            assert option_values(patch_select(app)) == ["patches/changes.json"]
        elif arm == "refresh":
            project = make_project(app.workarea)
            await open_project_shipped(pilot, app)
            await show_patch_editor(pilot, app)
            write_doc(project / "checks" / "k.chk.json", ENTRIES_K, kind="check")
            mark = len(log.messages)
            app.query_one("#patch_doc_refresh_button", Button).press()
            await wait_line(
                pilot, log, mark, lambda line: line == "Patch Editor: file list refreshed.",
                "the Refresh status",
            )
            assert option_values(patch_select(app)) == ["checks/k.chk.json"]
        elif arm == "no-project":
            write_doc(lib(app) / "a.json", ENTRY_C)
            write_doc(lib(app) / "b.json", ENTRY_C)
            await show_patch_editor(pilot, app)
            assert option_values(patch_select(app)) == ["a.json", "b.json"]
        elif arm == "project-load":
            write_doc(lib(app) / "w.json", ENTRY_C)
            project = make_project(app.workarea)
            write_doc(project / "patches" / "a.json", ENTRY_C)
            await load_image_fixture(pilot, app, app.base_dir)
            await show_patch_editor(pilot, app)
            assert option_values(patch_select(app)) == ["w.json"]
            await open_project_by_dialog(pilot, app)
            assert patch_select(app).region.width > 0, "the Patch Editor stayed displayed"
            assert option_values(patch_select(app)) == ["patches/a.json", "library/w.json"]
        else:
            write_doc(lib(app) / "w.json", ENTRY_C)
            await load_image_fixture(pilot, app, app.base_dir)
            await show_patch_editor(pilot, app)
            assert option_values(patch_select(app)) == ["w.json"]
            await save_project_by_dialog(pilot, app, log, "new")
            assert patch_select(app).region.width > 0, "the Patch Editor stayed displayed"
            assert option_values(patch_select(app)) == ["library/w.json"]
        return True

    assert run(tmp_path, scenario) is True


# ===========================================================================
# R-PATCH-DOC-DROPDOWN-001.2 - the empty list
# ===========================================================================


@pytest.mark.parametrize("arm", ["all-empty", "library-only"])
def test_r_patch_doc_dropdown_001_2_empty(tmp_path: Path, arm: str) -> None:
    """Cases R-PATCH-DOC-DROPDOWN-001.2/1 and /2: with every folder empty the
    dropdown paints its prompt ``Change files in patches/`` and holds no
    option; with only a library file it holds exactly the one option
    ``library/w.json`` (revised D-3).

    Negative control: emptiness decided on the project folders alone -> the
    library-only arm shows no option -> RED."""

    async def scenario(app, pilot, log):
        make_project(app.workarea)
        (app.workarea / "proj" / "patches").mkdir()
        (app.workarea / "proj" / "checks").mkdir()
        lib(app).mkdir(parents=True, exist_ok=True)
        if arm == "library-only":
            write_doc(lib(app) / "w.json", ENTRY_C)
        await open_project_shipped(pilot, app)
        await show_patch_editor(pilot, app)
        select = patch_select(app)
        if arm == "all-empty":
            assert option_values(select) == []
            painted = " ".join(painted_rows(app, select))
            assert "Change files in patches/" in painted, painted
        else:
            assert option_values(select) == ["library/w.json"]
        return True

    assert run(tmp_path, scenario) is True


# ===========================================================================
# R-PATCH-DOC-DROPDOWN-001.3 - a pick loads the file
# ===========================================================================


@pytest.mark.parametrize("arm", ["project", "library"])
def test_r_patch_doc_dropdown_001_3_pick(tmp_path: Path, arm: str) -> None:
    """Cases R-PATCH-DOC-DROPDOWN-001.3/1 and /3: a pick of a project file
    loads that file, the document source spelled from the app's work area (not
    resolved, S-4), status ``Loaded check: 2 entries, 0 error(s)``; a pick of
    ``library/w.json`` in a project loads ``workarea/patches/w.json``, status
    ``Loaded change: 1 entry, 0 error(s)``, ribbon name segment exactly
    ``w.json`` (not the listed ``library/w.json``; E5 C-4).

    Negative control: the pick resolved under ``workarea/patches/`` ->
    ``checks/k.chk.json`` is refused -> RED; the resolved path returned as the
    source -> /1 fails its equality when the work area is reached through a
    link (see ``..._pick_keeps_spelling``)."""

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        write_doc(project / "checks" / "k.chk.json", ENTRIES_K, kind="check")
        write_doc(lib(app) / "w.json", ENTRY_C)
        await open_project_shipped(pilot, app)
        await show_patch_editor(pilot, app)
        mark = len(log.messages)
        if arm == "project":
            await pick(pilot, app, "#patch_doc_file_select", "checks/k.chk.json")
            lines = await wait_line(
                pilot, log, mark, lambda line: line.startswith("Loaded "), "the load status"
            )
            assert "Loaded check: 2 entries, 0 error(s)" in lines, lines
            assert source_of(app) == app.workarea / "proj" / "checks" / "k.chk.json"
        else:
            await pick(pilot, app, "#patch_doc_file_select", "library/w.json")
            lines = await wait_line(
                pilot, log, mark, lambda line: line.startswith("Loaded "), "the load status"
            )
            assert "Loaded change: 1 entry, 0 error(s)" in lines, lines
            assert source_of(app) == lib(app) / "w.json"
            ribbon = str(app.query_one("#patch_identity_ribbon").render())
            assert ribbon.split(" · ")[0] == "w.json", ribbon
        return True

    assert run(tmp_path, scenario) is True


def test_r_patch_doc_dropdown_001_3_save_after_library_pick(tmp_path: Path) -> None:
    """E3A-18 / revised D-3 (R-PATCH-DOC-DROPDOWN-001.3, the Save arm): after a
    pick of ``library/w.json`` in a project, the Patch Editor Save claims a
    free name in the PROJECT's ``patches/`` and leaves the library file as it
    was. A file already named ``changes.json`` in ``proj/patches/`` is not
    overwritten (the free-name claim): its bytes are unchanged and a new file
    appears beside it.

    Negative control: Save writing to the library, or over the existing
    ``changes.json`` -> the library listing changes or the old bytes change
    -> RED."""

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        write_doc(project / "patches" / "changes.json", [projects.address_entry(0x8009, b"\x77")])
        write_doc(lib(app) / "w.json", ENTRY_C)
        await open_project_shipped(pilot, app)
        await show_patch_editor(pilot, app)
        library_before = files_under(lib(app))
        project_before = files_under(project / "patches")
        mark = len(log.messages)
        await pick(pilot, app, "#patch_doc_file_select", "library/w.json")
        await wait_line(
            pilot, log, mark, lambda line: line.startswith("Loaded "), "the load status"
        )
        mark = len(log.messages)
        app.query_one("#patch_doc_save_button", Button).press()
        await wait_line(
            pilot, log, mark, lambda line: line.startswith("Saved change-set to "),
            "the Save status",
        )
        project_after = files_under(project / "patches")
        assert files_under(lib(app)) == library_before, "Save touched the library"
        assert project_after["changes.json"] == project_before["changes.json"], "Save overwrote"
        assert len(project_after) == len(project_before) + 1, sorted(project_after)
        return True

    assert run(tmp_path, scenario) is True


def test_r_patch_doc_dropdown_001_3_pick_keeps_spelling(tmp_path: Path) -> None:
    """Case R-PATCH-DOC-DROPDOWN-001.3/4 (S-4): the app's base folder is named
    through a link ``alias -> real`` above ``.s19tool``, so the given and the
    resolved spellings differ. A pick of ``patches/a.json`` keeps the work
    area's spelling as the document source, so Save project classes the file
    in the project and, with an entry added, a Save project through ``ctrl+s``
    and its dialog (E5 C-3) says
    ``Change document a.json has unsaved edits - the project records the file
    as it is on disk; save it from the Patch Editor to keep them``.

    Negative control: the resolved path returned as the source -> the file is
    classed outside the project and the line is missing -> RED."""
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    make_link(alias, real)

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        write_doc(project / "patches" / "a.json", ENTRY_C)
        await open_project_shipped(pilot, app)
        await show_patch_editor(pilot, app)
        mark = len(log.messages)
        await pick(pilot, app, "#patch_doc_file_select", "patches/a.json")
        await wait_line(
            pilot, log, mark, lambda line: line.startswith("Loaded "), "the load status"
        )
        assert str(source_of(app)).startswith(str(alias)), (
            f"the source must keep the work area's spelling, got {source_of(app)}"
        )
        await add_patch_entry(pilot, app, "0x8007", "CC")
        mark = len(log.messages)
        await save_project_by_dialog(pilot, app, log, "proj")
        lines = log.since(mark)
        expected = (
            "Change document a.json has unsaved edits — the project records "
            "the file as it is on disk; save it from the Patch Editor to keep them"
        )
        assert expected in lines, lines
        return True

    assert run(tmp_path, scenario, base=alias) is True


# ===========================================================================
# R-PATCH-DOC-DROPDOWN-001.4 - the pick guard
# ===========================================================================

REFUSED_PATCH = "Patch Editor: change file {name!r} is outside the patches folder — not loaded."


async def post_change_pick(pilot, app, log, name: str) -> list:
    panel = patch_panel(app)
    mark = len(log.messages)
    panel.post_message(PatchEditorPanel.ChangeFileSelected(name))
    await wait_until(
        pilot,
        lambda: len(log.since(mark)) > 0,
        lambda: f"no status line followed the pick of {name!r}",
        timeout=20.0,
        pause_first=True,
    )
    await pilot.pause()
    return log.since(mark)


@pytest.mark.parametrize(
    "arm", ["link", "linked-folder", "unknown-folder", "inside-link", "popup-recheck"]
)
def test_r_patch_doc_dropdown_001_4_refused(tmp_path: Path, arm: str) -> None:
    """Cases R-PATCH-DOC-DROPDOWN-001.4/1 .. /5: a pick that is a link, lies
    under a linked folder (also one that stays inside the project, S-3), has no
    known folder, a ``..`` or is ``.`` (the folder itself, E5 C-7), or whose folder became a link while the
    unsaved-changes popup was open (S-5), is refused with the status
    ``Patch Editor: change file '<name>' is outside the patches folder — not
    loaded.`` and the document is unchanged.

    Negative control: a guard that resolves and compares instead of walking
    the links -> the inside-project link arm loads -> RED; no re-check after
    the popup -> the popup arm loads through the link -> RED."""
    if arm == "link":
        # the file link is made inside the scenario; skip early on a platform
        # that cannot make one
        probe = tmp_path / "probe"
        probe.write_text("x", encoding="utf-8")
        make_link(tmp_path / "probe-link", probe)

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        outside = tmp_path / "outside"
        write_doc(lib(app) / "a.json", ENTRY_C)
        write_doc(lib(app) / "w.json", ENTRY_C)
        if arm == "link":
            (project / "patches").mkdir()
        elif arm == "linked-folder":
            write_doc(outside / "x.json", ENTRY_C)
        elif arm == "inside-link":
            write_doc(project / "patches" / "x.json", ENTRY_C)
        elif arm == "popup-recheck":
            write_doc(project / "patches" / "a.json", ENTRY_C)
        await open_project_shipped(pilot, app)
        await show_patch_editor(pilot, app)
        if arm == "link":
            make_link(project / "patches" / "l.json", lib(app) / "a.json")
            names = ["patches/l.json"]
        elif arm == "linked-folder":
            make_link(project / "patches", outside)
            names = ["patches/x.json"]
        elif arm == "unknown-folder":
            names = ["w.json", "patches/../../w.json", "patches/."]
        elif arm == "inside-link":
            make_link(project / "checks", project / "patches")
            names = ["checks/x.json"]
        else:
            names = []
        if arm != "popup-recheck":
            before = doc_snapshot(app)
            for name in names:
                lines = await post_change_pick(pilot, app, log, name)
                assert REFUSED_PATCH.format(name=name) in lines, lines
                assert doc_snapshot(app) == before, "a refused pick changed the document"
            return True
        # popup-recheck: dirty document, pick, swap the folder, accept.
        await add_patch_entry(pilot, app, "0x8007", "CC")
        before = doc_snapshot(app)
        write_doc(outside / "a.json", [projects.address_entry(0x800A, b"\x55")])
        await pick(pilot, app, "#patch_doc_file_select", "patches/a.json")
        from s19_app.tui.screens_directionb import LoadGuardScreen

        await settled(
            pilot, lambda: isinstance(app.screen, LoadGuardScreen), "the unsaved-changes popup"
        )
        shutil.rmtree(project / "patches")
        make_link(project / "patches", outside)
        mark = len(log.messages)
        assert await pilot.click("#load_guard_accept"), "click missed the popup's accept"
        await wait_until(
            pilot,
            lambda: len(log.since(mark)) > 0 and not isinstance(app.screen, LoadGuardScreen),
            lambda: f"no status line after the accept; lines: {log.since(mark)!r}",
            pause_first=True,
        )
        lines = log.since(mark)
        assert REFUSED_PATCH.format(name="patches/a.json") in lines, lines
        assert doc_snapshot(app) == before, "the accept loaded through the link"
        return True

    assert run(tmp_path, scenario) is True


# ===========================================================================
# R-CHKED-031 / -034 - where Write puts the spec
# ===========================================================================


@pytest.mark.parametrize(
    "arm", ["project", "no-project", "after-library-pick", "never-overwrites"]
)
def test_r_chked_031_write_home(tmp_path: Path, arm: str) -> None:
    """Cases R-CHKED-031/1 .. /3, plus the free-name claim of revised D-3.

    /1: Write as ``s1.chk.json`` in a project -> ``proj/checks/s1.chk.json``
    and no ``workarea/patches/s1.chk.json``. /2: with no project -> the common
    folder. /3: after a pick of ``library/w.chk.json``, Write (Write as
    ``w.chk.json``) -> ``proj/checks/w.chk.json``; ``workarea/patches/`` holds
    only ``w.chk.json``, unchanged; the status names the project copy,
    ``Check Editor: wrote checks/w.chk.json (1 fields, kind=check).``
    (R-CHKED-032/3, E5 C-9). never-overwrites: a ``checks/s1.chk.json``
    that already exists keeps its bytes and the new spec takes another name.

    Negative control: Write without the check home -> the file lands in
    ``workarea/patches/`` -> RED."""

    async def scenario(app, pilot, log):
        if arm == "no-project":
            await load_image_fixture(pilot, app, app.base_dir)
        else:
            project = make_project(app.workarea)
            if arm == "after-library-pick":
                write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
            if arm == "never-overwrites":
                write_doc(project / "checks" / "s1.chk.json", ENTRY_W, kind="check")
            await open_project_shipped(pilot, app)
        await show_check_editor(pilot, app)
        if arm == "after-library-pick":
            library_before = files_under(lib(app))
            mark = len(log.messages)
            await pick(pilot, app, "#check_spec_file_select", "library/w.chk.json")
            await wait_line(
                pilot, log, mark, lambda line: line.startswith("Check Editor: loaded "),
                "the spec pick status",
            )
            lines = await write_spec(pilot, app, log, "w.chk.json")
            assert "Check Editor: wrote checks/w.chk.json (1 fields, kind=check)." in lines, lines
            assert (app.workarea / "proj" / "checks" / "w.chk.json").is_file()
            assert files_under(lib(app)) == library_before, "Write touched the library"
            return True
        await add_check_row(pilot, app)
        before = files_under(app.workarea / "proj" / "checks") if arm == "never-overwrites" else {}
        lines = await write_spec(pilot, app, log, "s1.chk.json")
        assert any(line.startswith("Check Editor: wrote ") for line in lines), lines
        if arm == "project":
            assert (app.workarea / "proj" / "checks" / "s1.chk.json").is_file()
            assert not (lib(app) / "s1.chk.json").exists()
        elif arm == "no-project":
            assert (lib(app) / "s1.chk.json").is_file()
        else:
            after = files_under(app.workarea / "proj" / "checks")
            assert after["s1.chk.json"] == before["s1.chk.json"], "Write overwrote the spec"
            assert len(after) == len(before) + 1, sorted(after)
            assert not (lib(app) / "s1.chk.json").exists()
        return True

    assert run(tmp_path, scenario) is True


@pytest.mark.parametrize("arm", ["project", "no-project", "collision"])
def test_r_chked_032_write_status_names_the_home(tmp_path: Path, arm: str) -> None:
    """Cases R-CHKED-032/1, /2 and /4 (E5 C-9 = SEC E5-2): the Write status
    names the written file as the Spec list lists it. /1: in a project, Write
    as ``s1.chk.json`` -> exactly ``Check Editor: wrote checks/s1.chk.json (1
    fields, kind=check).``. /2: with no project the bare name, as before. /4:
    with ``proj/checks/s1.chk.json`` already present the status names the
    claimed free name under ``checks/``. (/3, after a library pick, is
    ``test_r_chked_031_write_home[after-library-pick]``.)

    Negative control (M44): the status built from the bare file name -> /1
    reads ``wrote s1.chk.json`` and /4 the bare claimed name -> RED."""

    async def scenario(app, pilot, log):
        if arm == "no-project":
            await load_image_fixture(pilot, app, app.base_dir)
            home = lib(app)
        else:
            project = make_project(app.workarea)
            home = project / "checks"
            if arm == "collision":
                write_doc(home / "s1.chk.json", ENTRY_W, kind="check")
            await open_project_shipped(pilot, app)
        await show_check_editor(pilot, app)
        await add_check_row(pilot, app)
        before = files_under(home) if home.is_dir() else {}
        lines = await write_spec(pilot, app, log, "s1.chk.json")
        written = [line for line in lines if line.startswith("Check Editor: wrote ")]
        if arm == "project":
            assert written == ["Check Editor: wrote checks/s1.chk.json (1 fields, kind=check)."], lines
        elif arm == "no-project":
            assert written == ["Check Editor: wrote s1.chk.json (1 fields, kind=check)."], lines
        else:
            after = files_under(home)
            assert after["s1.chk.json"] == before["s1.chk.json"], "Write overwrote the spec"
            claimed = sorted(set(after) - set(before))
            assert len(claimed) == 1, sorted(after)
            assert written == [f"Check Editor: wrote checks/{claimed[0]} (1 fields, kind=check)."], lines
        return True

    assert run(tmp_path, scenario) is True


def test_r_chked_034_linked_check_home(tmp_path: Path) -> None:
    """Case R-CHKED-034/1: with ``proj/checks`` a linked folder, Write writes
    nothing: status ``Check Editor: spec NOT written.``, the Fields status
    starts ``Write refused: MF-WRITE-CONTAINMENT``, the link target holds no
    new file.

    Negative control: a destination that is not containment-checked -> the
    spec is written through the link (or into the common folder) -> RED."""
    outside = tmp_path / "outside"
    outside.mkdir()

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        await open_project_shipped(pilot, app)
        await show_check_editor(pilot, app)
        make_link(project / "checks", outside)
        await add_check_row(pilot, app)
        lines = await write_spec(pilot, app, log, "s1.chk.json")
        assert "Check Editor: spec NOT written." in lines, lines
        await settled(
            pilot,
            lambda: check_status(app).startswith("Write refused: MF-WRITE-CONTAINMENT"),
            "the Fields status line of the refused Write",
        )
        assert sorted(outside.iterdir()) == [], "a file was written through the link"
        return True

    assert run(tmp_path, scenario) is True


# ===========================================================================
# R-CHKED-040 / -042 / -044 - the Spec list
# ===========================================================================


@pytest.mark.parametrize(
    "arm", ["project", "after-write", "save-project", "project-load"]
)
def test_r_chked_040_spec_list(tmp_path: Path, arm: str) -> None:
    """Cases R-CHKED-040/1 .. /3 and the project-load trigger of E3A-18.

    /1: in a project the Spec dropdown lists ``checks/k.chk.json`` then
    ``library/w.chk.json``, both labelled `` CHECK``. /2: after a Write as
    ``s1.chk.json`` it lists ``checks/k.chk.json``, ``checks/s1.chk.json``,
    ``library/w.chk.json``. /3: after a Save project that creates the project,
    with the Check Editor displayed: ``library/w.chk.json``. project-load: after
    a project load with the Check Editor displayed: ``checks/k.chk.json``,
    ``library/w.chk.json``.

    Negative control: the common-folder scan -> the project arms list
    ``w.chk.json`` bare -> RED; no refill after a Save project or a project
    load -> RED."""

    async def scenario(app, pilot, log):
        write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
        project = make_project(app.workarea)
        write_doc(project / "checks" / "k.chk.json", ENTRIES_K, kind="check")
        if arm in ("project", "after-write"):
            await open_project_shipped(pilot, app)
            await show_check_editor(pilot, app)
            if arm == "project":
                select = spec_select(app)
                assert option_values(select) == ["checks/k.chk.json", "library/w.chk.json"]
                assert all(label.endswith(" CHECK") for label in option_labels(select)), (
                    option_labels(select)
                )
            else:
                await add_check_row(pilot, app)
                lines = await write_spec(pilot, app, log, "s1.chk.json")
                assert any(line.startswith("Check Editor: wrote checks/s1.chk.json") for line in lines), lines
                assert option_values(spec_select(app)) == [
                    "checks/k.chk.json",
                    "checks/s1.chk.json",
                    "library/w.chk.json",
                ]
        else:
            await load_image_fixture(pilot, app, app.base_dir)
            await show_check_editor(pilot, app)
            assert option_values(spec_select(app)) == ["w.chk.json"]
            if arm == "save-project":
                await save_project_by_dialog(pilot, app, log, "new")
                expected = ["library/w.chk.json"]
            else:
                await open_project_by_dialog(pilot, app)
                expected = ["checks/k.chk.json", "library/w.chk.json"]
            assert spec_select(app).region.width > 0, "the Check Editor stayed displayed"
            assert option_values(spec_select(app)) == expected
        return True

    assert run(tmp_path, scenario) is True


def test_r_chked_042_write_as_bare_name(tmp_path: Path) -> None:
    """Case R-CHKED-042/1 (revised D-3): a pick of ``library/w.chk.json`` in a
    project sets the Write as input to the bare file name ``w.chk.json`` (no
    folder part); the status is ``Check Editor: loaded 'library/w.chk.json'
    (1 fields).``

    Negative control: the listed value passed on as the name -> the input
    reads ``library/w.chk.json`` -> RED."""

    async def scenario(app, pilot, log):
        make_project(app.workarea)
        write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
        await open_project_shipped(pilot, app)
        await show_check_editor(pilot, app)
        mark = len(log.messages)
        await pick(pilot, app, "#check_spec_file_select", "library/w.chk.json")
        lines = await wait_line(
            pilot, log, mark, lambda line: line.startswith("Check Editor: "),
            "the spec pick status",
        )
        assert "Check Editor: loaded 'library/w.chk.json' (1 fields)." in lines, lines
        assert app.query_one("#check_file_name_input", Input).value == "w.chk.json"
        return True

    assert run(tmp_path, scenario) is True


@pytest.mark.parametrize("arm", ["link", "linked-folder"])
def test_r_chked_044_refused(tmp_path: Path, arm: str) -> None:
    """Cases R-CHKED-044/1 and /2: a pick that is a link, or lies under a
    linked check home, is refused with ``Check Editor: file '<name>' is outside
    the patches folder — not loaded.`` and the collector is unchanged.

    Negative control: as R-PATCH-DOC-DROPDOWN-001.4 -> the file is read
    through the link (or reported missing) instead of refused -> RED."""
    outside = tmp_path / "outside"
    if arm == "link":
        make_link(tmp_path / "probe-link", write_doc(tmp_path / "probe.json", ENTRY_W, kind="check"))

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
        if arm == "link":
            (project / "checks").mkdir()
            name = "checks/l.chk.json"
        else:
            write_doc(outside / "x.chk.json", ENTRY_W, kind="check")
            name = "checks/x.chk.json"
        await open_project_shipped(pilot, app)
        await show_check_editor(pilot, app)
        if arm == "link":
            make_link(project / "checks" / "l.chk.json", lib(app) / "w.chk.json")
        else:
            make_link(project / "checks", outside)
        table = app.query_one("#check_mem_table", DataTable)
        rows_before = table.row_count
        mark = len(log.messages)
        app.query_one("#check_editor_panel", CheckEditorPanel).post_message(
            CheckEditorPanel.SpecFileSelected(name)
        )
        await wait_until(
            pilot,
            lambda: len(log.since(mark)) > 0,
            lambda: f"no status line followed the pick of {name!r}",
            timeout=20.0,
            pause_first=True,
        )
        await pilot.pause()
        expected = (
            f"Check Editor: file {name!r} is outside the patches folder — not loaded."
        )
        assert expected in log.since(mark), log.since(mark)
        assert table.row_count == rows_before, "a refused pick changed the collector"
        return True

    assert run(tmp_path, scenario) is True


# ===========================================================================
# R-DIFF-CHK - the A2B Diff check-spec list
# ===========================================================================


@pytest.mark.parametrize("arm", ["project", "project-load", "save-project"])
def test_r_diff_chk_1_list(tmp_path: Path, arm: str) -> None:
    """Cases R-DIFF-CHK.1/1, /3 and the Save project trigger of E3A-18: the
    option values after ``(no check spec)`` equal the spec list exactly.

    /1 (key ``7`` in a project): ``checks/k.chk.json``, ``library/w.chk.json``.
    /3 (a project load while the A2B Diff stays displayed): the same, where the
    base kept ``w.chk.json``. save-project (a Save project that creates the
    project, A2B Diff displayed): ``library/w.chk.json``. (/2, the no-project
    list, is the existing ``test_tc_b94_15_dropdown_population``.)

    Negative control: the common-folder scan -> the project arms list bare
    names -> RED; no refill after the project install or the Save project ->
    RED."""

    async def scenario(app, pilot, log):
        write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
        project = make_project(app.workarea)
        write_doc(project / "checks" / "k.chk.json", ENTRIES_K, kind="check")
        if arm == "project":
            await open_project_shipped(pilot, app)
            await show_diff(pilot, app)
            assert option_values(diff_select(app)) == [
                "checks/k.chk.json",
                "library/w.chk.json",
            ]
        else:
            await load_image_fixture(pilot, app, app.base_dir)
            await show_diff(pilot, app)
            assert option_values(diff_select(app)) == ["w.chk.json"]
            if arm == "project-load":
                await open_project_by_dialog(pilot, app)
                expected = ["checks/k.chk.json", "library/w.chk.json"]
            else:
                await save_project_by_dialog(pilot, app, log, "new")
                expected = ["library/w.chk.json"]
            assert app.query_one("#ab_diff_panel").region.width > 0, "the A2B Diff stayed displayed"
            assert option_values(diff_select(app)) == expected
        return True

    assert run(tmp_path, scenario) is True


def test_r_diff_chk_3_no_row_for_empty_list(tmp_path: Path) -> None:
    """Case R-DIFF-CHK.3/1 (revised D-3): with the common library empty and a
    project whose ``checks/`` is empty, the A2B Diff paints no ``Check spec:``
    row. (On the base revision this holds as well: it is a standing guard of
    the row's absence.)

    Negative control: the row composed for an empty list -> ``Check spec:`` is
    painted -> RED."""

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        (project / "checks").mkdir()
        await load_image_fixture(pilot, app, app.base_dir)
        await open_project_by_dialog(pilot, app)
        await show_diff(pilot, app, expect_row=False)
        painted = "\n".join(painted_rows(app, app.query_one("#ab_diff_panel", AbDiffPanel)))
        assert painted.strip(), "the A2B Diff painted nothing"
        assert "Check spec:" not in painted, painted
        return True

    assert run(tmp_path, scenario) is True


@pytest.mark.parametrize("arm", ["link", "linked-folder"])
def test_r_diff_chk_5_refused(tmp_path: Path, arm: str) -> None:
    """Cases R-DIFF-CHK.5/1 and /2: a pick that is a link, or lies under a
    linked check home, is refused: ``#diff_status`` reads ``Check spec:
    '<name>' is outside the patches folder — not loaded.``

    Negative control: a guard rooted at the common folder -> the pick is
    treated as a file of the library (and fails another way) -> RED."""
    outside = tmp_path / "outside"
    if arm == "link":
        make_link(tmp_path / "probe-link", write_doc(tmp_path / "probe.json", ENTRY_W, kind="check"))

    async def scenario(app, pilot, log):
        project = make_project(app.workarea)
        write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
        if arm == "link":
            (project / "checks").mkdir()
            name = "checks/l.chk.json"
        else:
            write_doc(outside / "x.chk.json", ENTRY_W, kind="check")
            name = "checks/x.chk.json"
        await open_project_shipped(pilot, app)
        await show_diff(pilot, app)
        if arm == "link":
            make_link(project / "checks" / "l.chk.json", lib(app) / "w.chk.json")
        else:
            make_link(project / "checks", outside)
        before = diff_status(app)
        app.query_one("#ab_diff_panel", AbDiffPanel).post_message(
            AbDiffPanel.CheckFileSelected(name)
        )
        expected = f"Check spec: {name!r} is outside the patches folder — not loaded."
        await wait_until(
            pilot,
            lambda: diff_status(app) != before,
            lambda: f"#diff_status stayed {diff_status(app)!r} after the pick of {name!r}",
            timeout=20.0,
            pause_first=True,
        )
        assert diff_status(app) == expected, diff_status(app)
        return True

    assert run(tmp_path, scenario) is True


def test_r_diff_chk_8_library_spec_loads(tmp_path: Path) -> None:
    """Case R-DIFF-CHK.8/1 (revised D-3): in a project, a pick of
    ``library/w.chk.json`` in the A2B Diff loads the library file: ``#diff_status``
    reads ``Check spec 'library/w.chk.json' loaded — 1 declared field(s) will
    ride the report.``

    Negative control: the listed value resolved under the project -> the pick is
    refused -> RED."""

    async def scenario(app, pilot, log):
        make_project(app.workarea)
        write_doc(lib(app) / "w.chk.json", ENTRY_W, kind="check")
        await open_project_shipped(pilot, app)
        await show_diff(pilot, app)
        await pick(pilot, app, "#diff_check_select", "library/w.chk.json")
        expected = (
            "Check spec 'library/w.chk.json' loaded — 1 declared field(s) "
            "will ride the report."
        )
        await wait_until(
            pilot,
            lambda: diff_status(app).startswith("Check spec"),
            lambda: f"#diff_status read {diff_status(app)!r}",
            pause_first=True,
        )
        await settled(pilot, lambda: diff_status(app) == expected, "the loaded status")
        return True

    assert run(tmp_path, scenario) is True
