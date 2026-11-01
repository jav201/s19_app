"""Batch-100 increment 11 — the Save project dialog shows exactly what the
save will do (HLR-175, HLR-175a … HLR-175f; prepare + commit split; the F5
document-row fix).

Written by the independent tester (E4) from the approved design only:
``inc-11/E1-requirements-draft.md`` (thresholds and negative controls),
``inc-11/E1-scope.md`` (test notes), the fixed interfaces of
``inc-11/codewire/interfaces-11.md``, the example lines of
``codewire/proto-11-dialog.md`` (S1-… / C1-…) and ``codewire/proto-11-app.md``
(B11-…), and the rulings ``E1-rulings.md``, ``E2-rulings.md`` and
``E3-rulings.md`` (the round-3 rows marked T bind these tests). No line of
the Inc 11 implementation was read.

Covers:
  - TC-B100-47 — LLR-175.1, .1a … .1m, .1o, .1p, LLR-175.6 (the target line,
    the refusals painted in the dialog before Save, the one preparation).
  - TC-B100-48 — LLR-175.2, .2a (no parent field; the payload's parent is
    this work area).
  - TC-B100-49 — LLR-175.3, .3a … .3j (keys, focus, empty Save, Save during
    a refusal, the priority keys and the whole-stack guard, the prefill,
    the labels, nothing loaded).
  - TC-B100-65 — LLR-175.4, .4a … .4l, LLR-175.5, .5a, .5b (rows = plan,
    executed = painted, the out-of-date summary, the image / pending / links
    / merge rows, literal names, layout, the read-only plan, a direct
    payload, the once-per-open cost, the 150 ms recompute, the first frame).
  - TC-B100-66 — LLR-173.7 extended (the Save dialog paints no decision id).
  - AT-B100-16 — HLR-175, HLR-175b, HLR-175c, HLR-175d, HLR-175f (one chain:
    open, folder, clash, empty, escape), black-box.
  - AT-B100-21 — HLR-175 (painted half) and HLR-175a (executed half), the 7
    scenarios, black-box.
  - The E3 arms: S11-01, S11-02 … S11-05, A11-01, A11-02, A11-04, A11-05,
    A11-08, R2-01, R2-02 / R3-01, and the whole-stack guard over
    ``SaveProjectScreen``.

Base: every Inc 11 symbol (``SavePreview``, the keyword constructor, the
dialog's ``plan``, the app's ``_prepare_project_save`` family) is imported
or reached inside its test, so the file collects on the base revision and
each test fails there on its own: an assertion (the base dialog paints no
``#save_where`` / ``#save_summary``, ignores ``escape`` and ``alt+s``, opens
with nothing loaded, and refuses only after it closes), or the
``ImportError`` / ``AttributeError`` / ``TypeError`` of a symbol or a
signature the Inc 11 design adds.

Oracles are observable: the screen stack, the focused widget id, the painted
text of ``#save_where`` and the ``#save_summary`` rows, the value a dialog
hands its callback, the dialog's ``plan`` (the declared exception of the
§3 preface), the work-area tree on disk, the session digest and the status
log. Spies on the app's seams count calls only where a requirement states a
count (LLR-175.5, .5a, .5b, A11-01, R3-01).

Platform: the junction arms, the ``strasse`` / ``straße`` arm and the
case-insensitive ``ab`` / ``Ab`` arm are Windows only (reported not run
elsewhere, never passed). ``LongPathsEnabled`` is 0 on the development host,
so the 130-character file-name arm of LLR-175.4j (P-6) cannot be built
under the test's temp root: the clip of a long row is checked with a
90-character name instead (declared in the tester notes).
"""
from __future__ import annotations

import ast
import asyncio
import dataclasses
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

import pytest
from textual import events

import s19_app.tui.app as app_module
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests.support import b100_load_dialog as ld
from tests.support import b100_projects as projects
from tests.support import b100_save_dialog as sd
from tests.support.b100_workers import settle_workers

ROOT = Path(__file__).resolve().parents[1]
CASE01_DIR = ROOT / "examples" / "case_01_basic_valid"
CASE02_DIR = ROOT / "examples" / "case_02_gaps_and_patch_targets"
CASE06_DIR = ROOT / "examples" / "case_06_large_nested_a2l"
WIN = sys.platform == "win32"
SIZE = (118, 54)
SIZES = [(118, 54), (220, 60)]
DASH = "—"
DECISION_ID = re.compile(r"\bD\d+\b|\bO-\d+|VS-|LLR-|HLR-")
PREFIX = "Project NOT saved: "

WINDOWS_ARM = pytest.mark.skipif(
    not WIN, reason="Windows-only test arm (junction / case-insensitive volume); not run here"
)

#: The §3 token pairs the dialog paints (reason token, next-step token).
RESERVED = ("reserved name", "choose another name")
DEVICE = ("device name", "choose another name")
CLASH = ("already a project", "choose another name")
TOO_LONG = ("name too long", "shorten the name")
PATH_LONG = ("path too long", "shorten the name")
LINK = ("link or junction", "choose another name")
FOLDER_UNREADABLE = ("could not be read", "check that the folder can be opened, then save again")
EMPTY = ("name is empty", "type a project name")
SECOND_MAC = ("already has a MAC file", "choose another name")
SECOND_A2L = ("already has an A2L file", "choose another name")
TOO_MANY = ("too many files to copy", "move files out of the project, then save again")
NO_SPACE = ("not enough free space", "free disk space or remove files from the project")
MISSING = ("source file missing", "reload it or remove it from the project")
FILE_UNREADABLE = ("could not be read", "check that the file can be opened, then save again")
BLOCKED = ("blocked entr", "fix them in the Patch Editor")
CHANGED = sd.SUMMARY_CHANGED
NOTHING = ("Nothing to save", "load a data file or A2L first")
KINDS = (
    "new folder",
    "updates the open project",
    "merges into an existing project",
    "new project in an existing folder",
)


# ---------------------------------------------------------------------------
# fixtures, drivers and readers (stdlib + the shared support modules)
# ---------------------------------------------------------------------------


def _wa(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _settle(pilot, n: int = 6) -> None:
    await sd.settle(pilot, n)


def _run(base: Path, scenario, size: tuple = SIZE, notifications: bool = False):
    return sd.run(base, scenario, size=size, notifications=notifications)


def _sources(tmp_path: Path, source_dir: Path = CASE01_DIR, *names: str, folder: str = "src") -> Path:
    """Scratch copies of example files (default: case_01's S19); returns
    the folder."""
    return projects.copy_sources(tmp_path / folder, source_dir, *(names or ("firmware.s19",)))


def _save_project_from(base: Path, name: str, sources: list) -> Path:
    """Save project ``name`` holding ``sources`` (S19/HEX, MAC, A2L paths)
    through the shipped Save project handler in an app of its own (LED .42:
    every ``project.json`` a test consumes comes from the real handler).
    Returns the project folder."""
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.screens import SaveProjectPayload

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            for path in sources:
                path = Path(path)
                if path.suffix.lower() == ".a2l":
                    app.load_a2l_from_path(path)
                    done = lambda: app.current_a2l_path is not None  # noqa: E731
                else:
                    app._load_path_from_user_input(path)
                    done = lambda p=path: app.current_file is not None and (  # noqa: E731
                        app.current_file.path.name == p.name
                        or (app.current_file.mac_path is not None and app.current_file.mac_path.name == p.name)
                    )
                for _ in range(400):
                    if done():
                        break
                    await pilot.pause()
                else:
                    raise AssertionError(f"the load of {path.name} did not land")
            app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name=name))
            for _ in range(400):
                if app.current_project is not None and app.current_project.casefold() == name.casefold():
                    break
                await pilot.pause()
            else:
                raise AssertionError(f"Save project {name} did not land")
            return app.workarea / app.current_project

    project = asyncio.run(_drive())
    # The fixture app's work copies stay in ``temp/``; a later load of a
    # same-named file with other bytes would land as ``firmware_1.s19`` and
    # change every row the scenario names, so the fixture removes them.
    shutil.rmtree(_wa(base) / "temp", ignore_errors=True)
    return project


async def _home(pilot) -> None:
    await pilot.press("1")
    await _settle(pilot, 4)


async def _load_by_keys(pilot, app, path: Path) -> None:
    """Load ``path`` through the Load dialog by keys (``l``, the path typed,
    a click on ``#load_ok``)."""
    path = Path(path)
    if path.suffix.lower() == ".a2l":
        until = lambda: app.current_a2l_path is not None and Path(app.current_a2l_path).name == path.name  # noqa: E731
    elif path.suffix.lower() == ".mac":
        until = lambda: app.current_file is not None and app.current_file.mac_path is not None  # noqa: E731
    else:
        until = lambda: app.current_file is not None and app.current_file.path.name == path.name  # noqa: E731
    await ld.load_path_through_dialog(pilot, app, path, until=until, what=f"the load of {path.name}")
    await _settle(pilot, 6)


async def _open_project_by_keys(pilot, app, name: str) -> None:
    """Open project ``name`` through the Load dialog by keys (rail ``1``,
    ``p``, the row highlighted, ``#load_ok``) and close the Load-result
    panel with its shown key ``esc``."""
    await _home(pilot)
    await ld.open_project_through_dialog(pilot, app, name)
    await projects.dismiss_load_result_panel(pilot, app)
    await sd.wait_for(
        pilot,
        lambda: app.current_project is not None and app.current_project.casefold() == name.casefold(),
        f"the project {name} to open",
    )
    await _settle(pilot, 6)


async def _open_project_direct(pilot, app, name: str) -> None:
    """Open project ``name`` through the shipped Load project handler (a TC
    fixture step, not the surface under test)."""
    app._handle_load_project(name)
    await sd.wait_for(
        pilot,
        lambda: app.current_project is not None and app.current_project.casefold() == name.casefold(),
        f"the project {name} to open",
    )
    await _settle(pilot, 6)
    if len(app.screen.query("#result_ok")):
        await pilot.press("escape")
        await _settle(pilot, 6)


async def _load_direct(pilot, app, path: Path, timeout: float = 6.0) -> None:
    """Load ``path`` through the shipped load handlers (a TC fixture step)."""
    path = Path(path)
    if path.suffix.lower() == ".a2l":
        app.load_a2l_from_path(path)
        await sd.wait_for(pilot, lambda: app.current_a2l_path is not None, f"the load of {path.name}", timeout)
    else:
        app._load_path_from_user_input(path)
        await sd.wait_for(
            pilot,
            lambda: app.current_file is not None
            and (app.current_file.path.name == path.name
                 or (app.current_file.mac_path is not None and app.current_file.mac_path.name == path.name)),
            f"the load of {path.name}",
            timeout,
        )
    await _settle(pilot, 6)


async def _add_entry_by_keys(pilot, app, address: str = "0x8000007C", run: str = "DE AD BE EF") -> None:
    """Add one Patch Editor entry through the panel's own inputs (rail key
    ``6``)."""
    await pilot.press("6")
    await sd.wait_for(pilot, lambda: len(app.query("#patch_entry_add_button")) > 0, "the Patch Editor panel")
    assert await pilot.click("#patch_entry_address_input")
    await pilot.press("end", *(["backspace"] * 40))
    await pilot.press(*address)
    assert await pilot.click("#patch_entry_bytes_input")
    await pilot.press("end", *(["backspace"] * 40))
    await pilot.press(*run)
    before = len(app._change_service.document.entries) if app._change_service.document else 0
    assert await pilot.click("#patch_entry_add_button")
    await sd.wait_for(
        pilot,
        lambda: app._change_service.document is not None
        and len(app._change_service.document.entries) == before + 1,
        "the entry to be added",
    )
    await _settle(pilot, 4)


def _painted_log(app) -> str:
    """The four painted log-strip lines, joined (oldest first)."""
    return "\n".join(str(app.screen_stack[0].query_one(f"#log_line_{i}").render()) for i in (1, 2, 3, 4))


async def _apply_by_keys(pilot, app) -> None:
    """Apply the Patch Editor document (``#patch_doc_apply_button``) and
    wait for the painted apply line; back to the Workspace (rail ``1``)."""
    assert await pilot.click("#patch_doc_apply_button"), "click missed #patch_doc_apply_button"
    await sd.wait_for(pilot, lambda: "Apply:" in _painted_log(app), "the painted apply line")
    await _settle(pilot, 4)
    await _home(pilot)


def _apply_direct(app) -> None:
    loaded = app.current_file
    app._change_service.apply(loaded.mem_map, loaded.ranges, loaded.mac_records, None)


def _add_direct(app, address: int = 0x8000007C, run=(0xDE, 0xAD, 0xBE, 0xEF)) -> None:
    app._change_service.add_entry(f"0x{address:08X}", "", " ".join(f"{b:02X}" for b in run))


def _blocked_document_text() -> str:
    """The TC-B100-57 / TC-B100-17 document: its second entry has a
    malformed address, so the one entry left (``0x8000007C``) is blocked."""
    return (
        '{"format": "s19app-changeset", "version": "2.0", "kind": "change",'
        ' "encoding": "utf-8", "value_mode": "text", "entries": ['
        '{"type": "bytes", "address": "0x8000007C", "bytes": "DE AD BE EF"},'
        '{"type": "bytes", "address": "0xZZ", "bytes": "01"}]}'
    )


def _capture_callback(app) -> list:
    """Record what the Save dialog hands its dismiss callback. The callback
    is read as ``app._handle_save_dialog`` at push time (S-b), so the
    wrapper must be installed before ``ctrl+s``; it still runs the shipped
    router."""
    seen: list = []
    original = app._handle_save_dialog

    def _wrapped(payload):
        seen.append(payload)
        return original(payload)

    app._handle_save_dialog = _wrapped
    return seen


def _spy_method(app, name: str) -> list:
    """Count the calls of an app method (an instance attribute wrapper)."""
    calls: list = []
    original = getattr(app, name)

    def _wrapped(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    setattr(app, name, _wrapped)
    return calls


def _stack(app) -> list:
    return [type(s).__name__ for s in app.screen_stack]


def _focused_id(app):
    return getattr(app.focused, "id", None)


def _density(app) -> tuple:
    body = app.screen_stack[0].query_one("#workspace_body")
    return tuple(sorted(c for c in body.classes if c.startswith("density")))


def _lines_with(messages: list, *tokens: str) -> list:
    return [m for m in messages if all(t in m for t in tokens)]


def _action_rows(rows: list) -> list:
    """The painted rows that carry an action word (file, folder and
    ``project.json`` rows)."""
    pattern = re.compile(r"\b(" + "|".join(sd.ACTION_WORDS) + r")\b")
    return [r for r in rows if pattern.search(r) and not r.startswith("links or junctions")]


def _row_matches(row: str, name: str, action: str) -> bool:
    """``row`` names ``name`` and, after it, the action word ``action``."""
    if name not in row:
        return False
    tail = row.split(name, 1)[1]
    return re.search(rf"\b{re.escape(action)}\b", tail) is not None


def _assert_rows_equal_plan(rows: list, plan) -> None:
    """LLR-175.4 / AT-B100-21 painted half: every file row, folder row and
    the ``project.json`` row of ``plan`` is painted exactly once by landing
    name and action word, and no other painted row carries an action word
    (0 differences)."""
    assert plan is not None, "no plan painted"
    action_rows = _action_rows(rows)
    expected = [(row.landing.name, row.action) for row in plan.rows]
    expected += [(f"{folder.name}/", "new") for folder in plan.folders]
    unmatched = list(action_rows)
    for name, action in expected:
        hits = [r for r in unmatched if _row_matches(r, name, action)]
        assert hits, f"plan row {(name, action)} not painted; rows {rows}"
        unmatched.remove(hits[0])
    assert unmatched == [], f"painted rows with no plan row: {unmatched}; plan {expected}"
    for folder in plan.folders:
        row = next(r for r in action_rows if f"{folder.name}/" in r)
        assert str(folder.file_count) in row, (row, folder)
    words = {m.group(1) for r in action_rows for m in [re.search(r"\b(new|keep|merge|rewrite|replace)\b", r.split(" ", 1)[-1])] if m}
    assert "replace" not in words and words <= set(sd.ACTION_WORDS), words


#: Gather homes copied outside the plan (A11-06): the active CRC template
#: and the batch / assignment documents, excluded from the executed-half
#: oracle by name.
_GATHER_HOMES = ("templates/", "checks/")


def _assert_tree_equals_plan(plan, before: dict, after: dict) -> None:
    """HLR-175a / LLR-175.4a / AT-B100-21 executed half: the files written
    under the plan's target equal the plan by full path and action."""
    target = Path(plan.target)
    root = target.resolve()

    def rel(path: Path) -> str:
        try:
            return Path(path).resolve().relative_to(root).as_posix().casefold()
        except ValueError:
            return Path(path).name.casefold()

    written = {k for k, v in after.items() if before.get(k) != v and not k.startswith(_GATHER_HOMES)}
    allowed = set()
    for row in plan.rows:
        key = rel(row.landing)
        if row.action == "new":
            assert key not in before and key in after, (row, sorted(after))
            allowed.add(key)
        elif row.action in ("rewrite", "merge"):
            assert key in before and key in after, (row, sorted(after))
            allowed.add(key)
        elif row.action == "keep":
            assert before.get(key) == after.get(key) is not None, row
        else:
            raise AssertionError(f"unexpected action {row}")
    for folder in plan.folders:
        landed = {k for k in written if k.startswith(f"{folder.name.casefold()}/")}
        assert len(landed) == folder.file_count, (folder, sorted(landed))
        allowed |= landed
    unplanned = written - allowed
    assert unplanned == set(), f"files written with no plan row: {sorted(unplanned)}"


# ---------------------------------------------------------------------------
# TC-B100-47 — LLR-175.1 … LLR-175.1p, LLR-175.6: the target line, the
# refusals painted in the dialog before Save, the one preparation
# ---------------------------------------------------------------------------


async def _type_and_wait(pilot, app, name: str, *tokens: str) -> str:
    """Type ``name`` (keys for plain ASCII, a value set otherwise) and wait
    for ``tokens`` in the painted dialog."""
    if name.isascii() and "[" not in name and "/" not in name and "." not in name:
        await sd.type_name(pilot, app, name)
    else:
        await sd.set_name(pilot, app, name)
    return await sd.wait_painted(pilot, app, *tokens)


def _where_line_for_text(text: str, name: str, kind: str) -> bool:
    """One line of ``text`` names folder ``name`` (as a whole word) and
    ``kind``."""
    return any(
        kind in line and re.search(rf"(^|[^\w]){re.escape(name)}([^\w]|$)", line)
        for line in text.split("\n")
    )


@pytest.mark.parametrize("typed,folder", [("a b", "ab"), ("../evil", "evil")])
def test_tc_b100_47_target_line_names_the_sanitised_folder_new(tmp_path: Path, typed: str, folder: str) -> None:
    """LLR-175.1, HLR-175 (F-fresh): ``a b`` → ``#save_where`` names ``ab``
    and ``new folder``; ``../evil`` → ``evil`` and ``new folder``; the line
    has 0 markup spans.

    Why: M-4 — the engineer must see the folder the save will really create
    before Save (the sanitiser drops the space and the path parts).
    Negative control: executed on the 9a tree (P11-2): ``typed 'a b' ->
    dialog text has 'ab' folder line? False`` → RED (base: no
    ``#save_where``)."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, typed, "new folder")
        return sd.where_text(app.screen), sd.spans(sd.where_widget(app.screen))

    text, spans = _run(base, scenario)
    assert _where_line_for_text(text, folder, "new folder"), text
    assert spans == 0, text


def test_tc_b100_47_target_line_open_project_kind(tmp_path: Path) -> None:
    """LLR-175.1 (F-open, ``P`` open): ``P`` → ``P`` and ``updates the open
    project``; the unsanitised ``P `` → ``P`` and the same kind (2 of 2).

    Why: saving into the open project rewrites it; the engineer must see
    that before Save. Negative control: base paints no target line (P11-2)
    → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        out = []
        for typed in ("P", "P "):
            await _type_and_wait(pilot, app, typed, "updates the open project")
            out.append(_where_line_for_text(sd.where_text(app.screen), "P", "updates the open project"))
        return out

    assert _run(base, scenario) == [True, True]


@WINDOWS_ARM
def test_tc_b100_47_target_line_open_project_in_another_case(tmp_path: Path) -> None:
    """LLR-175.1 boundary (LED .52(a), B11-26 / B11-45): ``Ab`` saved and
    open, ``ab`` typed → ``#save_where`` names ``Ab`` (the on-disk name) and
    ``updates the open project`` — never ``merges into an existing
    project``.

    Negative control: the kind computed with a case-sensitive comparison →
    ``merges into an existing project`` → RED. Windows arm (case-insensitive
    volume)."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "Ab", files=("firmware.s19",))

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "Ab")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "ab", "updates the open project")
        return sd.where_text(app.screen)

    text = _run(base, scenario)
    assert _where_line_for_text(text, "Ab", "updates the open project"), text
    assert "merges into an existing project" not in text, text


def test_tc_b100_47_target_line_merge_and_existing_folder_kinds(tmp_path: Path) -> None:
    """LLR-175.1 (F-merge, A11-17, R2-08): project ``ab`` saved and not open
    → ``ab`` → ``merges into an existing project``; an empty folder ``ef``
    and a folder ``nt`` holding only ``notes.txt`` → ``new project in an
    existing folder`` (3 of 3).

    Why: a merge adds a variant to a project the engineer may not mean to
    touch; a plain folder becomes a project. Negative control: the kind
    painted ``merges into an existing project`` for a folder that is not a
    project (the base word) → RED; base paints no target line → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "ab", files=("firmware.s19",))
    (_wa(base) / "ef").mkdir()
    (_wa(base) / "nt").mkdir()
    (_wa(base) / "nt" / "notes.txt").write_text("notes", encoding="utf-8")
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        out = {}
        await _type_and_wait(pilot, app, "ab", "merges into an existing project")
        out["ab"] = sd.where_text(app.screen)
        for name in ("ef", "nt"):
            await _type_and_wait(pilot, app, name, "new project in an existing folder")
            out[name] = sd.where_text(app.screen)
        return out

    out = _run(base, scenario)
    assert _where_line_for_text(out["ab"], "ab", "merges into an existing project"), out
    for name in ("ef", "nt"):
        assert _where_line_for_text(out[name], name, "new project in an existing folder"), out
        assert "merges into an existing project" not in out[name], out


# --- the refusal arms (one fixture each; reused by the LLR-175.6 equality) --


class _Arm:
    """One refusal arm of HLR-175b: a fixture built before the app, a setup
    inside it, the typed name, the token pair and the names the line must
    hold, and an optional stub active while the dialog (or the direct call)
    prepares the save."""

    def __init__(self, key, name, tokens, names=(), prep=None, setup=None, stub=None,
                 windows=False, base=None):
        self.key = key
        self.name = name
        self.tokens = tokens
        self.names = names
        self.prep = prep
        self.setup = setup
        self.stub = stub
        self.windows = windows
        self.base = base


def _base_of(arm: _Arm, tmp_path: Path, side: str) -> Path:
    return arm.base(tmp_path / side) if arm.base else tmp_path / side / "app"


def _prep_none(tmp_path: Path, base: Path) -> dict:
    return {"src": _sources(tmp_path, CASE01_DIR, "firmware.s19", "firmware.mac", "firmware.a2l",
                            folder=f"src_{base.parent.name}")}


async def _setup_s19(app, pilot, ctx) -> None:
    await _load_direct(pilot, app, ctx["src"] / "firmware.s19")


def _prep_clash(tmp_path: Path, base: Path) -> dict:
    ctx = _prep_none(tmp_path, base)
    projects.save_case01_project(base, "ab", files=("firmware.s19",))
    projects.save_case01_project(base, "P2", files=("firmware.s19",))
    return ctx


async def _setup_open_p2(app, pilot, ctx) -> None:
    await _open_project_direct(pilot, app, "P2")


def _padded_base(side_dir: Path, workarea_len: int = 180) -> Path:
    """A base folder whose work-area string is ``workarea_len`` long."""
    tail = side_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    pad = workarea_len - len(str(tail)) - 1
    if pad <= 0:
        pytest.skip(f"tmp_path too deep for a {workarea_len}-character work area: {tail}")
    return side_dir / ("p" * pad)


def _path_limit_name_length(base: Path) -> int:
    """L: the longest name that meets the full-path limit exactly."""
    return app_module._SAVE_FULL_PATH_LIMIT - app_module._SAVE_REPORT_SUFFIX_CHARS - 1 - len(str(_wa(base)))


def _prep_junction(tmp_path: Path, base: Path) -> dict:
    from tests.support.b100_links import create_junction

    ctx = _prep_none(tmp_path, base)
    outside = projects.outside_folder(base.parent, "jt_target")
    _wa(base).mkdir(parents=True, exist_ok=True)
    try:
        create_junction(_wa(base) / "jt", outside)
    except OSError as exc:  # pragma: no cover - platform
        pytest.skip(f"a directory junction cannot be made here: {exc}")
    ctx["outside"] = outside
    return ctx


def _prep_saved_p(tmp_path: Path, base: Path) -> dict:
    ctx = _prep_none(tmp_path, base)
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    return ctx


def _stub_lstat_p(monkeypatch, app, ctx):
    """``os.lstat`` raises ``PermissionError`` for ``W/P`` (the TC-B100-62
    fixture pattern, TC stub)."""
    denied = os.path.normcase(str(app.workarea / "P"))
    original = os.lstat

    def _lstat(path, *args, **kwargs):
        if os.path.normcase(str(path)) == denied:
            raise PermissionError(13, "denied", str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(app_module.os, "lstat", _lstat)
    return lambda: monkeypatch.setattr(app_module.os, "lstat", original)


def _prep_strasse(tmp_path: Path, base: Path) -> dict:
    ctx = _prep_none(tmp_path, base)
    strasse = projects.save_case01_project(base, "strasse", files=("firmware.s19",))
    imported = _wa(base) / "straße"
    try:
        shutil.copytree(strasse, imported)
    except OSError as exc:  # pragma: no cover - platform
        pytest.skip(f"the volume cannot hold both strasse and straße: {exc}")
    if not imported.is_dir() or os.path.samefile(imported, strasse):
        pytest.skip("the volume folds straße onto strasse")
    ctx["imported"] = imported
    ctx["imported_manifest"] = _sha(imported / "project.json")
    return ctx


async def _setup_open_strasse(app, pilot, ctx) -> None:
    await _open_project_direct(pilot, app, "strasse")


def _prep_second_mac(tmp_path: Path, base: Path) -> dict:
    ctx = _prep_none(tmp_path, base)
    projects.save_case01_project(base, "P1", files=("firmware.s19", "firmware.mac"))
    m2 = projects.save_case01_project(base, "m2", files=("firmware.s19",))
    (m2 / "other.mac").write_bytes((CASE01_DIR / "firmware.mac").read_bytes())
    return ctx


async def _setup_open_p1(app, pilot, ctx) -> None:
    await _open_project_direct(pilot, app, "P1")


def _stub_disk_short(monkeypatch, app, ctx):
    """``shutil.disk_usage`` reports ``ctx["free"]`` (default: one byte
    less than the fresh ``fresh1`` plan's 69 632, B11-30) for the work area
    only (TC stub, LLR-175.1j)."""
    real = shutil.disk_usage
    workarea = os.path.normcase(str(app.workarea))
    free = ctx.get("free", 69631)

    def _usage(path):
        usage = real(path)
        if os.path.normcase(str(path)) == workarea:
            return type(usage)(usage.total, usage.total - free, free)
        return usage

    monkeypatch.setattr(shutil, "disk_usage", _usage)
    return lambda: monkeypatch.setattr(shutil, "disk_usage", real)


async def _setup_s19_then_delete(app, pilot, ctx) -> None:
    await _load_direct(pilot, app, ctx["src"] / "firmware.s19")
    Path(app.current_file.path).unlink()


def _stub_digest_mac(monkeypatch, app, ctx):
    """``_file_digest`` raises ``PermissionError`` for the MAC (TC stub,
    LLR-175.1l)."""
    original = app_module._file_digest

    def _digest(path, *args, **kwargs):
        if Path(path).name == "firmware.mac":
            raise PermissionError(13, "Permission denied", str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(app_module, "_file_digest", _digest)
    return lambda: monkeypatch.setattr(app_module, "_file_digest", original)


async def _setup_blocked(app, pilot, ctx) -> None:
    await _load_direct(pilot, app, ctx["src"] / "firmware.s19")
    app._change_service.load_text(_blocked_document_text())


def _stub_listdir_wa(monkeypatch, app, ctx):
    """``os.listdir`` (the ``Path.iterdir`` listing on Python 3.11) raises
    ``PermissionError`` for the work area only (S11-03)."""
    denied = os.path.normcase(os.path.abspath(str(app.workarea)))
    original = os.listdir

    def _listdir(path=".", *args, **kwargs):
        if os.path.normcase(os.path.abspath(os.fspath(path))) == denied:
            raise PermissionError(13, "denied", os.fspath(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "listdir", _listdir)
    return lambda: monkeypatch.setattr(os, "listdir", original)


REFUSAL_ARMS = [
    _Arm("reserved", "Reports", RESERVED, ("Reports",), _prep_none, _setup_s19),
    _Arm("device", "CON", DEVICE, ("CON",), _prep_none, _setup_s19),
    _Arm("clash", "a b", CLASH, ("a b", "ab"), _prep_clash, _setup_open_p2),
    _Arm("over64", "a" * 65, TOO_LONG, (), _prep_none, _setup_s19),
    _Arm("path", None, PATH_LONG, (), _prep_none, _setup_s19, base=_padded_base),
    _Arm("link", "jt", LINK, ("jt",), _prep_junction, _setup_s19, windows=True),
    _Arm("unreadable_target", "P", FOLDER_UNREADABLE, ("P",), _prep_saved_p, _setup_s19, stub=_stub_lstat_p),
    _Arm("no_char", "!!!", EMPTY, (), _prep_none, _setup_s19),
    _Arm("casefold", "strasse", CLASH, ("strasse", "straße"), _prep_strasse, _setup_open_strasse,
         windows=True),
    _Arm("plan", "m2", SECOND_MAC, ("other.mac",), _prep_second_mac, _setup_open_p1),
    _Arm("space", "fresh1", NO_SPACE, (), _prep_none, _setup_s19, stub=_stub_disk_short),
    _Arm("missing", "ok", MISSING, ("firmware.s19",), _prep_none, _setup_s19_then_delete),
    _Arm("unreadable_source", "ok", FILE_UNREADABLE, ("firmware.mac",), _prep_second_mac, _setup_open_p1,
         stub=_stub_digest_mac),
    _Arm("blocked", "ok", BLOCKED, ("0x8000007C",), _prep_none, _setup_blocked),
    _Arm("workarea", "ok", FOLDER_UNREADABLE, (), _prep_none, _setup_s19, stub=_stub_listdir_wa),
]


def _arm_name(arm: _Arm, base: Path) -> str:
    if arm.key == "path":
        return "a" * (_path_limit_name_length(base) + 1)
    return arm.name


def _refusal_in_dialog(tmp_path: Path, monkeypatch, arm: _Arm) -> dict:
    """Drive one arm through the dialog: open, type, read the painted
    refusal and the rows, press ``alt+s``, read again; the work-area
    listing before and after."""
    if arm.windows and not WIN:
        pytest.skip("Windows-only arm; not run here")
    base = _base_of(arm, tmp_path, "dlg")
    ctx = arm.prep(tmp_path, base)
    name = _arm_name(arm, base)

    async def scenario(app, pilot, log):
        await arm.setup(app, pilot, ctx)
        listing0 = sd.workarea_listing(app.workarea)
        restore = arm.stub(monkeypatch, app, ctx) if arm.stub else None
        try:
            await sd.open_save_dialog(pilot, app)
            await _type_and_wait(pilot, app, name, *arm.tokens)
            before_save = sd.where_text(app.screen)
            rows = sd.summary_rows(app.screen)
            await pilot.press("alt+s")
            await _settle(pilot, 8)
            open_after = sd.is_save_dialog(app.screen)
            after_save = sd.where_text(app.screen) if open_after else ""
            spans = sd.spans(sd.where_widget(app.screen)) if open_after else -1
        finally:
            if restore:
                restore()
        listing1 = sd.workarea_listing(app.workarea)
        return {"before": before_save, "rows": rows, "open": open_after, "after": after_save,
                "new_paths": sorted(listing1 - listing0), "running": app.is_running, "spans": spans}

    return _run(base, scenario)


@pytest.mark.parametrize("arm", REFUSAL_ARMS, ids=[a.key for a in REFUSAL_ARMS])
def test_tc_b100_47_refusal_painted_in_the_dialog_before_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: _Arm
) -> None:
    """HLR-175b, LLR-175.1a … .1m, .1o, .1p, LLR-175.3f (one arm per
    refusal kind, 15 arms; platform arms counted): the refusal's reason
    token and next-step token (and the names it must hold) are painted in
    ``#save_where`` BEFORE Save, with 0 summary rows; ``alt+s`` keeps the
    dialog open with the pair still painted; 0 new paths in the work-area
    listing; the app keeps running; the line has 0 markup spans.

    Why: O-9 / M-4 — a refusal painted only after the dialog closed made
    the engineer retype from memory; a Save that would be refused must say
    why next to the field the engineer must change (ruling Q5).
    Negative control: executed on the 9a tree (P11-2): ``typed 'Reports' ->
    dialog text has 'reserved name'? False`` → RED; a mutant that paints the
    refusal only after the dialog closes → 0 lines before Save and 1
    dismiss → RED. Per-arm mutants (draft): the comparison without
    case-folding (reserved, clash), only the sanitised form checked
    (device), the cap read as 65, the 53-character suffix dropped (path),
    the link check removed, ``unreadable`` mapped to no refusal, the pair
    painted only on Save (no usable character), the plan's rows painted
    without its refusal, the free-space check left in the handler, the
    ``OSError`` not caught (unreadable source, unreadable work area), the
    open project decided by case-folding (``strasse`` / ``straße``)."""
    out = _refusal_in_dialog(tmp_path, monkeypatch, arm)
    for token in tuple(arm.tokens) + tuple(arm.names):
        assert token in out["before"], (token, out)
    assert out["rows"] == [], out
    assert out["open"] is True, out
    for token in arm.tokens:
        assert token in out["after"], (token, out)
    assert out["new_paths"] == [], out
    assert out["running"] is True
    assert out["spans"] == 0, out


@pytest.mark.parametrize("typed", ["reports", "CRC", "Splits", "FLOWS", "Temp"])
def test_tc_b100_47_reserved_names_in_mixed_case(tmp_path: Path, typed: str) -> None:
    """LLR-175.1a (5 of 5): each reserved home in mixed case → ``reserved
    name`` / ``choose another name`` in the dialog; ``alt+s`` keeps it
    open; 0 new paths.

    Why: a project named after a work-area home would overlay it. Negative
    control: the comparison without case-folding → ``CRC`` paints no pair →
    RED; base: no line before Save (P11-2) → RED."""
    out = _refusal_in_dialog(tmp_path, None, _Arm("r", typed, RESERVED, (), _prep_none, _setup_s19))
    assert all(t in out["before"] for t in RESERVED), out
    assert out["open"] and out["new_paths"] == [], out


@pytest.mark.parametrize("typed", ["nul", "CON", "com1", "LPT¹", "con.txt", "C O N"])
def test_tc_b100_47_device_names_raw_component_and_sanitised(tmp_path: Path, typed: str) -> None:
    """LLR-175.1b (6 of 6): ``nul``, ``CON``, ``com1``, ``LPT¹``, ``con.txt``
    and ``C O N`` → ``device name`` / ``choose another name`` before Save;
    ``alt+s`` keeps the dialog; 0 new paths.

    Why: a Windows device name cannot be a folder; ``con.txt`` and ``C O N``
    are caught on the raw name and on the sanitised form. Negative control:
    only the sanitised form checked → ``con.txt`` (``contxt``) paints no
    pair → RED."""
    out = _refusal_in_dialog(tmp_path, None, _Arm("d", typed, DEVICE, (), _prep_none, _setup_s19))
    assert all(t in out["before"] for t in DEVICE), out
    assert out["open"] and out["new_paths"] == [], out


def test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges(tmp_path: Path) -> None:
    """LLR-175.1c (F-merge with ``P2`` open; 3 of 3): ``a b`` → 1 line with
    ``already a project``, ``a b``, ``ab`` and ``choose another name``;
    ``AB`` → the same naming ``AB`` and ``ab``; ``ab`` exactly → no refusal
    and ``merges into an existing project``; after ``alt+s`` on each refused
    arm 0 new paths and the ``ab`` folder's digests unchanged.

    Why: a case-folded or sanitised twin of another project would silently
    merge into it (UX-35). Negative control: the clash compared without
    case-folding → ``AB`` paints ``new folder`` → RED."""
    base = tmp_path / "app"
    ctx = _prep_clash(tmp_path, base)

    async def scenario(app, pilot, log):
        await _setup_open_p2(app, pilot, ctx)
        ab = app.workarea / "ab"
        digests0 = sd.tree_digests(ab)
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        out = {}
        for typed in ("a b", "AB"):
            # E4 integration: also wait for the typed name itself; the stale
            # ``a b`` refusal already holds the CLASH tokens.
            await _type_and_wait(pilot, app, typed, *CLASH, f"'{typed}'")
            text = sd.where_text(app.screen)
            await pilot.press("alt+s")
            await _settle(pilot, 8)
            out[typed] = (text, sd.is_save_dialog(app.screen))
        await _type_and_wait(pilot, app, "ab", "merges into an existing project")
        out["ab"] = (sd.where_text(app.screen), True)
        out["digests"] = sd.tree_digests(ab) == digests0
        out["new_paths"] = sorted(sd.workarea_listing(app.workarea) - listing0)
        return out

    out = _run(base, scenario)
    for typed in ("a b", "AB"):
        text, still_open = out[typed]
        line = next((l for l in text.split("\n") if CLASH[0] in l), "")
        assert f"'{typed}'" in line and "'ab'" in line and CLASH[1] in line, out
        assert still_open, out
    assert CLASH[0] not in out["ab"][0], out
    assert out["digests"] is True and out["new_paths"] == [], out


def test_tc_b100_47_name_cap_64_65_300(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-175.1d (3 of 3): 64 characters → no refusal (``new folder``); 65
    and 300 → ``name too long`` / ``shorten the name``, the app running,
    0 new paths.

    The full-path limit (LLR-175.1e, its own test) is lifted here: the 64
    arm needs a work area of at most 141 characters, longer than the test
    temp root gives (E4 integration).

    The 65 and 300 refusals paint the same text, so each over-cap arm first
    waits for a neutral ``bbb — new folder`` paint and then reads the field
    value: the 300 arm can only pass on its own paint (E5, SR-11-name-cap).

    Negative control: the cap read as 65 → the 65 arm paints no pair → RED;
    a cap that refuses 65 but not 300 → the 300 arm paints ``new folder``
    → RED."""
    import s19_app.tui.app as app_module

    monkeypatch.setattr(app_module, "_SAVE_FULL_PATH_LIMIT", 10_000)
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        out = {}
        await _type_and_wait(pilot, app, "a" * 64, "new folder")
        out[64] = sd.where_text(app.screen)
        for n in (65, 300):
            await sd.set_name(pilot, app, "bbb")
            await sd.wait_for(
                pilot,
                lambda: _where_line_for_text(sd.where_text(app.screen), "bbb", "new folder"),
                "the neutral paint of bbb",
                10.0,
            )
            await sd.set_name(pilot, app, "a" * n)
            await sd.wait_painted(pilot, app, *TOO_LONG)
            out[n] = sd.where_text(app.screen)
            out[f"value{n}"] = sd.name_input(app.screen).value
        out["new"] = sorted(sd.workarea_listing(app.workarea) - listing0)
        out["running"] = app.is_running
        return out

    out = _run(base, scenario)
    assert TOO_LONG[0] not in out[64], out
    assert all(t in out[65] for t in TOO_LONG) and all(t in out[300] for t in TOO_LONG), out
    assert out["value65"] == "a" * 65 and out["value300"] == "a" * 300, out
    assert out["new"] == [] and out["running"], out


def test_tc_b100_47_path_limit_met_and_exceeded(tmp_path: Path) -> None:
    """LLR-175.1e (2 of 2): a base whose work area is sized so that a name
    of length L meets the full-path limit exactly → no refusal; L + 1 →
    ``path too long`` / ``shorten the name``.

    Negative control: the 53-character report suffix dropped from the sum
    → the L + 1 arm paints no pair → RED."""
    base = _padded_base(tmp_path / "dlg")
    src = _sources(tmp_path)
    length = _path_limit_name_length(base)
    assert 1 <= length <= 64, length

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await sd.set_name(pilot, app, "a" * length)
        await sd.wait_painted(pilot, app, "new folder")
        met = sd.where_text(app.screen)
        await sd.set_name(pilot, app, "a" * (length + 1))
        await sd.wait_painted(pilot, app, *PATH_LONG)
        return met, sd.where_text(app.screen)

    met, over = _run(base, scenario)
    assert PATH_LONG[0] not in met, met
    assert all(t in over for t in PATH_LONG), over


@WINDOWS_ARM
def test_tc_b100_47_junction_target_writes_nothing_through_it(tmp_path: Path) -> None:
    """LLR-175.1f (Windows arm; 1 of 1): ``W/jt`` a directory junction, ``jt``
    typed → ``link or junction`` / ``choose another name``; after
    ``alt+s`` 0 files under the junction's target.

    Negative control: the link check removed → ``merges into an existing
    project`` for ``jt`` → RED."""
    base = tmp_path / "dlg" / "app"
    ctx = _prep_junction(tmp_path, base)
    before = sorted(p.name for p in ctx["outside"].iterdir())

    async def scenario(app, pilot, log):
        await _setup_s19(app, pilot, ctx)
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "jt", *LINK)
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return sd.where_text(app.screen), sd.is_save_dialog(app.screen)

    text, still_open = _run(base, scenario)
    assert all(t in text for t in LINK) and still_open, text
    assert sorted(p.name for p in ctx["outside"].iterdir()) == before


def test_tc_b100_47_no_usable_character_painted_live(tmp_path: Path) -> None:
    """LLR-175.1h (3 of 3): ``!!!``, ``..`` and ``/`` → ``name is empty`` /
    ``type a project name`` painted by the recompute, BEFORE any Save; 0
    dismisses on ``alt+s``. Boundary (B11-46): an empty field at open paints
    no ``name is empty`` before Save.

    Why: a name that sanitises to nothing would be refused only on Save.
    Negative control: the pair painted only on Save → ``!!!`` paints
    nothing before Save → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        out = {"open": sd.where_text(app.screen)}
        for typed in ("!!!", "..", "/"):
            await _type_and_wait(pilot, app, typed, *EMPTY)
            out[typed] = sd.where_text(app.screen)
        await pilot.press("alt+s")
        await _settle(pilot, 6)
        out["still"] = sd.is_save_dialog(app.screen)
        return out

    out = _run(base, scenario)
    assert EMPTY[0] not in out["open"], out
    for typed in ("!!!", "..", "/"):
        assert all(t in out[typed] for t in EMPTY), out
    assert out["still"] is True


def test_tc_b100_47_plan_refusals_replace_the_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-175.1i (3 of 3): a target holding a second MAC → ``already has a
    MAC file`` / ``choose another name``; a target holding a second A2L →
    ``already has an A2L file``; a save as over the file ceiling (lowered
    to 10, TC only) → ``too many files to copy`` / ``move files out of the
    project, then save again``. Each paints 0 summary rows, the dialog's
    ``plan`` is the refused plan (0 rows), and ``alt+s`` writes 0 new paths.

    Why: a plan refusal reached the engineer only after the dialog closed.
    Negative control: the painter paints the rows of a refused plan and
    drops its refusal → 0 token pairs → RED."""
    import s19_app.tui.services.project_gather_service as gather

    base = tmp_path / "app"
    projects.save_case01_project(base, "P1", files=("firmware.s19", "firmware.mac", "firmware.a2l"))
    m2 = projects.save_case01_project(base, "m2", files=("firmware.s19",))
    (m2 / "other.mac").write_bytes((CASE01_DIR / "firmware.mac").read_bytes())
    a2 = projects.save_case01_project(base, "a2", files=("firmware.s19",))
    (a2 / "x.a2l").write_bytes((CASE01_DIR / "firmware.a2l").read_bytes())
    projects.bulk_files(_wa(base) / "P1", "reports", 11)
    monkeypatch.setattr(gather, "SAVE_AS_FILE_CEILING", 10)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P1")
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        out = {}
        for typed, tokens in (("m2", SECOND_MAC), ("a2", SECOND_A2L), ("Q", TOO_MANY)):
            await _type_and_wait(pilot, app, typed, *tokens)
            plan = app.screen.plan
            text, rows = sd.where_text(app.screen), sd.summary_rows(app.screen)
            await pilot.press("alt+s")
            await _settle(pilot, 8)
            out[typed] = (text, rows, None if plan is None else (plan.refusal is not None, len(plan.rows)),
                          sd.is_save_dialog(app.screen))
        out["new"] = sorted(sd.workarea_listing(app.workarea) - listing0)
        return out

    out = _run(base, scenario)
    for typed, tokens in (("m2", SECOND_MAC), ("a2", SECOND_A2L), ("Q", TOO_MANY)):
        text, rows, plan, still_open = out[typed]
        assert all(t in text for t in tokens), out[typed]
        assert rows == [], out[typed]
        assert plan == (True, 0), out[typed]
        assert still_open, out[typed]
    assert out["new"] == [], out


def test_tc_b100_47_free_space_short_by_one_and_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-175.1j, A11-02 (2 of 2): ``shutil.disk_usage`` stubbed (TC only)
    to the plan's ``total_bytes − 1`` free → ``not enough free space`` /
    ``free disk space or remove files from the project``, 0 dismisses on
    ``alt+s``, and the dialog's ``plan`` is ``None`` (A11-02: a free-space
    refusal passes no plan); exactly ``total_bytes`` free → no refusal.

    Why: the free-space check ran only after the dialog closed; a refusal
    that kept a plan could commit rows nobody saw after space was freed.
    Negative control: the check left in the handler → the dialog paints no
    pair and ``alt+s`` closes it → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)
    ctx: dict = {}

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "fresh1", "new folder")
        need = app.screen.plan.total_bytes
        ctx["free"] = need
        restore = _stub_disk_short(monkeypatch, app, ctx)
        await _type_and_wait(pilot, app, "fresh2", "fresh2", "new folder")
        exact = sd.where_text(app.screen)
        restore()
        ctx["free"] = need - 1
        restore = _stub_disk_short(monkeypatch, app, ctx)
        await _type_and_wait(pilot, app, "fresh3", *NO_SPACE)
        short = sd.where_text(app.screen)
        plan_after = app.screen.plan
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        still = sd.is_save_dialog(app.screen)
        restore()
        return need, exact, short, plan_after, still

    need, exact, short, plan_after, still = _run(base, scenario)
    assert need == 69632, need
    assert NO_SPACE[0] not in exact, exact
    assert all(t in short for t in NO_SPACE), short
    assert plan_after is None, plan_after
    assert still is True


@pytest.mark.parametrize("which", ["firmware.s19", "firmware.mac", "firmware.a2l"])
def test_tc_b100_47_missing_source_painted_at_open(tmp_path: Path, which: str) -> None:
    """LLR-175.1k (3 arms): a session file deleted after the load, then
    ``ctrl+s`` → 1 line holding ``source file missing``, the file's name and
    ``reload it or remove it from the project`` (shown even with the field
    empty, B11-46); 0 dismisses on ``alt+s``; 0 new paths.

    Negative control: on the 9a tree this refusal is painted only after the
    dialog closes (``_handle_save_dialog``, the LLR-155.4 arm) → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path, CASE01_DIR, "firmware.s19", "firmware.mac", "firmware.a2l")

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await _load_direct(pilot, app, src / "firmware.mac")
        await _load_direct(pilot, app, src / "firmware.a2l")
        paths = {
            "firmware.s19": app.current_file.path,
            "firmware.mac": app.current_file.mac_path,
            "firmware.a2l": app.current_a2l_path,
        }
        Path(paths[which]).unlink()
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, *MISSING)
        at_open = sd.where_text(app.screen)
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return at_open, sd.is_save_dialog(app.screen), sorted(sd.workarea_listing(app.workarea) - listing0)

    at_open, still, new = _run(base, scenario)
    line = next((l for l in at_open.split("\n") if MISSING[0] in l), "")
    assert which in line and MISSING[1] in line, at_open
    assert still is True and new == [], (still, new)


@pytest.mark.parametrize("arm", ["digest", "exists"])
def test_tc_b100_47_unreadable_source_painted_and_app_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-175.1l, S11-02 (2 arms): ``_file_digest`` raising
    ``PermissionError`` for the MAC (TC stub) → 1 line holding ``could not
    be read``, ``firmware.mac`` and ``check that the file can be opened,
    then save again``; ``Path.exists`` raising ``PermissionError`` for the
    MAC (the missing-source test inside the ``try``, S11-02) → the same
    line; 0 dismisses on ``alt+s``; the app running in both.

    Negative control: the ``OSError`` not caught at dialog open → the app
    raises → RED; on the 9a tree the text has no next step → RED (ruling
    Q11)."""
    base = tmp_path / "app"
    _prep_second_mac(tmp_path, base)

    async def scenario(app, pilot, log):
        await _setup_open_p1(app, pilot, {})
        if arm == "digest":
            restore = _stub_digest_mac(monkeypatch, app, {})
        else:
            real_exists = Path.exists

            def _exists(self, *args, **kwargs):
                if self.name == "firmware.mac":
                    raise PermissionError(13, "Permission denied", str(self))
                return real_exists(self, *args, **kwargs)

            monkeypatch.setattr(Path, "exists", _exists)
            restore = lambda: monkeypatch.setattr(Path, "exists", real_exists)  # noqa: E731
        try:
            await sd.open_save_dialog(pilot, app)
            await sd.wait_painted(pilot, app, *FILE_UNREADABLE)
            text = sd.where_text(app.screen)
            await pilot.press("alt+s")
            await _settle(pilot, 8)
            still = sd.is_save_dialog(app.screen)
        finally:
            restore()
        return text, still, app.is_running

    text, still, running = _run(base, scenario)
    line = next((l for l in text.split("\n") if FILE_UNREADABLE[0] in l), "")
    assert "firmware.mac" in line and FILE_UNREADABLE[1] in line, text
    assert still and running, (still, running)


@pytest.mark.parametrize("count", [1, 3])
def test_tc_b100_47_blocked_entries_painted_with_addresses(tmp_path: Path, count: int) -> None:
    """LLR-175.1m (1 and 3 blocked entries): the TC-B100-57 document shape
    → 1 line holding the blocked-entries reason token, the blocked
    addresses and ``fix them in the Patch Editor``; 0 dismisses on
    ``alt+s``; 0 new paths.

    Negative control: on the 9a tree this refusal is painted only after the
    dialog closes → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)
    addresses = ["0x8000007C", "0x80000070", "0x80000074"][:count]
    entries = ",".join('{"type": "bytes", "address": "%s", "bytes": "DE AD"}' % a for a in addresses)
    text_doc = (
        '{"format": "s19app-changeset", "version": "2.0", "kind": "change",'
        ' "encoding": "utf-8", "value_mode": "text", "entries": ['
        + entries + ',{"type": "bytes", "address": "0xZZ", "bytes": "01"}]}'
    )

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        app._change_service.load_text(text_doc)
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, *BLOCKED)
        text = sd.where_text(app.screen)
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return text, sd.is_save_dialog(app.screen), sorted(sd.workarea_listing(app.workarea) - listing0)

    text, still, new = _run(base, scenario)
    line = next((l for l in text.split("\n") if BLOCKED[0] in l), "")
    assert all(a in line for a in addresses) and BLOCKED[1] in line, text
    assert still is True and new == [], (still, new)


@WINDOWS_ARM
def test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash(tmp_path: Path) -> None:
    """LLR-175.1p, S11-01 (Windows arm; 1 of 1 plus the exact-name merge):
    ``strasse`` open with ``straße`` present (an imported project),
    ``strasse`` typed → ``already a project`` naming ``strasse`` and
    ``straße``, ``choose another name``; ``alt+s`` keeps the dialog; 0 files
    written; ``straße/project.json`` unchanged. ``straße`` typed exactly →
    ``merges into an existing project`` (R2-03).

    Why: Python ``casefold`` folds ``straße`` to ``strasse`` while NTFS keeps
    two folders; deciding "the open project" by case-folding would save the
    open session's files into ``straße``. Negative control: the open-project
    test kept on case-folding → ``updates the open project`` and the files
    land in ``straße`` → RED."""
    base = tmp_path / "app"
    ctx = _prep_strasse(tmp_path, base)

    async def scenario(app, pilot, log):
        await _setup_open_strasse(app, pilot, ctx)
        digests0 = sd.tree_digests(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "strasse", *CLASH)
        refused = sd.where_text(app.screen)
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        still = sd.is_save_dialog(app.screen)
        digests1 = sd.tree_digests(app.workarea)
        await _type_and_wait(pilot, app, "straße", "merges into an existing project")
        return refused, still, digests0 == digests1, sd.where_text(app.screen)

    refused, still, unchanged, exact = _run(base, scenario)
    line = next((l for l in refused.split("\n") if CLASH[0] in l), "")
    assert "strasse" in line and "straße" in line and CLASH[1] in line, refused
    assert still and unchanged, (still, unchanged)
    assert _sha(ctx["imported"] / "project.json") == ctx["imported_manifest"]
    assert "updates the open project" not in refused, refused
    assert "merges into an existing project" in exact, exact


def test_tc_b100_47_one_preparation_ast_census() -> None:
    """LLR-175.6 (B11-32, S2-6, V-2), AST arm: in ``app.py`` the Save path
    reaches ``sanitize_project_name``, ``is_windows_device_name`` (on the
    typed name), the ``RESERVED_WORKAREA_HOMES`` comparison,
    ``PROJECT_NAME_MAX_CHARS``, ``_project_folder_refusal`` (on the target)
    and ``_plan_project_save`` only inside ``_prepare_project_save`` (0 other
    Save-path sites; declared exemptions: ``is_windows_device_name`` in the
    commit's unrecorded-file line, ``_project_folder_refusal`` on
    ``self.current_project_dir``). In ``screens.py`` the
    ``SaveProjectScreen`` class body calls none of the rules, the listing
    or the planner, and nothing in ``screens.py`` builds a ``SavePreview``.

    Why: two copies of the rules let the dialog say "saves" while the
    handler refuses. Negative control: a dialog-side copy of the reserved
    rule → 1 extra site → RED. RED (base): ``_prepare_project_save`` does
    not exist."""
    app_tree = ast.parse((ROOT / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(app_tree) if isinstance(n, ast.ClassDef) and n.name == "S19TuiApp")
    methods = {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "_prepare_project_save" in methods, "no _prepare_project_save (the one preparation)"
    save_path = [
        "action_save_project", "_handle_save_dialog", "_save_dialog_preview", "_compose_save_preview",
        "_confirm_project_save", "_commit_project_save", "_save_session_inputs", "_current_save_session",
    ]
    rules = {"sanitize_project_name", "RESERVED_WORKAREA_HOMES", "PROJECT_NAME_MAX_CHARS", "_plan_project_save"}

    def sites(fn) -> list:
        found = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Name) and node.id in rules:
                found.append(node.id)
            elif isinstance(node, ast.Attribute) and node.attr in rules:
                found.append(node.attr)
            elif isinstance(node, ast.Call):
                func = node.func
                fname = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if fname == "_project_folder_refusal":
                    arg = ast.unparse(node.args[0]) if node.args else ""
                    if "current_project_dir" not in arg:
                        found.append(f"_project_folder_refusal({arg})")
                if fname == "is_windows_device_name" and fn.name != "_commit_project_save":
                    found.append("is_windows_device_name")
        return found

    outside = {name: sites(methods[name]) for name in save_path if name in methods and sites(methods[name])}
    assert outside == {}, outside
    inside = sites(methods["_prepare_project_save"])
    for rule in ("sanitize_project_name", "RESERVED_WORKAREA_HOMES", "PROJECT_NAME_MAX_CHARS",
                 "_plan_project_save", "is_windows_device_name"):
        assert rule in inside, (rule, inside)

    screens_tree = ast.parse((ROOT / "s19_app" / "tui" / "screens.py").read_text(encoding="utf-8"))
    dialog = next(n for n in ast.walk(screens_tree) if isinstance(n, ast.ClassDef) and n.name == "SaveProjectScreen")
    banned = {
        "sanitize_project_name", "is_windows_device_name", "predict_placement", "place_into_workarea",
        "list_projects", "listdir", "iterdir", "_project_folder_refusal", "plan_project_save", "SavePreview",
    }

    def call_name(node) -> str:
        return node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")

    called = sorted(call_name(n) for n in ast.walk(dialog) if isinstance(n, ast.Call) and call_name(n) in banned)
    assert called == [], called
    builders = [n for n in ast.walk(screens_tree) if isinstance(n, ast.Call) and call_name(n) == "SavePreview"]
    assert builders == [], "screens.py builds a SavePreview (a second decider)"


def _status_refusal(messages: list) -> str:
    refusals = [m for m in messages if m.startswith(PREFIX)]
    return refusals[-1] if refusals else ""


@pytest.mark.parametrize(
    "arm", REFUSAL_ARMS + [_Arm("valid", "fresh1", (), (), _prep_none, _setup_s19)],
    ids=[a.key for a in REFUSAL_ARMS] + ["valid"],
)
def test_tc_b100_47_dialog_line_equals_the_direct_status_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: _Arm
) -> None:
    """LLR-175.6 (B11-33; 16 of 16, platform arms counted): for each of the
    15 refusal arms and ``fresh1``, on twin fixtures, the dialog's refused
    ``#save_where`` line equals, character for character, the status line a
    direct ``_handle_save_dialog`` call paints with ``Project NOT saved: ``
    removed; ``fresh1`` saves on both sides (the dialog by ``alt+s``).

    Why: one function decides what the dialog shows and what the save does,
    so the dialog can never say "saves" while the handler refuses (R-PC).
    Negative control: the dialog side keeps its own copy of the reserved
    rule without case-folding → ``Reports`` paints nothing in the dialog
    while the direct call refuses → RED."""
    from s19_app.tui.screens import SaveProjectPayload

    if arm.windows and not WIN:
        pytest.skip("Windows-only arm; not run here")
    sides = {}
    for side in ("dlg", "dir"):
        base = _base_of(arm, tmp_path, side)
        ctx = arm.prep(tmp_path, base)
        name = _arm_name(arm, base)

        async def scenario(app, pilot, log, side=side, ctx=ctx, name=name):
            await arm.setup(app, pilot, ctx)
            restore = arm.stub(monkeypatch, app, ctx) if arm.stub else None
            try:
                if side == "dir":
                    mark = len(log.messages)
                    app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name=name))
                    await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
                    await _settle(pilot, 10)
                    msgs = log.since(mark)
                    return _status_refusal(msgs), any(m.startswith("Saved project to") for m in msgs)
                await sd.open_save_dialog(pilot, app)
                if arm.tokens:
                    await _type_and_wait(pilot, app, name, *arm.tokens)
                    lines = [l for l in sd.where_text(app.screen).split("\n") if arm.tokens[0] in l]
                    return (lines[0] if lines else sd.where_text(app.screen)), False
                await _type_and_wait(pilot, app, name, "new folder")
                mark = len(log.messages)
                await pilot.press("alt+s")
                await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the dialog to close")
                await sd.wait_for(
                    pilot, lambda: any(m.startswith("Saved project to") for m in log.since(mark)), "the save"
                )
                return "", True
            finally:
                if restore:
                    restore()

        sides[side] = _run(base, scenario)
    (dialog_line, dialog_saved), (status_line, direct_saved) = sides["dlg"], sides["dir"]
    if not arm.tokens:
        assert dialog_saved and direct_saved, sides
        return
    assert status_line.startswith(PREFIX), sides
    assert dialog_line == status_line[len(PREFIX):], sides


# ---------------------------------------------------------------------------
# TC-B100-48 — LLR-175.2, LLR-175.2a: no parent field; the payload's parent
# is this work area
# ---------------------------------------------------------------------------

PC_B_IDS = ("save_box", "project_name", "save_where", "save_summary", "saveproject_buttons", "save_ok", "save_cancel")


@pytest.mark.parametrize("size", SIZES)
def test_tc_b100_48_no_parent_field_and_no_browse(tmp_path: Path, size: tuple) -> None:
    """LLR-175.2, HLR-175e, HLR-175f, R1-1 (2 of 2 sizes): the dialog opened
    by ``ctrl+s`` composes 0 ``#project_parent_path``, 0 ``#save_browse``
    and 0 ``#save_browse_row``, and exactly 1 of each ``pc_B`` id
    (``#save_box``, ``#project_name``, ``#save_where``, ``#save_summary``,
    ``#saveproject_buttons``, ``#save_ok``, ``#save_cancel``); ``screens.py``
    holds no ``project_parent_path`` / ``save_browse`` text.

    Why: D7 = ``solo_workarea`` — a parent field let the engineer save
    outside the work area. Negative control: executed on the 9a tree
    (P11-2): ``widgets #project_parent_path: 1 #save_browse: 1`` → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        return (
            {i: len(screen.query(f"#{i}")) for i in ("project_parent_path", "save_browse", "save_browse_row")},
            {i: len(screen.query(f"#{i}")) for i in PC_B_IDS},
            len(app.screen_stack),
        )

    retired, ids, depth = _run(base, scenario, size=size)
    assert retired == {"project_parent_path": 0, "save_browse": 0, "save_browse_row": 0}, retired
    assert ids == {i: 1 for i in PC_B_IDS}, ids
    assert depth == 2
    source = (ROOT / "s19_app" / "tui" / "screens.py").read_text(encoding="utf-8")
    assert "project_parent_path" not in source and "save_browse" not in source


def test_tc_b100_48_payload_parent_is_the_work_area_under_a_long_base(tmp_path: Path) -> None:
    """LLR-175.2a, HLR-175e, S6-2, S8-2 (2 of 2): a save through the dialog
    under a base path of at least 150 characters → ``Path(payload.
    parent_folder) == app.workarea``, the payload carries the painted plan
    object (``payload.plan is screen.plan``), and the new folder's parent
    equals ``app.workarea``.

    Why: the dialog saves only into this work area (D7); the router refuses
    any other parent (LLR-171.3). Negative control: the payload's parent
    taken from ``base_dir`` → the router refuses ``not the work area
    folder`` → RED (declared: on the 9a tree the editable field's default
    already is the work area, so the base RED here is the missing
    ``alt+s`` / summary)."""
    deep = tmp_path / "b"
    pad = 150 - len(str(deep)) - 1
    base = deep / ("q" * pad) if pad > 0 else deep
    assert len(str(base)) >= 150 or pad <= 0
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await _type_and_wait(pilot, app, "fresh1", "fresh1", "new folder")
        painted_plan = screen.plan
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the dialog to close")
        await sd.wait_for(pilot, lambda: (app.workarea / "fresh1" / "project.json").is_file(), "the save")
        return seen, painted_plan, app.workarea

    seen, painted_plan, workarea = _run(base, scenario)
    assert len(seen) == 1 and seen[0] is not None, seen
    assert Path(seen[0].parent_folder) == workarea, (seen[0].parent_folder, workarea)
    assert seen[0].plan is painted_plan and painted_plan is not None
    assert (workarea / "fresh1").parent == workarea


# ---------------------------------------------------------------------------
# TC-B100-49 — LLR-175.3 … LLR-175.3j: keys, focus, empty Save, Save during
# a refusal, the priority keys, the prefill, the labels, nothing loaded
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("focus", ["project_name", "save_summary", "save_ok", "save_cancel"])
def test_tc_b100_49_escape_from_each_focus_position(tmp_path: Path, focus: str) -> None:
    """LLR-175.3, HLR-175c, S7-1 (4 of 4): ``fresh1`` typed and its summary
    painted; ``escape`` with the focus on ``#project_name``,
    ``#save_summary``, ``#save_ok`` or ``#save_cancel`` → the callback gets
    ``None``, the stack is the main screen alone, 0 new paths, the session
    digest unchanged.

    Why: CW-U-12 — ``escape`` was ignored, so the only way out was a mouse.
    Negative control: executed on the 9a tree (P11-2): ``escape -> stack:
    ['Screen', 'SaveProjectScreen']`` → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        digest0 = sd.session_digest(app)
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "fresh1", "fresh1", "new folder")
        app.screen.set_focus(app.screen.query_one(f"#{focus}"))
        await _settle(pilot, 2)
        focused = _focused_id(app)
        await pilot.press("escape")
        await _settle(pilot, 8)
        return focused, list(seen), _stack(app), sorted(sd.workarea_listing(app.workarea) - listing0), \
            sd.session_digest(app) == digest0

    focused, seen, stack, new, same = _run(base, scenario)
    assert focused == focus
    assert seen == [None], seen
    assert len(stack) == 1, stack
    assert new == [] and same, (new, same)


def test_tc_b100_49_escape_after_a_refusal_closes(tmp_path: Path) -> None:
    """HLR-175c boundary, S7-3: ``Reports`` refused and ``alt+s`` refused,
    then ``escape`` → the callback gets ``None`` and the dialog closes.

    Negative control: a mutant that marks the dialog dismissed on a refused
    Save → ``escape`` is ignored → RED; base: ``escape`` ignored (P-18)."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "Reports", *RESERVED)
        await pilot.press("alt+s")
        await _settle(pilot, 6)
        refused_open = sd.is_save_dialog(app.screen)
        await pilot.press("escape")
        await _settle(pilot, 8)
        return refused_open, list(seen), _stack(app)

    refused_open, seen, stack = _run(base, scenario)
    assert refused_open is True
    assert seen == [None] and len(stack) == 1, (seen, stack)


@pytest.mark.parametrize("how", ["click", "enter"])
def test_tc_b100_49_cancel_closes_with_no_result(tmp_path: Path, how: str) -> None:
    """LLR-175.3a, S7-2 (2 of 2): ``fresh1`` typed and its summary painted;
    a click on ``#save_cancel`` or ``enter`` on the focused ``#save_cancel``
    → the callback gets ``None``, 0 new paths.

    Negative control: Cancel routed to the save action → 1 new folder →
    RED. Declared: on the 9a tree Cancel already dismisses with ``None``;
    the base RED of this node is the summary that is never painted."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "fresh1", "fresh1", "new folder")
        if how == "click":
            assert await pilot.click("#save_cancel")
        else:
            app.screen.set_focus(app.screen.query_one("#save_cancel"))
            await _settle(pilot, 2)
            await pilot.press("enter")
        await _settle(pilot, 8)
        return list(seen), sorted(sd.workarea_listing(app.workarea) - listing0)

    seen, new = _run(base, scenario)
    assert seen == [None] and new == [], (seen, new)


@pytest.mark.parametrize("text", ["", "   "])
@pytest.mark.parametrize("trigger", ["alt+s", "save_ok", "enter"])
def test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why(tmp_path: Path, text: str, trigger: str) -> None:
    """LLR-175.3b, HLR-175d, S6-4, B11-62 (6 of 6): the field ``""`` or
    ``"   "``, then ``alt+s``, a click on ``#save_ok`` or ``enter`` in the
    field → ``#save_where`` paints ``name is empty`` / ``type a project
    name``; 0 dismisses; 0 new paths. Before the press nothing about the
    empty name is painted (LLR-175.1h boundary).

    Why: CW-U-13 — an empty Save said nothing. Negative control: executed
    on the 9a tree (P11-2): ``empty Save click -> … 'name is empty'?
    False`` → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, text)
        await sd.wait_recompute(pilot)
        before = sd.where_text(app.screen)
        if trigger == "alt+s":
            await pilot.press("alt+s")
        elif trigger == "save_ok":
            assert await pilot.click("#save_ok")
        else:
            app.screen.set_focus(sd.name_input(app.screen))
            await _settle(pilot, 2)
            await pilot.press("enter")
        await _settle(pilot, 8)
        return before, sd.where_text(app.screen), list(seen), sd.is_save_dialog(app.screen), \
            sorted(sd.workarea_listing(app.workarea) - listing0)

    before, after, seen, still, new = _run(base, scenario)
    assert EMPTY[0] not in before, before
    assert all(t in after for t in EMPTY), after
    assert seen == [] and still and new == [], (seen, still, new)


async def _post_alt_s(app) -> None:
    """``alt+s`` as the terminal sends it (``character="s"``; Pilot builds
    ``character=None``), posted to the app (S6-3, A9b-01)."""
    app.post_message(events.Key("alt+s", "s"))


@pytest.mark.parametrize("trigger", ["alt+s", "save_ok", "enter", "posted_alt_s"])
def test_tc_b100_49_confirming_save_closes_and_saves(tmp_path: Path, trigger: str) -> None:
    """LLR-175.3c, HLR-175a, S6-1, S6-3, B11-63 (4 of 4): F-fresh, ``fresh1``
    typed and its summary painted, then ``alt+s``, a click on ``#save_ok``,
    ``enter`` in ``#project_name``, or a posted ``alt+s`` key with
    ``character="s"`` (4 fresh apps) → 1 dismiss with the payload naming
    ``fresh1`` and 1 folder ``fresh1`` holding ``firmware.s19`` and
    ``project.json``; the field never receives the ``s``.

    Why: ruling Q8 — every shown confirm route saves, behind the same
    checks. Negative control: code read on the 9a tree: no ``BINDINGS`` and
    no ``on_input_submitted`` → ``alt+s`` and ``enter`` save nothing → RED;
    a binding without ``priority=True`` types ``s`` into the field → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "fresh1", "fresh1", "new folder")
        if trigger == "alt+s":
            await pilot.press("alt+s")
        elif trigger == "save_ok":
            assert await pilot.click("#save_ok")
        elif trigger == "enter":
            app.screen.set_focus(sd.name_input(app.screen))
            await _settle(pilot, 2)
            await pilot.press("enter")
        else:
            await _post_alt_s(app)
        await sd.wait_for(pilot, lambda: (app.workarea / "fresh1" / "project.json").is_file(), "the save")
        await _settle(pilot, 6)
        files = sorted(p.name for p in (app.workarea / "fresh1").iterdir())
        return [None if p is None else p.project_name for p in seen], files, len(app.screen_stack)

    names, files, depth = _run(base, scenario)
    assert names == ["fresh1"], names
    assert files == ["firmware.s19", "project.json"], files
    assert depth == 1


@pytest.mark.parametrize("route", ["ctrl+s", "palette"])
def test_tc_b100_49_dialog_opens_with_the_focus_in_the_name_field(tmp_path: Path, route: str) -> None:
    """LLR-175.3d, HLR-175f, S4-4 (2 of 2): ``ctrl+s`` and the palette entry
    ``save_project`` (dispatched by name, as the command bar does) → 1
    dialog (stack depth 2) and ``app.focused.id == "project_name"``.

    Negative control: executed on the 9a tree (P11-2): ``focused at open:
    OsClipboardInput project_parent_path`` → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        if route == "ctrl+s":
            await pilot.press("ctrl+s")
        else:
            await app.run_action("save_project")
        await sd.wait_for(pilot, lambda: sd.is_save_dialog(app.screen), "the Save dialog")
        await _settle(pilot, 6)
        return len(app.screen_stack), _focused_id(app)

    assert _run(base, scenario) == (2, "project_name")


def test_tc_b100_49_plain_letters_stay_in_the_name_field(tmp_path: Path) -> None:
    """LLR-175.3e, S1-5 (1 of 1): with the focus as the dialog opens it,
    ``s``, ``q``, ``l``, ``p``, ``v``, ``y`` (letters the app binds on the
    main screen) → ``#project_name`` holds ``sqlpvy``, the stack depth
    stays 2, 0 status lines added.

    Negative control: a plain ``s`` bound to the save action → the field
    misses ``s`` and the dialog closes → RED (declared: on the 9a tree the
    modal already blocks the app's letters; the base RED here is the focus,
    which opens in the parent field)."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        mark = len(log.messages)
        await pilot.press("s", "q", "l", "p", "v", "y")
        await _settle(pilot, 6)
        return sd.name_input(app.screen).value, len(app.screen_stack), log.since(mark)

    value, depth, lines = _run(base, scenario)
    assert value == "sqlpvy", value
    assert depth == 2 and lines == [], (depth, lines)


def test_tc_b100_49_save_during_a_refusal_keeps_the_dialog_and_save_focusable(tmp_path: Path) -> None:
    """LLR-175.3f, VS-PC-2, S6-5, B11-61 (1 of 1): a disguised clash ``a b``
    (``ab`` saved, ``P2`` open), then ``alt+s``, then ``tab`` to
    ``#save_ok`` and ``enter`` → 0 dismisses; ``#save_ok.can_focus`` is true
    and it gains the focus (never disabled); the pair painted after each
    press; 0 new paths.

    Negative control: ``#save_ok`` disabled during a refusal → it cannot
    gain the focus → RED; the refused payload dismissed → 1 dismiss →
    RED."""
    base = tmp_path / "app"
    ctx = _prep_clash(tmp_path, base)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _setup_open_p2(app, pilot, ctx)
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "a b", *CLASH)
        await pilot.press("alt+s")
        await _settle(pilot, 6)
        after_alt = sd.where_text(app.screen)
        for _ in range(6):
            if _focused_id(app) == "save_ok":
                break
            await pilot.press("tab")
            await _settle(pilot, 2)
        button = app.screen.query_one("#save_ok")
        state = (_focused_id(app), button.can_focus, button.disabled)
        await pilot.press("enter")
        await _settle(pilot, 8)
        return after_alt, state, sd.where_text(app.screen), list(seen), sd.is_save_dialog(app.screen), \
            sorted(sd.workarea_listing(app.workarea) - listing0)

    after_alt, state, after_enter, seen, still, new = _run(base, scenario)
    assert all(t in after_alt for t in CLASH), after_alt
    assert state == ("save_ok", True, False), state
    assert all(t in after_enter for t in CLASH), after_enter
    assert seen == [] and still and new == [], (seen, still, new)


def test_tc_b100_49_priority_keys_are_inert_while_the_dialog_is_open(tmp_path: Path) -> None:
    """LLR-175.3g, B11-07, B11-08, B11-09 (4 of 4 keys, whole stack, no
    over-reach): with the dialog open, ``ctrl+l`` → stack depth 2, 0 Load
    dialogs; ``ctrl+s`` → depth 2, 0 second Save dialogs; ``ctrl+k`` → the
    focus stays inside the dialog and the main screen's command-bar palette
    stays closed; ``ctrl+d`` → the ``#workspace_body`` density unchanged.
    ``ctrl+p`` over the dialog (the command palette opens over it), then
    ``ctrl+s`` → 0 Save pushes, ``ctrl+l`` → 0 Load dialogs (the guard reads
    the whole screen stack). After ``escape``: ``ctrl+d`` cycles the
    density once and ``ctrl+s`` opens 1 dialog.

    Why: the app's priority keys reach through a modal (Textual 8.2.8); a
    Load or a second Save stacked over the dialog acts on the session the
    engineer is saving. Negative control: executed on the 9a tree (P11-2,
    P11-3): ``ctrl+l over Save dialog -> stack: ['Screen',
    'SaveProjectScreen', 'LoadFileScreen']``, ``ctrl+d`` changes the density
    → RED; a stack-top guard → ``ctrl+s`` after ``ctrl+p`` pushes a second
    Save dialog → RED. Declared: ``ctrl+k`` / ``ctrl+d`` then reach the
    name field's own line-editing bindings."""
    from s19_app.tui.command_bar import CommandBar

    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await _home(pilot)
        await sd.open_save_dialog(pilot, app)
        out = {}
        await pilot.press("ctrl+l")
        await _settle(pilot)
        out["ctrl+l"] = _stack(app)
        await pilot.press("ctrl+s")
        await _settle(pilot)
        out["ctrl+s"] = _stack(app)
        await pilot.press("ctrl+k")
        await _settle(pilot)
        focused = app.focused
        out["ctrl+k inside"] = focused is not None and sd.is_save_dialog(focused.screen)
        out["ctrl+k palette open"] = app.screen_stack[0].query_one(CommandBar).palette_is_open
        density = _density(app)
        await pilot.press("ctrl+d")
        await _settle(pilot)
        out["ctrl+d same"] = _density(app) == density
        await pilot.press("ctrl+p")
        await _settle(pilot, 10)
        out["palette"] = _stack(app)
        await pilot.press("ctrl+s")
        await _settle(pilot, 10)
        await pilot.press("ctrl+l")
        await _settle(pilot, 10)
        out["after palette"] = _stack(app)
        await pilot.press("escape")
        await _settle(pilot, 8)
        for _ in range(4):
            if len(app.screen_stack) == 1:
                break
            await pilot.press("escape")
            await _settle(pilot, 8)
        out["closed"] = _stack(app)
        if len(app.screen_stack) > 1:
            return out
        density = _density(app)
        await pilot.press("ctrl+d")
        await _settle(pilot)
        out["closed ctrl+d cycles"] = _density(app) != density
        await pilot.press("ctrl+s")
        await sd.wait_for(pilot, lambda: sd.is_save_dialog(app.screen), "the Save dialog after close")
        out["closed ctrl+s"] = _stack(app)
        return out

    out = _run(base, scenario)
    assert len(out["ctrl+l"]) == 2 and out["ctrl+l"][-1] == "SaveProjectScreen", out
    assert len(out["ctrl+s"]) == 2 and out["ctrl+s"].count("SaveProjectScreen") == 1, out
    assert out["ctrl+k inside"] is True and out["ctrl+k palette open"] is False, out
    assert out["ctrl+d same"] is True, out
    assert out["palette"][-1] == "CommandPalette", out
    assert out["after palette"].count("SaveProjectScreen") == 1, out
    assert not any("Load" in name for name in out["after palette"]), out
    assert len(out["closed"]) == 1, out
    assert out["closed ctrl+d cycles"] is True, out
    assert len(out["closed ctrl+s"]) == 2 and out["closed ctrl+s"][-1] == "SaveProjectScreen", out


def test_tc_b100_49_open_project_name_is_offered_selected(tmp_path: Path) -> None:
    """LLR-175.3h, S4-2, S4-3, B11-05 (3 of 3): F-open (``P`` open) →
    ``#project_name`` holds ``P``, the selection covers all of it, and
    ``#save_where`` says ``updates the open project``; typing ``x`` → the
    field holds ``x`` (the selection is replaced); F-fresh → the field is
    empty.

    Why: pc_B (ruling Q7) — re-saving the open project is the common case.
    Negative control: code read on the 9a tree: ``on_mount`` fills only
    ``#project_parent_path`` and the name starts empty → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    src = _sources(tmp_path)

    async def open_scene(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project")
        field = sd.name_input(app.screen)
        selection = (field.selection.start, field.selection.end) if hasattr(field, "selection") else None
        value = field.value
        where = sd.where_text(app.screen)
        await pilot.press("x")
        await _settle(pilot, 4)
        return value, selection, where, field.value, _focused_id(app)

    async def fresh_scene(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        return sd.name_input(app.screen).value

    value, selection, where, typed, focused = _run(base, open_scene)
    assert value == "P", value
    assert selection is not None and sorted(selection) == [0, 1], selection
    assert _where_line_for_text(where, "P", "updates the open project"), where
    assert typed == "x" and focused == "project_name", (typed, focused)
    assert _run(tmp_path / "fresh", fresh_scene) == ""


def test_tc_b100_49_buttons_show_their_keys_and_the_keys_work(tmp_path: Path) -> None:
    """LLR-175.3i, S2-3 (2 of 2): ``#save_ok`` is labelled ``Save (alt+s)``
    and ``#save_cancel`` ``Cancel (esc)``; ``alt+s`` performs Save (the
    folder is created) and ``escape`` performs Cancel (the callback gets
    ``None``) — every shown key verified by pressing it.

    Negative control: code read on the 9a tree: the labels are ``Save`` and
    ``Cancel`` → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        labels = (str(app.screen.query_one("#save_ok").label), str(app.screen.query_one("#save_cancel").label))
        await pilot.press("escape")
        await _settle(pilot, 8)
        cancelled = list(seen)
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "fresh1", "fresh1", "new folder")
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: (app.workarea / "fresh1").is_dir(), "the save by alt+s")
        return labels, cancelled

    labels, cancelled = _run(base, scenario)
    assert labels == ("Save (alt+s)", "Cancel (esc)"), labels
    assert cancelled == [None], cancelled


@pytest.mark.parametrize("route", ["ctrl+s", "palette"])
def test_tc_b100_49_nothing_loaded_opens_no_dialog(tmp_path: Path, route: str) -> None:
    """LLR-175.3j, B11-02 (2 of 2): a fresh app with nothing loaded,
    ``ctrl+s`` and the palette entry ``save_project`` → stack depth 1, 1
    status line holding ``Nothing to save`` and ``load a data file or A2L
    first``, 0 new paths.

    Why: ruling Q9 — a dialog that can only refuse is removed. Negative
    control: executed on the 9a tree (P11-2, nothing loaded): ``open ctrl+s
    -> stack: ['Screen', 'SaveProjectScreen']`` → RED."""
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        listing0 = sd.workarea_listing(app.workarea)
        mark = len(log.messages)
        if route == "ctrl+s":
            await pilot.press("ctrl+s")
        else:
            await app.run_action("save_project")
        await _settle(pilot, 10)
        return len(app.screen_stack), _lines_with(log.since(mark), *NOTHING), \
            sorted(sd.workarea_listing(app.workarea) - listing0)

    depth, lines, new = _run(base, scenario)
    assert depth == 1, depth
    assert len(lines) == 1, lines
    assert new == []


def test_tc_b100_49_an_a2l_alone_opens_the_dialog(tmp_path: Path) -> None:
    """LLR-175.3j boundary, B11-03: only ``firmware.a2l`` loaded → ``ctrl+s``
    → stack depth 2, the top a Save dialog, and its summary paints no image
    row (LLR-175.4c empty boundary: the plan's ``image`` is empty).

    Negative control: a guard reading ``self.current_file`` alone → 0
    dialogs → RED. RED (base): no summary."""
    base = tmp_path / "app"
    src = _sources(tmp_path, CASE01_DIR, "firmware.a2l")

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.a2l")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "a2only", "a2only", "new folder")
        return len(app.screen_stack), sd.summary_rows(app.screen), app.screen.plan

    depth, rows, plan = _run(base, scenario)
    assert depth == 2
    assert plan is not None and plan.image == "", plan
    assert not any("unchanged copy" in r or "change entr" in r for r in rows), rows
    assert any("firmware.a2l" in r for r in rows), rows


# ---------------------------------------------------------------------------
# The dialog alone, fed by recording fakes of the two app callables (the
# fixed S-a / S-b seam: ``preview(text) -> SavePreview``, ``confirm(text,
# plan) -> Optional[SavePreview]``). The fakes stand for G-B's composed text;
# the dialog paints whatever it gets (proto-11-dialog "Fixtures").
# ---------------------------------------------------------------------------


class _Fakes:
    """``F`` / ``C`` of proto-11-dialog: a preview fake that records each
    call and its time, and a confirm fake that records ``(name, plan)``."""

    def __init__(self, workarea: Path, refuse=None, slow_first: float = 0.0, post_on_first=None):
        self.workarea = workarea
        self.refuse = dict(refuse or {})
        self.preview_calls: list = []
        self.preview_times: list = []
        self.confirm_calls: list = []
        self.plans: dict = {}
        self.slow_first = slow_first
        self.post_on_first = post_on_first
        self.confirm_override = None
        #: name -> a ``SavePreview`` the preview fake returns for that name
        self.custom: dict = {}

    @staticmethod
    def types():
        from s19_app.tui.screens import SavePreview
        from s19_app.tui.services.project_gather_service import SavePlan

        return SavePreview, SavePlan

    def plan(self, name: str):
        _, SavePlan = self.types()
        if name not in self.plans:
            self.plans[name] = SavePlan(target=self.workarea / name, target_kind="new", rows=(),
                                        image="firmware.s19 unchanged copy", manifest_keys=())
        return self.plans[name]

    def pv(self, name: str):
        SavePreview, _ = self.types()
        return SavePreview(where=((f"{name}   new folder", "info"),),
                           rows=(f"new  {name}/firmware.s19", f"new  {name}/project.json"),
                           plan=self.plan(name), refused=False)

    def refused(self, line: str):
        SavePreview, _ = self.types()
        return SavePreview(where=((line, "refusal"),), rows=(), plan=None, refused=True)

    def preview(self, text: str):
        self.preview_calls.append(text)
        self.preview_times.append(time.monotonic())
        if len(self.preview_calls) == 1:
            if self.post_on_first is not None:
                self.post_on_first()
            if self.slow_first:
                time.sleep(self.slow_first)
        SavePreview, _ = self.types()
        if text in self.custom:
            return self.custom[text]
        if not text.strip():
            return SavePreview(where=(), rows=(), plan=None, refused=False)
        if text in self.refuse:
            return self.refused(self.refuse[text])
        return self.pv(text)

    def confirm(self, text: str, plan):
        self.confirm_calls.append((text, plan))
        if self.confirm_override is not None:
            return self.confirm_override(text, plan)
        SavePreview, SavePlan = self.types()
        if not text.strip():
            return self.refused("name is empty — type a project name")
        if text in self.refuse:
            return self.refused(self.refuse[text])
        if plan is not None and plan is self.plans.get(text):
            return None
        self.plans.pop(text, None)
        fresh = self.pv(text)
        return SavePreview(where=fresh.where + (("the summary changed — check it, then save again", "refusal"),),
                           rows=fresh.rows, plan=fresh.plan, refused=False)


def _dialog(fakes: _Fakes, **kwargs):
    from s19_app.tui.screens import SaveProjectScreen

    return SaveProjectScreen(preview=fakes.preview, confirm=fakes.confirm, **kwargs)


def _dialog_run(tmp_path: Path, scene, size: tuple = SIZE, **fake_kwargs):
    """Push the dialog (with fakes) on a fresh app and run ``scene(app,
    pilot, screen, fakes, cb)``."""
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        fakes = _Fakes(app.workarea, **fake_kwargs)
        cb: list = []
        screen = await scene_setup(app, pilot, fakes, cb)
        return await scene(app, pilot, screen, fakes, cb)

    async def scene_setup(app, pilot, fakes, cb):
        kwargs = getattr(scene, "dialog_kwargs", {})
        screen = _dialog(fakes, **kwargs)
        app.push_screen(screen, cb.append)
        await sd.wait_for(pilot, lambda: app.screen is screen, "the pushed dialog")
        await sd.wait_recompute(pilot)
        return screen

    return _run(base, scenario, size=size)


def test_tc_b100_49_constructor_is_keyword_only_and_computes_nothing(tmp_path: Path) -> None:
    """HLR-175f, LLR-175.3c, LLR-175.3d, LLR-175.5b, LLR-175.4k, S1-1 …
    S1-4: ``SaveProjectScreen.__init__`` takes ``self, *, preview, confirm,
    initial_name=None, variants=None, candidate_files=None`` (the old
    positional ``default_parent`` form raises ``TypeError``); a constructed,
    not pushed, dialog has called neither callable and ``plan is None``;
    ``variants`` / ``candidate_files`` stay readable attributes; the class
    holds no ``DEFAULT_CSS`` (TC-033), ``AUTO_FOCUS == "#project_name"`` and
    the bindings ``escape → cancel`` and ``alt+s → save`` with
    ``priority=True``.

    Why: a dialog that computed the plan before its first frame would hold
    the app's image decision before the engineer sees the dialog
    (LLR-175.5b); a non-priority ``alt+s`` loses to the focused field
    (A9b-01). Negative control: base signature ``(self, default_parent,
    variants=None, candidate_files=None)`` → RED."""
    import inspect

    from s19_app.tui.screens import SaveProjectScreen

    params = inspect.signature(SaveProjectScreen.__init__).parameters
    assert list(params) == ["self", "preview", "confirm", "initial_name", "variants", "candidate_files"], list(params)
    assert all(params[n].kind is inspect.Parameter.KEYWORD_ONLY for n in list(params)[1:]), params
    with pytest.raises(TypeError):
        SaveProjectScreen(tmp_path)  # the retired positional form
    fakes = _Fakes(tmp_path)
    screen = _dialog(fakes, variants=[("a", "a.s19"), ("b", "b.s19")], candidate_files=["doc.json", "extra.json"])
    assert fakes.preview_calls == [] and fakes.confirm_calls == []
    assert screen.plan is None
    assert screen.variants == [("a", "a.s19"), ("b", "b.s19")]
    assert screen.candidate_files == ["doc.json", "extra.json"]
    assert SaveProjectScreen.__dict__.get("DEFAULT_CSS", "") == ""
    assert SaveProjectScreen.AUTO_FOCUS == "#project_name"
    bindings = [(b.key, b.action, b.priority) for b in SaveProjectScreen.BINDINGS]
    assert ("escape", "cancel", False) in bindings and ("alt+s", "save", True) in bindings, bindings


def test_tc_b100_65_plan_is_read_only(tmp_path: Path) -> None:
    """LLR-175.4k, S8-1, S8-3, B11-64 (3 errors + ``None`` + the refused
    plan): ``plan`` is ``None`` before the first paint; after a paint,
    assigning ``screen.plan`` raises ``AttributeError``, assigning
    ``plan.rows`` raises ``FrozenInstanceError`` and appending to
    ``plan.rows`` raises ``AttributeError`` (a tuple); a refused preview
    that carries a refused plan leaves ``plan`` that refused plan (0 rows).

    Why: the router executes the object the dialog painted (Q-2); a reader
    that could change it would execute rows nobody saw. Negative control:
    ``plan`` a plain attribute → the assignment succeeds → RED."""

    async def scene(app, pilot, screen, fakes, cb):
        out = {"before": None}
        await sd.type_name(pilot, app, "x")
        await sd.wait_painted(pilot, app, "x   new folder")
        plan = screen.plan
        errors = []
        try:
            screen.plan = fakes.plan("y")
        except AttributeError:
            errors.append("screen.plan")
        try:
            plan.rows = ()
        except dataclasses.FrozenInstanceError:
            errors.append("plan.rows =")
        try:
            plan.rows.append(1)
        except AttributeError:
            errors.append("append")
        out["errors"] = errors
        out["is_painted"] = plan is fakes.plans["x"]
        SavePreview, SavePlan = fakes.types()
        refused_plan = SavePlan(target=app.workarea / "Q", target_kind="new", rows=(), image="",
                                manifest_keys=(), refusal="too many files to copy — move files out")
        refusal = SavePreview(where=(("too many files to copy — move files out of the project, then save again",
                                      "refusal"),), rows=(), plan=refused_plan, refused=True)
        fakes.custom["Q"] = refusal
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "too many files to copy")
        out["refused_plan"] = screen.plan is refused_plan and len(screen.plan.rows) == 0
        return out

    fakes_probe = _Fakes(tmp_path)
    assert _dialog(fakes_probe).plan is None
    out = _dialog_run(tmp_path, scene)
    assert out["errors"] == ["screen.plan", "plan.rows =", "append"], out
    assert out["is_painted"] is True
    assert out["refused_plan"] is True, out


def test_tc_b100_65_paint_rows_verbatim_in_order_and_refusal_empties(tmp_path: Path) -> None:
    """LLR-175.4 (G-A share), LLR-175.4c … .4f (rows painted verbatim),
    LLR-175.1i (G-A share), S9-1, S9-4, S9-6, S9-8, C2-1: a preview's rows
    are painted one widget per row, exactly and in the given order (a
    ``keep`` row, the image / pending / links / active-variant rows); a
    refused preview empties the summary, paints its line with the class
    ``refusal`` in bold, and leaves ``plan`` ``None``; a where line of kind
    ``refusal`` sets the class even when ``refused`` is false.

    Negative control: a painter that drops ``keep`` rows → 2 rows → RED; a
    painter that keeps stale rows under a refusal → RED; one that sorts the
    rows → RED."""
    rows = ("keep  ab/firmware.s19", "new  ab/firmware_1.s19",
            "firmware.s19 + 1 change entry, 0 applied by this save", "unsaved changes in firmware.s19",
            "links or junctions not copied: flows/j1", "active variant firmware_1 (was firmware)",
            "rewrite  ab/project.json")

    async def scene(app, pilot, screen, fakes, cb):
        SavePreview, _ = fakes.types()
        plan_ab = fakes.plan("ab")
        out = {}
        fakes.refuse["m2"] = "target already has a MAC file (m.mac) — choose another name"
        good = SavePreview(where=(("ab   merges into an existing project", "info"),), rows=rows, plan=plan_ab,
                           refused=False)
        fakes.custom["ab"] = good
        await sd.type_name(pilot, app, "ab")
        await sd.wait_painted(pilot, app, "merges into an existing project")
        out["rows"] = sd.summary_rows(app.screen)
        out["plan"] = screen.plan is plan_ab
        out["class_info"] = sd.where_widget(app.screen).has_class("refusal")
        await sd.type_name(pilot, app, "m2")
        await sd.wait_painted(pilot, app, "already has a MAC file")
        await _settle(pilot, 6)
        widget = sd.where_widget(app.screen)
        out["refused_rows"] = sd.summary_rows(app.screen)
        out["refused_plan"] = screen.plan
        out["refused_class"] = widget.has_class("refusal")
        out["bold"] = "bold" in str(widget.styles.text_style)
        return out

    out = _dialog_run(tmp_path, scene)
    assert out["rows"] == list(rows), out
    assert out["plan"] is True and out["class_info"] is False, out
    assert out["refused_rows"] == [] and out["refused_plan"] is None, out
    assert out["refused_class"] is True and out["bold"] is True, out


def test_tc_b100_65_recompute_is_a_150ms_debounce(tmp_path: Path) -> None:
    """LLR-175.5a, S5-1, S5-3, S5-4 (3 arms): 20 keys ``a`` … ``t`` posted
    10 ms apart → ``preview`` is called at most 3 times (the debounce
    groups them), the field holds the 20 letters after the last key, and
    the plan for ``abcdefghijklmnopqrst`` is painted within 300 ms of the
    last key; one key ``q`` after a quiet period → 1 call, about 150 ms
    later (not inside the key handler); two bursts ``ab`` and ``cd`` with a
    400 ms pause → 2 calls, ``ab`` then ``abcd``.

    Why: a recompute per keystroke re-plans the save 20 times while the
    engineer types (LLR-175.5a). Negative control: a recompute per
    keystroke → 20 calls → RED; no trailing recompute → the final name is
    never painted → RED."""

    async def scene(app, pilot, screen, fakes, cb):
        out = {}
        field = sd.name_input(screen)
        screen.set_focus(field)
        await _settle(pilot, 2)
        start = len(fakes.preview_calls)
        for ch in "abcdefghijklmnopqrst":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.01)
        last_key = time.monotonic()
        out["echo"] = None
        await sd.wait_for(pilot, lambda: field.value == "abcdefghijklmnopqrst", "the 20 letters echoed", 2.0)
        await sd.wait_for(pilot, lambda: "abcdefghijklmnopqrst   new folder" in sd.where_text(screen),
                          "the final paint", 2.0)
        out["final_after"] = time.monotonic() - last_key
        out["burst_calls"] = fakes.preview_calls[start:]
        await asyncio.sleep(0.5)
        await sd.clear_name(pilot, app)
        await asyncio.sleep(0.5)
        start = len(fakes.preview_calls)
        app.post_message(events.Key("q", "q"))
        key_at = time.monotonic()
        await sd.wait_for(pilot, lambda: len(fakes.preview_calls) > start, "the q recompute", 2.0)
        out["q_delay"] = fakes.preview_times[start] - key_at
        out["q_calls"] = fakes.preview_calls[start:]
        await asyncio.sleep(0.5)
        await sd.clear_name(pilot, app)
        await asyncio.sleep(0.5)
        start = len(fakes.preview_calls)
        for ch in "ab":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.4)
        for ch in "cd":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.5)
        await _settle(pilot, 4)
        out["two_bursts"] = fakes.preview_calls[start:]
        return out

    out = _dialog_run(tmp_path, scene)
    assert 1 <= len(out["burst_calls"]) <= 3, out
    assert out["burst_calls"][-1] == "abcdefghijklmnopqrst", out
    assert out["final_after"] <= 0.3, out
    assert out["q_calls"] == ["q"], out
    assert 0.1 <= out["q_delay"] <= 0.5, out
    assert out["two_bursts"] == ["ab", "abcd"], out


def test_tc_b100_65_first_preview_after_the_first_frame_and_once_while_idle(tmp_path: Path) -> None:
    """LLR-175.5b (G-A share), LLR-175.5 (G-A share), S4-1, S4-5: pushed with
    ``initial_name="P"`` → ``preview`` is called exactly once by the time
    the first frame settles, with ``"P"``; at that call the dialog is the
    active screen and ``#project_name`` is laid out (width > 0); then 1 s
    with no key → still 1 call in total.

    Negative control: the first preview called in ``__init__`` / ``compose``
    → at that call the dialog is not the active screen → RED; a second call
    from ``on_mount`` → 2 calls at open → RED."""
    seen: dict = {}
    base = tmp_path

    async def probe_scene(app, pilot, log):
        fakes = _Fakes(app.workarea)
        original = fakes.preview

        def _preview(text):
            if "first" not in seen:
                field = app.screen.query("#project_name")
                seen["first"] = (app.screen is screen, field.first().region.width if len(field) else 0, text)
            return original(text)

        from s19_app.tui.screens import SaveProjectScreen

        screen = SaveProjectScreen(preview=_preview, confirm=fakes.confirm, initial_name="P")
        app.push_screen(screen)
        await sd.wait_for(pilot, lambda: len(fakes.preview_calls) >= 1, "the first preview", 3.0)
        await asyncio.sleep(1.0)
        await _settle(pilot, 4)
        return list(fakes.preview_calls)

    calls = _run(base / "probe", probe_scene)
    assert calls == ["P"], calls
    is_active, width, text = seen["first"]
    assert is_active is True and width > 0 and text == "P", seen


def test_tc_b100_65_save_before_the_preview_is_shown_repaints(tmp_path: Path) -> None:
    """LLR-175.4b, S11-04, S6-12 (1 of 1): a preview fake that queues the
    Save action on the dialog (``call_next``) and then sleeps 300 ms on its
    first call (so the Save runs right after the first paint, before the
    frame that shows it) →
    ``confirm`` is called with ``(name, None)``, 0 dismisses, and
    ``#save_where`` paints ``the summary changed`` / ``check it, then save
    again``; a second ``alt+s`` → 1 dismiss.

    Why: a Save that arrives before the painted preview was refreshed would
    save a plan nobody saw (R-PC). Negative control: the dialog passes its
    plan regardless of whether it was shown → ``confirm`` sees the plan
    equal and returns ``None`` → 1 dismiss of a plan nobody saw → RED."""
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        cb: list = []
        # E4 integration: an ``alt+s`` posted to the app here is processed
        # after the refresh in Textual 8.2.8 (probe: post, paint, mark,
        # save with shown True), so the Save is queued on the dialog itself.
        fakes = _Fakes(app.workarea, slow_first=0.3,
                       post_on_first=lambda: screen.call_next(screen.action_save))
        screen = _dialog(fakes, initial_name="fresh1")
        app.push_screen(screen, cb.append)
        await sd.wait_for(pilot, lambda: len(fakes.confirm_calls) >= 1, "the first confirm", 4.0)
        await sd.wait_recompute(pilot)
        first = (fakes.confirm_calls[0][0], fakes.confirm_calls[0][1], list(cb), sd.where_text(screen))
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return first, list(cb)

    (name, plan, cb_first, where), cb_after = _run(base, scenario)
    assert name == "fresh1" and plan is None, (name, plan)
    assert cb_first == [], cb_first
    assert all(t in where for t in CHANGED), where
    assert len(cb_after) == 1 and cb_after[0] is not None and cb_after[0].project_name == "fresh1", cb_after


def test_tc_b100_65_out_of_date_save_repaints_and_stops_the_timer(tmp_path: Path) -> None:
    """LLR-175.4b (G-A share), K11, S6-7, S6-8, S6-11: ``abc`` typed 10 ms
    apart and ``alt+s`` 20 ms after the last key (the recompute pending) →
    ``confirm`` is called once with ``"abc"``, 0 dismisses, ``#save_where``
    paints ``abc   new folder`` and ``the summary changed — check it, then
    save again``; 400 ms later the same text (the pending recompute was
    dropped); a second ``alt+s`` → 1 dismiss whose ``plan`` is the
    repainted plan object (``screen.plan`` after the repaint).

    Negative control: the repaint leaves the trailing timer running → the
    pair is erased 150 ms later → RED; the dialog dismisses with a freshly
    computed plan → 1 dismiss, 0 token pairs → RED."""

    async def scene(app, pilot, screen, fakes, cb):
        screen.set_focus(sd.name_input(screen))
        await asyncio.sleep(0.3)
        for ch in "abc":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.02)
        await pilot.press("alt+s")
        await _settle(pilot, 2)
        out = {"confirm": [c[0] for c in fakes.confirm_calls], "cb": list(cb), "where": sd.where_text(screen)}
        await asyncio.sleep(0.4)
        await _settle(pilot, 4)
        out["later"] = sd.where_text(screen)
        repainted = screen.plan
        await pilot.press("alt+s")
        await _settle(pilot, 6)
        out["cb2"] = list(cb)
        out["identity"] = len(cb) == 1 and cb[0] is not None and cb[0].plan is repainted
        return out

    out = _dialog_run(tmp_path, scene)
    assert out["confirm"] == ["abc"], out
    assert out["cb"] == [], out
    assert "abc   new folder" in out["where"] and all(t in out["where"] for t in CHANGED), out
    assert all(t in out["later"] for t in CHANGED), out
    assert out["identity"] is True, out


def test_tc_b100_49_escape_with_a_recompute_pending_and_double_close(tmp_path: Path) -> None:
    """HLR-175c, S5-7, S7-4 (interfaces S-b ``_dismissed``): ``ab`` typed and
    ``escape`` 20 ms later (the recompute pending) → the callback gets one
    ``None`` and ``preview`` is not called in the next 400 ms; two posted
    ``escape`` keys in one tick → one dismiss, the stack the main screen
    alone, no exception.

    Negative control: the close leaves the timer running → a ``preview``
    call on an unmounted dialog → RED; an unguarded second close →
    ``ScreenStackError`` → RED."""

    async def scene(app, pilot, screen, fakes, cb):
        screen.set_focus(sd.name_input(screen))
        await _settle(pilot, 2)
        start = len(fakes.preview_calls)
        for ch in "ab":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.005)
        await asyncio.sleep(0.02)
        app.post_message(events.Key("escape", None))
        app.post_message(events.Key("escape", None))
        await asyncio.sleep(0.4)
        await _settle(pilot, 6)
        return list(cb), fakes.preview_calls[start:], _stack(app), app.is_running

    cb, calls, stack, running = _dialog_run(tmp_path, scene)
    assert cb == [None], cb
    assert calls == [], calls
    assert stack == ["Screen"] and running, stack


def test_tc_b100_65_assignment_rows_literal_and_in_the_tab_order(tmp_path: Path) -> None:
    """LLR-175.4g (G-A share), LLR-175.4i, Q4, S2-5, S2-7, S6-10: with 2
    variants and 2 candidate files, ``tab`` × 6 from ``#project_name`` →
    ``save_summary``, ``assign_batch``, ``assign_0``, ``assign_1``,
    ``save_ok``, ``save_cancel``; a variant labelled ``[b]x`` paints
    ``Assign files to '[b]x':`` with 0 spans and the option ``[i]doc.json``
    paints literally; the selections reach the payload unchanged
    (``batch``, ``assignments`` keyed by variant id).

    Negative control: the assignment rows composed after the buttons →
    ``save_ok`` comes 2nd → RED; a markup label → ``Assign files to 'x':``
    with 1 span → RED."""
    from textual.widgets import Label, SelectionList

    async def scene(app, pilot, screen, fakes, cb):
        out = {}
        screen.set_focus(sd.name_input(screen))
        await _settle(pilot, 2)
        order = []
        for _ in range(6):
            await pilot.press("tab")
            await _settle(pilot, 2)
            order.append(_focused_id(app))
        out["order"] = order
        labels = [sd.plain(w) for w in screen.query(Label)]
        out["label"] = next((t for t in labels if t.startswith("Assign files to")), "")
        label_widget = next((w for w in screen.query(Label) if sd.plain(w).startswith("Assign files to '[b]")), None)
        out["label_spans"] = sd.spans(label_widget) if label_widget is not None else -1
        batch = screen.query_one("#assign_batch", SelectionList)
        out["option"] = str(batch.get_option_at_index(0).prompt)
        batch.select("[i]doc.json")
        screen.query_one("#assign_1", SelectionList).select("extra.json")
        await sd.type_name(pilot, app, "fresh1")
        await sd.wait_painted(pilot, app, "fresh1   new folder")
        await pilot.press("alt+s")
        await _settle(pilot, 6)
        out["payload"] = (cb[0].batch, dict(cb[0].assignments)) if cb and cb[0] is not None else None
        return out

    scene.dialog_kwargs = {"variants": [("a", "a.s19"), ("b", "[b]x")], "candidate_files": ["[i]doc.json", "extra.json"]}
    out = _dialog_run(tmp_path, scene)
    assert out["order"] == ["save_summary", "assign_batch", "assign_0", "assign_1", "save_ok", "save_cancel"], out
    assert out["label_spans"] == 0, out
    assert out["option"] == "[i]doc.json", out
    assert out["payload"] == (("[i]doc.json",), {"b": ("extra.json",)}), out


# ---------------------------------------------------------------------------
# The 7 scenarios of AT-B100-21 / LLR-175.4 (fresh, pending patch, refused,
# files, document, merge, save-as), built by real saves (LED .42) and
# driven either through the shipped handlers (TC) or by keys (AT).
# ---------------------------------------------------------------------------

SCENARIOS = ["fresh", "pending", "refused", "files", "document", "merge", "saveas"]
SCENARIO_NAME = {"fresh": "fresh1", "pending": "P", "refused": "m2", "files": "P", "document": "doc1",
                 "merge": "ab", "saveas": "Q"}
SCENARIO_WAIT = {
    "fresh": ("fresh1", "new folder", "project.json"),
    "pending": ("updates the open project", "project.json", "unsaved changes"),
    "refused": SECOND_MAC,
    "files": ("updates the open project", "project.json"),
    "document": ("doc1", "new folder", "project.json"),
    "merge": ("merges into an existing project", "project.json"),
    "saveas": ("Q", "new folder", "project.json"),
}
#: B11-48: the rows each scenario paints, exactly (the composed text of the
#: G-B design; probe gb-plans S1–S9 for the plan rows they paint).
SCENARIO_ROWS = {
    "fresh": ["firmware.s19 unchanged copy", f"image firmware.s19 {DASH} new", f"project.json {DASH} new"],
    "pending": [
        "firmware.s19 + 1 change entry, 0 applied by this save",
        "unsaved changes in firmware.s19",
        f"image firmware.s19 → firmware_1.s19 {DASH} new",
        f"MAC firmware.mac {DASH} keep",
        f"document patches/changes.json {DASH} new",
        f"project.json {DASH} rewrite",
    ],
    "refused": [],
    "files": [
        "firmware.s19 unchanged copy",
        f"image firmware.s19 {DASH} keep",
        f"MAC firmware.mac {DASH} keep",
        f"A2L firmware.a2l {DASH} keep",
        f"project.json {DASH} rewrite",
    ],
    "document": [
        "firmware.s19 + 1 change entry, 1 applied by this save",
        f"image firmware.s19 {DASH} new",
        f"document patches/changes.json {DASH} new",
        f"project.json {DASH} new",
    ],
    "merge": [
        "firmware.s19 unchanged copy",
        f"image firmware.s19 → firmware_1.s19 {DASH} new",
        "active variant firmware_1 (before: firmware)",
        f"project.json {DASH} merge",
    ],
    "saveas": [
        "firmware.s19 unchanged copy",
        f"image firmware.s19 {DASH} new",
        f"folder flows/ (1 file) {DASH} new",
        f"folder patches/ (1 file) {DASH} new",
        f"folder reports/ (1 file) {DASH} new",
        f"project.json {DASH} new",
    ],
}


def _scenario_prep(key: str, tmp_path: Path, base: Path) -> dict:
    ctx = {"src": _sources(tmp_path, CASE01_DIR, "firmware.s19", "firmware.mac", "firmware.a2l",
                           folder=f"src_{key}_{base.parent.name}")}
    if key == "pending":
        projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.mac"))
    elif key == "refused":
        projects.save_case01_project(base, "P1", files=("firmware.s19", "firmware.mac"))
        m2 = projects.save_case01_project(base, "m2", files=("firmware.s19",))
        (m2 / "other.mac").write_bytes((CASE01_DIR / "firmware.mac").read_bytes())
    elif key == "files":
        projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.mac", "firmware.a2l"))
    elif key == "merge":
        other = _sources(tmp_path, CASE02_DIR, "firmware.s19", folder=f"src02_{base.parent.name}")
        _save_project_from(base, "ab", [other / "firmware.s19"])
    elif key == "saveas":
        projects.build_save_as_project(base, "P", sub_files=projects.AT09_FILES)
    return ctx


async def _scenario_setup(key: str, app, pilot, ctx: dict, by_keys: bool) -> None:
    load = _load_by_keys if by_keys else _load_direct
    open_project = _open_project_by_keys if by_keys else _open_project_direct
    if key in ("fresh", "document", "merge"):
        await load(pilot, app, ctx["src"] / "firmware.s19")
    if key == "document":
        if by_keys:
            await _add_entry_by_keys(pilot, app)
            await _home(pilot)
        else:
            _add_direct(app)
    if key == "pending":
        await open_project(pilot, app, "P")
        if by_keys:
            await _add_entry_by_keys(pilot, app)
            await _apply_by_keys(pilot, app)
        else:
            _add_direct(app)
            _apply_direct(app)
    if key == "refused":
        await open_project(pilot, app, "P1")
    if key in ("files", "saveas"):
        await open_project(pilot, app, "P")
    await _settle(pilot, 6)


def _scenario_paint(tmp_path: Path, key: str, *, by_keys: bool = False, save: bool = False, size: tuple = (220, 60),
                    commit_spy: bool = False):
    """Open the dialog in scenario ``key``, type its name, wait for its
    summary and read it; with ``save``, press ``alt+s`` and read the tree.
    Returns a dict of the readings."""
    base = tmp_path / "app"
    ctx = _scenario_prep(key, tmp_path, base)

    async def scenario(app, pilot, log):
        await _scenario_setup(key, app, pilot, ctx, by_keys)
        commits = _spy_method(app, "_commit_project_save") if commit_spy else None
        listing0 = sd.workarea_listing(app.workarea)
        before = sd.tree_digests(app.workarea)
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await sd.type_name(pilot, app, SCENARIO_NAME[key])
        # E4 integration: let the debounce for the typed name land first; a
        # prefilled name equal to the typed one already paints the same
        # tokens, and its plan object is replaced by the recompute.
        await sd.wait_recompute(pilot)
        await sd.wait_painted(pilot, app, *SCENARIO_WAIT[key], timeout=10.0)
        out = {"where": sd.where_text(screen), "rows": sd.summary_rows(screen), "plan": screen.plan,
               "spans": [sd.spans(w) for w in sd.summary_widgets(screen)] + [sd.spans(sd.where_widget(screen))]}
        if save:
            painted_plan = screen.plan
            mark = len(log.messages)
            await pilot.press("alt+s")
            if key == "refused":
                await _settle(pilot, 10)
                out["still_open"] = sd.is_save_dialog(app.screen)
            else:
                await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the dialog to close", 10.0)
                await sd.wait_for(
                    pilot,
                    lambda: any(m.startswith("Saved project to") or m.startswith(PREFIX) for m in log.since(mark)),
                    "the save outcome", 15.0,
                )
                await _settle(pilot, 6)
            out["messages"] = log.since(mark)
            out["painted_plan"] = painted_plan
            out["before"] = before
            out["after"] = sd.tree_digests(app.workarea)
            out["new_paths"] = sorted(sd.workarea_listing(app.workarea) - listing0)
            out["commits"] = commits
            out["workarea"] = app.workarea
        return out

    return _run(base, scenario, size=size)


def _target_digests(digests: dict, plan, workarea: Path) -> dict:
    """The part of a work-area digest map under the plan's target, keyed
    relative to the target."""
    prefix = Path(plan.target).resolve().relative_to(workarea.resolve()).as_posix().casefold() + "/"
    return {k[len(prefix):]: v for k, v in digests.items() if k.startswith(prefix)}


@pytest.mark.parametrize("key", SCENARIOS)
def test_tc_b100_65_summary_rows_equal_the_plan(tmp_path: Path, key: str) -> None:
    """LLR-175.4, HLR-175, B11-48, B11-55 (7 of 7, at 220 columns): the
    painted summary rows are exactly the scenario's rows (the image line,
    the pending line, one row per plan file row with its landing name — and
    its source name when the two differ — and its action word, one row per
    planned sub-folder with its file count, the merge's active-variant row,
    the ``project.json`` row), they equal the painted plan's ``rows`` and
    ``folders`` one for one by landing name and action word (0
    differences), the action words are only ``new``, ``keep``, ``merge`` and
    ``rewrite``, no row holds a line break, and every row and the target
    line have 0 markup spans. The refused scenario paints 0 rows.

    Why: R-PC — the operator's P-C note: an error here could invalidate,
    lose, overwrite or rename the engineer's work, so the dialog paints the
    one plan the save executes. Negative control: a painter that drops
    ``keep`` rows → the pending scenario loses ``MAC firmware.mac — keep``
    → RED; on base there is no summary (P11-2) → RED."""
    out = _scenario_paint(tmp_path, key)
    assert out["rows"] == SCENARIO_ROWS[key], out["rows"]
    assert not any("\n" in r for r in out["rows"]), out["rows"]
    assert set(out["spans"]) <= {0}, out["spans"]
    if key == "refused":
        assert out["plan"] is not None and out["plan"].rows == (), out["plan"]
        return
    _assert_rows_equal_plan(out["rows"], out["plan"])


def test_tc_b100_65_the_preview_and_the_dialog_list_nothing_themselves() -> None:
    """LLR-175.4 (AST arm): ``_save_dialog_preview`` and
    ``_compose_save_preview`` in ``app.py`` call no placement or listing
    function (``predict_placement``, ``place_into_workarea``, ``listdir``,
    ``iterdir``, ``list_projects``) — they read the one preparation's
    result.

    Why: a painter that lists the disk itself paints a second plan.
    Negative control: a painter that calls ``predict_placement`` → 1 site →
    RED. RED (base): the two functions do not exist."""
    tree = ast.parse((ROOT / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "S19TuiApp")
    methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
    banned = {"predict_placement", "place_into_workarea", "listdir", "iterdir", "list_projects", "scandir"}
    for name in ("_save_dialog_preview", "_compose_save_preview"):
        assert name in methods, f"{name} is missing"
        calls = [
            (n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", ""))
            for n in ast.walk(methods[name]) if isinstance(n, ast.Call)
        ]
        assert not (set(calls) & banned), (name, sorted(set(calls) & banned))


@pytest.mark.parametrize("key", SCENARIOS)
def test_tc_b100_65_save_executes_the_painted_plan(tmp_path: Path, key: str) -> None:
    """LLR-175.4a, HLR-175a, B11-13, B11-65 (7 of 7): ``alt+s`` → the commit
    step (a spy on ``_commit_project_save``) receives a prepared save whose
    ``plan`` IS the plan the dialog painted (``screen.plan``, identity), and
    a payload carrying that same object; the tree written under the target
    equals that plan by full path and action (``new`` written, ``keep``
    untouched, ``rewrite`` / ``merge`` on an existing file, every planned
    folder's files copied, nothing else; the gather homes excluded by name).
    The refused scenario commits nothing and writes 0 new paths.

    Why: HLR-175a — Save writes exactly the files the painted plan names.
    Negative control: a router that always re-prepares → ``prepared.plan is
    screen.plan`` false → RED; a commit that re-plans without the document
    row writes ``patches/changes.json`` with no painted row → RED. RED
    (base): ``_commit_project_save`` / ``screen.plan`` do not exist."""
    out = _scenario_paint(tmp_path, key, save=True, commit_spy=True)
    painted_plan = out["painted_plan"]
    if key == "refused":
        assert out["still_open"] is True
        assert out["commits"] == [] and out["new_paths"] == [], out
        return
    assert len(out["commits"]) == 1, out["commits"]
    (args, kwargs) = out["commits"][0]
    prepared = args[0] if args else kwargs.get("prepared")
    payload = args[1] if len(args) > 1 else kwargs.get("payload")
    assert prepared.plan is painted_plan, "the commit received a plan the dialog did not paint"
    assert payload.plan is painted_plan
    assert any(m.startswith("Saved project to") for m in out["messages"]), out["messages"]
    workarea = out["workarea"]
    _assert_tree_equals_plan(
        painted_plan,
        _target_digests(out["before"], painted_plan, workarea),
        _target_digests(out["after"], painted_plan, workarea),
    )


def test_tc_b100_65_document_keep_row_is_what_the_save_writes(tmp_path: Path) -> None:
    """LLR-175.4a document arm, A11-04 (p11b U3, B11-76, ruling Q10): ``P``
    records ``patches/changes.json`` beside an identical
    ``patches/changes_1.json``; save as ``Q`` → the painted document row
    names ``changes_1.json`` with ``keep`` (``document changes.json →
    patches/changes_1.json — keep``), the plan's document row lands on
    ``changes_1.json`` (``keep``), and after ``alt+s`` ``Q`` holds
    ``patches/changes_1.json`` and no ``patches/changes.json``, and
    ``Q/project.json`` records ``active_document ==
    "patches/changes_1.json"``.

    Why: the F5 remainder — the plan said ``changes.json new`` while the
    save wrote ``changes_1.json``, so the dialog would paint a row the save
    does not write. Negative control: executed on base (p11b U3): the plan
    row ``('document', 'changes.json', 'new')`` while ``Q`` holds
    ``patches/changes_1.json`` → RED."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True, exist_ok=True)
    project = projects.seed_document_project(_wa(base), "P", document="patches/changes.json")
    shutil.copyfile(project / "patches" / "changes.json", project / "patches" / "changes_1.json")

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "Q", "new folder", "project.json", timeout=10.0)
        rows = sd.summary_rows(screen)
        plan = screen.plan
        mark = len(log.messages)
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: any(m.startswith("Saved project to") for m in log.since(mark)),
                          "the save as Q", 10.0)
        await _settle(pilot, 6)
        q = app.workarea / "Q"
        tree = sorted(p.relative_to(q).as_posix() for p in q.rglob("*") if p.is_file())
        return rows, plan, tree, projects.read_manifest(q).get("active_document")

    rows, plan, tree, active = _run(base, scenario)
    doc_rows = [r for r in rows if r.startswith("document")]
    assert len(doc_rows) == 1 and "changes_1.json" in doc_rows[0] and re.search(r"\bkeep\b", doc_rows[0]), rows
    plan_doc = [(r.landing.name, r.action) for r in plan.rows if r.role == "document"]
    assert plan_doc == [("changes_1.json", "keep")], plan_doc
    assert "patches/changes_1.json" in tree and "patches/changes.json" not in tree, tree
    assert active == "patches/changes_1.json", active


def test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_1(tmp_path: Path) -> None:
    """LLR-175.4b arm 1, R2-01, B11-59: F-fresh, ``abc`` typed 10 ms apart and
    ``alt+s`` within 50 ms of the last key (before the 150 ms recompute) →
    0 dismisses, ``the summary changed`` / ``check it, then save again``
    painted, the summary now the plan for ``abc``, 0 new paths; a second
    ``alt+s`` with nothing changed → 1 dismiss and 1 folder ``abc``.

    Why: a Save inside the recompute window would save a plan nobody saw
    (R-PC). Negative control: the save action dismisses with the freshly
    computed plan → 1 dismiss, 0 token pairs → RED; a confirm that
    memoises the "changed" preview → the second press never saves → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        screen.set_focus(sd.name_input(screen))
        await _settle(pilot, 2)
        for ch in "abc":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.02)
        await pilot.press("alt+s")
        await _settle(pilot, 4)
        first = (list(seen), sd.where_text(screen), sd.summary_rows(screen),
                 None if screen.plan is None else Path(screen.plan.target).name,
                 sorted(sd.workarea_listing(app.workarea) - listing0))
        await asyncio.sleep(0.4)
        await _settle(pilot, 4)
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: (app.workarea / "abc" / "project.json").is_file(), "the second Save", 8.0)
        return first, [None if p is None else p.project_name for p in seen]

    (cb_first, where, rows, target, new), names = _run(base, scenario)
    assert cb_first == [], cb_first
    assert all(t in where for t in CHANGED), where
    assert _where_line_for_text(where, "abc", "new folder"), where
    assert target == "abc" and rows, (target, rows)
    assert new == [], new
    assert names == ["abc"], names


def test_tc_b100_65_summary_out_of_date_at_save_is_repainted_arm_2(tmp_path: Path) -> None:
    """LLR-175.4b arm 2, B11-60: F-merge where ``ab`` holds the same
    ``firmware.s19`` (painted ``image firmware.s19 — keep``); then the test
    writes ``ab/firmware.s19`` with other bytes; then ``alt+s`` → 0
    dismisses, ``the summary changed`` / ``check it, then save again``, the
    image row now lands ``firmware_1.s19`` with ``new``; 0 new paths.

    Negative control: a confirm that compares nothing and returns "go" →
    1 dismiss, the save lands ``firmware_1.s19`` without a painted row →
    RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "ab", files=("firmware.s19",))
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await sd.type_name(pilot, app, "ab")
        await sd.wait_painted(pilot, app, "merges into an existing project", "project.json")
        painted_rows = sd.summary_rows(screen)
        (app.workarea / "ab" / "firmware.s19").write_bytes((CASE02_DIR / "firmware.s19").read_bytes())
        listing0 = sd.workarea_listing(app.workarea)
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return painted_rows, list(seen), sd.where_text(screen), sd.summary_rows(screen), \
            sorted(sd.workarea_listing(app.workarea) - listing0)

    painted_rows, seen, where, rows, new = _run(base, scenario)
    assert any(_row_matches(r, "firmware.s19", "keep") for r in painted_rows), painted_rows
    assert seen == [], seen
    assert all(t in where for t in CHANGED), where
    assert any(_row_matches(r, "firmware_1.s19", "new") for r in rows), rows
    assert new == [], new


@pytest.mark.parametrize("key,line", [
    ("pending", "firmware.s19 + 1 change entry, 0 applied by this save"),
    ("document", "firmware.s19 + 1 change entry, 1 applied by this save"),
    ("fresh", "firmware.s19 unchanged copy"),
])
def test_tc_b100_65_image_line_says_emit_or_copy(tmp_path: Path, key: str, line: str) -> None:
    """LLR-175.4c, B11-49 (3 of 3; the A2L-only empty boundary is in
    ``test_tc_b100_49_an_a2l_alone_opens_the_dialog``): F-pending (1 entry
    applied) → ``firmware.s19 + 1 change entry, 0 applied by this save``;
    F-document (1 pasted entry, not applied) → ``+ 1 change entry, 1 applied
    by this save``; F-fresh → ``firmware.s19 unchanged copy``.

    Why: the engineer must see whether the save writes the patched image or
    a copy. Negative control: the description built from
    ``image_differs_from_source`` alone → F-document says ``unchanged
    copy`` → RED."""
    out = _scenario_paint(tmp_path, key)
    assert line in out["rows"], out["rows"]
    assert out["plan"].image == line, out["plan"].image


def test_tc_b100_65_pending_line_marks_unsaved_changes(tmp_path: Path) -> None:
    """LLR-175.4d, B11-50 (4 of 4): F-pending → 1 line holding ``unsaved
    changes`` and ``firmware.s19``; the same session after a Save project
    (through the dialog) → 0 lines at the next open; patched again → 1
    line; F-fresh → 0 lines.

    Why: the pending line warns that the session holds changes the disk
    does not. Negative control: the line keyed on
    ``image_differs_from_source`` → after a Save project the journal still
    shows the patch, so the line is painted → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.mac"))

    def pending(rows: list) -> list:
        return [r for r in rows if "unsaved changes" in r]

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        _add_direct(app)
        _apply_direct(app)
        out = {}
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project", "project.json")
        out["pending"] = pending(sd.summary_rows(app.screen))
        await pilot.press("escape")
        await _settle(pilot, 6)
        await sd.save_through_dialog(pilot, app, "P", confirm="alt+s")
        await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the save")
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await _settle(pilot, 10)
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project", "project.json")
        out["after_save"] = pending(sd.summary_rows(app.screen))
        await pilot.press("escape")
        await _settle(pilot, 6)
        _add_direct(app, 0x80000060, (0xAA,))
        _apply_direct(app)
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project", "project.json")
        out["again"] = pending(sd.summary_rows(app.screen))
        return out

    out = _run(base, scenario, size=(220, 60))
    assert len(out["pending"]) == 1 and "firmware" in out["pending"][0], out
    assert out["after_save"] == [], out
    assert len(out["again"]) == 1, out
    fresh = _scenario_paint(tmp_path / "fresh", "fresh")
    assert pending(fresh["rows"]) == [], fresh["rows"]


@WINDOWS_ARM
@pytest.mark.parametrize("count", [1, 12])
def test_tc_b100_65_skipped_links_get_one_row(tmp_path: Path, count: int) -> None:
    """LLR-175.4e, B11-51 (Windows arms; 2 of 2): a save as of ``P`` holding
    1 directory junction ``flows/jx`` → 1 row holding ``links or junctions
    not copied`` and ``flows/jx``; 12 junctions ``reports/j01`` …
    ``reports/j12`` → 1 row naming the first 10 and ``and 2 more``.

    Negative control: the links row omitted → 0 rows → RED."""
    base = tmp_path / "app"
    project = projects.build_save_as_project(base, "P", sub_files=projects.AT09_FILES)
    outside = projects.outside_folder(tmp_path, "links_target")
    names = ["flows/jx"] if count == 1 else [f"reports/j{i:02d}" for i in range(1, 13)]
    try:
        projects.add_junctions(project, outside, names)
    except OSError as exc:  # pragma: no cover - platform
        pytest.skip(f"junctions cannot be made here: {exc}")

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "Q", "new folder", "links or junctions not copied", timeout=10.0)
        return sd.summary_rows(app.screen)

    rows = _run(base, scenario, size=(220, 60))
    link_rows = [r for r in rows if "links or junctions not copied" in r]
    assert len(link_rows) == 1, rows
    if count == 1:
        assert "flows/jx" in link_rows[0], link_rows
    else:
        assert all(f"reports/j{i:02d}" in link_rows[0] for i in range(1, 11)), link_rows
        assert "reports/j11" not in link_rows[0] and "and 2 more" in link_rows[0], link_rows


def test_tc_b100_65_merge_names_the_active_variant_it_sets(tmp_path: Path) -> None:
    """LLR-175.4f, B11-52 (2 + 1): F-merge where ``ab`` records ``firmware``
    and the image lands as ``firmware_1.s19`` → 1 row holding ``active
    variant``, ``firmware_1`` and ``firmware``; after ``alt+s``
    ``ab/project.json`` records ``active_variant == "firmware_1"``; a merge
    whose target records no active variant → 1 row naming ``none
    recorded``.

    Why: a merge silently switched the project's active variant
    (UX-35). Negative control: the row omitted → 0 rows → RED; the row
    naming the first variant by name → the after-save equality fails →
    RED."""
    out = _scenario_paint(tmp_path, "merge", save=True)
    rows = [r for r in out["rows"] if "active variant" in r]
    assert len(rows) == 1 and "firmware_1" in rows[0] and re.search(r"\bfirmware\b", rows[0].split("firmware_1", 1)[1]), rows
    assert projects.read_manifest(out["workarea"] / "ab").get("active_variant") == "firmware_1"

    base = tmp_path / "none" / "app"
    other = _sources(tmp_path, CASE02_DIR, "firmware.s19", folder="src02_none")
    ab = _save_project_from(base, "ab", [other / "firmware.s19"])
    manifest = json.loads((ab / "project.json").read_text(encoding="utf-8"))
    manifest.pop("active_variant", None)
    (ab / "project.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    src = _sources(tmp_path, folder="src_none")

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "ab")
        await sd.wait_painted(pilot, app, "merges into an existing project", "active variant")
        return sd.summary_rows(app.screen)

    rows = [r for r in _run(base, scenario, size=(220, 60)) if "active variant" in r]
    assert len(rows) == 1 and "none recorded" in rows[0], rows


def _tiny_hex() -> bytes:
    """A small, valid Intel HEX image (two data records and EOF)."""

    def record(address: int, data: bytes) -> str:
        total = len(data) + (address >> 8) + (address & 0xFF) + sum(data)
        return f":{len(data):02X}{address:04X}00{data.hex().upper()}{(-total) & 0xFF:02X}"

    lines = [record(0x0000, bytes(range(16))), record(0x0010, bytes(range(16, 32))), ":00000001FF"]
    return ("\n".join(lines) + "\n").encode("ascii")


def test_tc_b100_65_active_variant_change_counts_as_out_of_date(tmp_path: Path) -> None:
    """A11-08, B11-88 (1 of 1): F-merge, ``ab`` painted (``active variant
    firmware_1 (before: firmware)``); then a data file ``firmware_1.hex``
    appears in ``ab`` (the image row is unchanged, but its stem now
    collides, so the variant the save makes active changes) → ``alt+s`` →
    ``the summary changed`` / ``check it, then save again``, 0 dismisses,
    0 new paths besides the test's own file.

    Why: confirm compares the plan AND the predicted active variant; the
    plan alone would save a variant the dialog did not name. Negative
    control: the equality on the plan alone (base) → ``confirm`` says go
    and the save records a variant the dialog did not paint → RED."""
    base = tmp_path / "app"
    ctx = _scenario_prep("merge", tmp_path, base)

    async def scenario(app, pilot, log):
        seen = _capture_callback(app)
        await _scenario_setup("merge", app, pilot, ctx, False)
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await sd.type_name(pilot, app, "ab")
        await sd.wait_painted(pilot, app, "merges into an existing project", "active variant")
        before_rows = sd.summary_rows(screen)
        (app.workarea / "ab" / "firmware_1.hex").write_bytes(_tiny_hex())
        listing0 = sd.workarea_listing(app.workarea)
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return before_rows, list(seen), sd.where_text(screen), sorted(sd.workarea_listing(app.workarea) - listing0)

    before_rows, seen, where, new = _run(base, scenario, size=(220, 60))
    assert any("active variant firmware_1" in r for r in before_rows), before_rows
    assert seen == [], seen
    assert all(t in where for t in CHANGED), where
    assert new == [], new


def test_tc_b100_65_manifest_backup_gets_its_own_row(tmp_path: Path) -> None:
    """A11-05, B11-85 (1 of 1): a merge into ``ab`` whose ``project.json``
    is damaged → the ``project.json`` row says the commit keeps a copy as
    ``project.json.previous-<UTC>``; after ``alt+s`` ``ab`` holds one
    ``project.json.previous-*`` file.

    Why: the commit backs the damaged manifest up; a dialog that showed
    only ``project.json — rewrite`` would hide a file the save writes.
    Negative control: the row omitted → the dialog paints no
    ``project.json.previous`` while the commit writes one → RED."""
    base = tmp_path / "app"
    ab = projects.save_case01_project(base, "ab", files=("firmware.s19",))
    (ab / "project.json").write_text("{not json", encoding="utf-8")
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "ab")
        await sd.wait_painted(pilot, app, "ab", "project.json", timeout=10.0)
        rows = sd.summary_rows(app.screen)
        mark = len(log.messages)
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the dialog to close", 8.0)
        await sd.wait_for(pilot, lambda: any("Saved project" in m or "NOT saved" in m for m in log.since(mark)),
                          "the save outcome", 10.0)
        await _settle(pilot, 6)
        return rows, sorted(p.name for p in (app.workarea / "ab").iterdir())

    rows, names = _run(base, scenario, size=(220, 60))
    manifest_rows = [r for r in rows if r.startswith("project.json")]
    assert len(manifest_rows) == 1 and "project.json.previous" in manifest_rows[0], rows
    assert sum(1 for n in names if n.startswith("project.json.previous-")) == 1, names


def test_tc_b100_65_names_are_painted_literally(tmp_path: Path) -> None:
    """LLR-175.4g, B11-25, B11-54, P-6 (5 of 5): a loaded file ``[b]x.s19``
    → the image rows hold ``[b]x.s19``; a save as whose open project holds
    the top-level file ``[i]f.json`` → a row holds ``[i]f.json``; a typed
    ``[red]a`` → ``#save_where`` names ``reda``; a disguised clash typed
    ``[b]a b`` against project ``bab`` → the refusal holds ``'[b]a b'``; a
    file named ``x`` + U+202E + ``y.s19`` → the row holds ``xy.s19`` and no
    U+202E. Every painted line has 0 markup spans.

    Why: a name read from disk must never restyle the dialog or hide its
    real text. Negative control: the summary widget with markup on →
    ``[b]x.s19`` paints ``x.s19`` in bold → RED. Design note: the draft's
    ``[b]P`` clash arm cannot fire (the sanitiser drops the brackets, so no
    project folder ``[b]P`` can case-fold-equal a sanitised name); the arm
    is re-pinned to a typed name holding brackets (tester notes)."""
    out = {}
    base = tmp_path / "a" / "app"
    srcs = tmp_path / "a" / "srcs"
    srcs.mkdir(parents=True)
    shutil.copy2(CASE01_DIR / "firmware.s19", srcs / "[b]x.s19")
    rtl = "x‮y.s19"
    shutil.copy2(CASE01_DIR / "firmware.s19", srcs / rtl)
    projects.save_case01_project(base, "bab", files=("firmware.s19",))
    projects.save_case01_project(base, "P2", files=("firmware.s19",))

    async def first(app, pilot, log):
        await _load_direct(pilot, app, srcs / "[b]x.s19")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "[red]a", "reda", "new folder", "project.json")
        res = {"rows": sd.summary_rows(app.screen), "where": sd.where_text(app.screen),
               "spans": [sd.spans(w) for w in sd.summary_widgets(app.screen)] + [sd.spans(sd.where_widget(app.screen))]}
        await pilot.press("escape")
        await _settle(pilot, 6)
        await _open_project_direct(pilot, app, "P2")
        await sd.open_save_dialog(pilot, app)
        await _type_and_wait(pilot, app, "[b]a b", *CLASH)
        res["clash"] = sd.where_text(app.screen)
        res["clash_spans"] = sd.spans(sd.where_widget(app.screen))
        return res

    out["a"] = _run(base, first, size=(220, 60))
    base_b = tmp_path / "b" / "app"
    project = projects.save_case01_project(base_b, "P", files=("firmware.s19",))
    (project / "[i]f.json").write_bytes(b'{"tag": "i"}')

    async def second(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "Q", "new folder", "[i]f.json", timeout=10.0)
        return sd.summary_rows(app.screen), [sd.spans(w) for w in sd.summary_widgets(app.screen)]

    out["b"] = _run(base_b, second, size=(220, 60))
    base_c = tmp_path / "c" / "app"

    async def third(app, pilot, log):
        await _load_direct(pilot, app, srcs / rtl)
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "rtl")
        await sd.wait_painted(pilot, app, "rtl", "new folder", "project.json")
        return sd.summary_rows(app.screen)

    out["c"] = _run(base_c, third, size=(220, 60))
    a = out["a"]
    assert any("[b]x.s19" in r for r in a["rows"]), a
    assert _where_line_for_text(a["where"], "reda", "new folder"), a
    assert set(a["spans"]) == {0}, a
    assert "'[b]a b'" in a["clash"] and a["clash_spans"] == 0, a
    rows_b, spans_b = out["b"]
    assert any("[i]f.json" in r for r in rows_b) and set(spans_b) == {0}, out["b"]
    assert any("xy.s19" in r for r in out["c"]) and not any("‮" in r for r in out["c"]), out["c"]


def _three_hundred_rows(base: Path, long_name_len: int = 90) -> Path:
    """``P`` saved (case_01's S19), then 298 top-level files and one with a
    ``long_name_len``-character name: a save as plans about 300 rows."""
    project = projects.save_case01_project(base, "P", files=("firmware.s19",))
    for index in range(298):
        (project / f"t{index:03d}.bin").write_bytes(bytes([index % 256]))
    # MAX_PATH (LongPathsEnabled is 0 on the development host): the name is
    # cut to what the deepest copy (``W/Q/<name>``) can hold.
    long_name_len = min(long_name_len, 255 - len(str(project)))
    (project / (("L" * (long_name_len - 4)) + ".bin")).write_bytes(b"long")
    return project


def _fully_visible(screen, widget) -> bool:
    geo = screen.find_widget(widget)
    region = geo.region
    return region == region.intersection(geo.clip) and screen.region.contains_region(region) and region.height >= 1


@pytest.mark.parametrize("size", SIZES)
def test_tc_b100_65_buttons_stay_visible_and_rows_never_wrap(tmp_path: Path, size: tuple) -> None:
    """LLR-175.4h, LLR-175.4j, HLR-175f boundary, C3-1, C3-3, S9-5 (2 of 2
    sizes): a save-as plan of about 300 rows at 118×54 and 220×60 →
    ``#save_ok`` and ``#save_cancel`` fully visible (each region equals its
    clipped region, lies inside the screen and is at least 1 high); every
    summary row's region is 1 high; at 118 columns the row naming a
    90-character file is cut and its rendered line ends with ``…``.

    Why: a long summary pushed Save and Cancel off the screen. Negative
    control: ``#save_summary`` and ``#save_box`` both unbounded →
    ``#save_ok`` at y = 305, not visible → RED (P-GA11-2); a row allowed to
    wrap → 2 lines high → RED. Environment: the draft's 130-character name
    (P-6) cannot be built under this temp root (MAX_PATH, LongPathsEnabled
    0); the 90-character name exercises the same one-line rule."""
    base = tmp_path / "app"
    _three_hundred_rows(base)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "Q", "new folder", "project.json", timeout=15.0)
        await _settle(pilot, 10)
        widgets = sd.summary_widgets(screen)
        heights = {w.region.height for w in widgets}
        long_row = next((w for w in widgets if "LLLLLLLL" in sd.plain(w)), None)
        cut = None
        if long_row is not None:
            screen.query_one("#save_summary").scroll_to_widget(long_row, animate=False)
            await _settle(pilot, 6)
            # the cut is owed only when the row is wider than its region
            if len(sd.plain(long_row)) > long_row.region.width:
                cut = long_row.render_line(0).text.rstrip()
            else:
                cut = "(row fits its region; no cut owed) …"
        return (len(widgets), _fully_visible(screen, screen.query_one("#save_ok")),
                _fully_visible(screen, screen.query_one("#save_cancel")), heights, cut)

    count, ok_visible, cancel_visible, heights, cut = _run(base, scenario, size=size)
    assert count >= 300, count
    assert ok_visible and cancel_visible, (ok_visible, cancel_visible)
    assert heights == {1}, heights
    if size[0] == 118:
        assert cut is not None and cut.endswith("…"), cut


def test_tc_b100_65_last_row_reachable_by_keyboard(tmp_path: Path) -> None:
    """LLR-175.4i, C3-2 (1 + 2): the ~300-row save-as plan at 118×54:
    ``tab`` from ``#project_name`` gives the focus to ``#save_summary``,
    then ``end`` → it scrolls to the bottom and the last row's region lies
    inside the summary's region; the ``tab`` order is ``#project_name`` →
    ``#save_summary`` → ``#save_ok`` → ``#save_cancel`` → ``#project_name``
    and ``shift+tab`` the reverse.

    Negative control: ``#save_summary`` not focusable → ``tab`` lands on
    ``save_ok`` and ``end`` stays in the name field → RED."""
    base = tmp_path / "app"
    _three_hundred_rows(base)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        screen = app.screen
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "Q", "new folder", "project.json", timeout=15.0)
        await _settle(pilot, 10)
        screen.set_focus(sd.name_input(screen))
        await _settle(pilot, 2)
        forward = []
        for _ in range(4):
            await pilot.press("tab")
            await _settle(pilot, 2)
            forward.append(_focused_id(app))
        backward = []
        for _ in range(4):
            await pilot.press("shift+tab")
            await _settle(pilot, 2)
            backward.append(_focused_id(app))
        await pilot.press("tab")
        await _settle(pilot, 2)
        on_summary = _focused_id(app)
        await pilot.press("end")
        await _settle(pilot, 10)
        box = screen.query_one("#save_summary")
        last = sd.summary_widgets(screen)[-1]
        inside = box.region.contains_region(last.region)
        return forward, backward, on_summary, box.scroll_y == box.max_scroll_y, inside

    forward, backward, on_summary, at_bottom, inside = _run(base, scenario)
    assert forward == ["save_summary", "save_ok", "save_cancel", "project_name"], forward
    assert backward == ["save_cancel", "save_ok", "save_summary", "project_name"], backward
    assert on_summary == "save_summary" and at_bottom and inside, (on_summary, at_bottom, inside)


def test_tc_b100_65_a_direct_payload_saves_the_same_tree(tmp_path: Path) -> None:
    """LLR-175.4l, B11-11 (1 of 1): twin F-fresh fixtures — one saves
    ``fresh1`` through the dialog (``alt+s``), the other through a direct
    ``_handle_save_dialog(SaveProjectPayload(work area, "fresh1"))`` → the
    two ``fresh1`` trees hold the same files with equal digests, the
    session digests (paths taken relative to each base) are equal, and
    after each route the app holds no per-open Save state
    (``_save_session`` and ``_save_confirmed`` are ``None``, S-d).

    Why: 56 direct test calls and the dialog must run the same preparation.
    Negative control: a router that requires a dialog-prepared plan →
    every direct call refuses → RED."""
    from s19_app.tui.screens import SaveProjectPayload

    results = {}
    for side in ("dlg", "dir"):
        base = tmp_path / side / "app"
        src = _sources(tmp_path, folder=f"src_{side}")

        async def scenario(app, pilot, log, side=side, base=base, src=src):
            await _load_direct(pilot, app, src / "firmware.s19")
            if side == "dlg":
                await sd.save_through_dialog(pilot, app, "fresh1", confirm="alt+s")
            else:
                app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="fresh1"))
            await sd.wait_for(pilot, lambda: app.current_project == "fresh1", "the save", 10.0)
            await _settle(pilot, 6)
            digest = tuple(
                None if v is None else v.replace(str(base), "<base>") for v in sd.session_digest(app)
            )
            state = (getattr(app, "_save_session", "missing"), getattr(app, "_save_confirmed", "missing"))
            return sd.tree_digests(app.workarea / "fresh1"), digest, state

        results[side] = _run(base, scenario)
    (tree_d, dig_d, state_d), (tree_r, dig_r, state_r) = results["dlg"], results["dir"]
    assert sorted(tree_d) == ["firmware.s19", "project.json"], tree_d
    assert tree_d == tree_r, (tree_d, tree_r)
    assert dig_d == dig_r, (dig_d, dig_r)
    assert state_d == (None, None) and state_r == (None, None), (state_d, state_r)


# ---------------------------------------------------------------------------
# TC-B100-65 cost arms — LLR-175.5, .5a, .5b, A11-01, R2-02 / R3-01, S11-05
# ---------------------------------------------------------------------------


def _spy_digest(monkeypatch) -> list:
    """Every ``_file_digest`` call's path (the app's module-level helper)."""
    calls: list = []
    original = app_module._file_digest

    def _wrapped(path, *args, **kwargs):
        calls.append(os.path.normcase(str(Path(path).resolve())))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(app_module, "_file_digest", _wrapped)
    return calls


async def _post_keys(app, text: str, gap: float = 0.01) -> float:
    """Post one key per character, ``gap`` seconds apart; return the time of
    the last key."""
    for ch in text:
        app.post_message(events.Key(ch, ch))
        await asyncio.sleep(gap)
    return time.monotonic()


def test_tc_b100_65_session_decided_once_per_open_case06(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-175.5, A11-01, B11-36, B11-37, B11-83 (F-case06: the 37 742 888-byte
    A2L, its S19 and MAC, 1 applied entry so the image is emitted): 1 dialog
    open, 20 keystrokes of a new name, then ``alt+s`` → 1 call of
    ``_decide_project_image``, 1 ``_file_digest`` call for the A2L and 1 for
    the MAC (0 for the emitted image, counted: MUT11-M-68), 1
    ``_derived_record`` call — 0 more
    during the keystrokes and 0 more at ``alt+s``; the summary is painted
    within 2 s of ``ctrl+s`` (the measured time is recorded in the tester
    notes, C-QA-5).

    Why: re-deciding the image and re-hashing 37 MB on every keystroke
    would freeze the dialog. Negative control: the decision and digests
    recomputed with the plan → 20 keystrokes give ≥ 2 decisions → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path, CASE06_DIR, "firmware.s19", "firmware.mac", "firmware.a2l")

    async def scenario(app, pilot, log):
        from s19_app.tui.screens import SaveProjectPayload

        await _load_direct(pilot, app, src / "firmware.s19")
        await _load_direct(pilot, app, src / "firmware.mac")
        app.load_a2l_from_path(src / "firmware.a2l")
        await sd.wait_for(pilot, lambda: app.current_a2l_path is not None, "the case_06 A2L", 120.0)
        await _settle(pilot, 6)
        # F-case06: a project holding the case_06 files (saved by the
        # shipped handler, LED .42), so the dialog opens prefilled.
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
        await sd.wait_for(pilot, lambda: app.current_project == "P", "the case_06 project P", 60.0)
        await _settle(pilot, 6)
        first = min(app.current_file.mem_map)
        _add_direct(app, first, (0x5A,))
        _apply_direct(app)
        decisions = _spy_method(app, "_decide_project_image")
        derived = _spy_method(app, "_derived_record")
        digests = _spy_digest(monkeypatch)
        a2l = os.path.normcase(str(Path(app.current_a2l_path).resolve()))
        mac = os.path.normcase(str(Path(app.current_file.mac_path).resolve()))
        image = os.path.normcase(str(Path(app.current_file.path).resolve()))
        start = time.monotonic()
        await pilot.press("ctrl+s")
        await sd.wait_for(pilot, lambda: sd.is_save_dialog(app.screen), "the dialog")
        await sd.wait_for(pilot, lambda: bool(sd.summary_rows(app.screen)), "the first summary", 10.0)
        painted_after = time.monotonic() - start
        at_open = (len(decisions), digests.count(a2l), digests.count(mac), len(derived))
        image_digests = [digests.count(image)]
        app.screen.set_focus(sd.name_input(app.screen))
        await sd.clear_name(pilot, app)
        await _post_keys(app, "newname1234567890abc")
        await sd.wait_painted(pilot, app, "newname1234567890abc", "new folder", timeout=10.0)
        after_keys = (len(decisions), digests.count(a2l), digests.count(mac), len(derived))
        image_digests.append(digests.count(image))
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the save", 30.0)
        await _settle(pilot, 6)
        after_save = (len(decisions), digests.count(a2l), digests.count(mac), len(derived))
        return painted_after, at_open, after_keys, after_save, image_digests

    painted_after, at_open, after_keys, after_save, image_digests = _run(base, scenario)
    print(f"[C-QA-5] F-case06 summary painted {painted_after * 1000:.0f} ms after ctrl+s")
    assert at_open == (1, 1, 1, 1), at_open
    assert after_keys == at_open, (at_open, after_keys)
    assert after_save == at_open, (at_open, after_save)
    assert image_digests == [0, 0], image_digests
    assert painted_after <= 2.0, painted_after


def test_tc_b100_65_recompute_at_most_three_of_twenty_keystrokes(tmp_path: Path) -> None:
    """LLR-175.5a (app half, 3 assertions): F-fresh, 20 keystrokes 10 ms
    apart → at most 3 calls of the app's preview for the burst, each
    keystroke echoed in ``#project_name``, and the plan for the final name
    painted within 300 ms of the last keystroke.

    Negative control: a recomputation per keystroke → 20 previews → RED; no
    trailing recomputation → the final name's plan is never painted →
    RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        previews = _spy_method(app, "_save_dialog_preview")
        await sd.open_save_dialog(pilot, app)
        field = sd.name_input(app.screen)
        app.screen.set_focus(field)
        await _settle(pilot, 2)
        start = len(previews)
        last = await _post_keys(app, "abcdefghijklmnopqrst")
        await sd.wait_for(pilot, lambda: field.value == "abcdefghijklmnopqrst", "the echo", 2.0)
        await sd.wait_for(
            pilot, lambda: _where_line_for_text(sd.where_text(app.screen), "abcdefghijklmnopqrst", "new folder"),
            "the final paint", 2.0,
        )
        final = time.monotonic() - last
        await asyncio.sleep(0.4)
        return len(previews) - start, final

    count, final = _run(base, scenario)
    assert 1 <= count <= 3, count
    assert final <= 0.3, final


def test_tc_b100_65_emitting_4mib_image_recomputes_fast(tmp_path: Path) -> None:
    """LLR-175.5a 4 MiB arm, A11-01 (1 of 1): a 4 MiB S19 with 1 applied
    entry (an emitting session) → after the first summary, 20 keystrokes
    10 ms apart are each echoed and the plan for the final name is painted
    within 300 ms of the last keystroke, because the emitted record is
    computed once per open, not per recompute.

    Negative control: ``emitted_record`` (and the payload digest) computed in
    each preparation → every recompute parses and hashes 4 MiB → the final
    paint misses 300 ms → RED."""
    from tests.conftest import make_large_s19

    base = tmp_path / "app"
    big = make_large_s19(tmp_path / "big.s19", num_ranges=1024, bytes_per_range=4096, base_address=0x08000000)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, big, timeout=120.0)
        _add_direct(app, 0x08000000, (0xDE, 0xAD))
        _apply_direct(app)
        await pilot.press("ctrl+s")
        await sd.wait_for(pilot, lambda: sd.is_save_dialog(app.screen), "the dialog")
        await sd.wait_recompute(pilot)
        await sd.type_name(pilot, app, "x")
        await sd.wait_painted(pilot, app, "new folder", "project.json", timeout=30.0)
        field = sd.name_input(app.screen)
        app.screen.set_focus(field)
        await sd.clear_name(pilot, app)
        await sd.wait_recompute(pilot)
        last = await _post_keys(app, "abcdefghijklmnopqrst")
        await sd.wait_for(pilot, lambda: field.value == "abcdefghijklmnopqrst", "the echo", 5.0)
        await sd.wait_for(
            pilot, lambda: _where_line_for_text(sd.where_text(app.screen), "abcdefghijklmnopqrst", "new folder"),
            "the final paint", 5.0,
        )
        return time.monotonic() - last

    final = _run(base, scenario)
    print(f"[C-QA-5] 4 MiB emitting image: final paint {final * 1000:.0f} ms after the last key")
    assert final <= 0.3, final


def test_tc_b100_65_first_frame_before_the_image_decision(tmp_path: Path) -> None:
    """LLR-175.5b, B11-06, B11-43 (1 of 1 + the AST arm): a spy on
    ``_decide_project_image`` records, at its first call after ``ctrl+s``,
    that ``app.screen`` is a mounted Save dialog whose ``#project_name`` is
    laid out (it has completed a refresh); the body of
    ``action_save_project`` calls none of ``_decide_project_image``,
    ``_save_session_inputs``, ``_prepare_project_save`` and
    ``_file_digest``.

    Why: the engineer sees the dialog before the image decision runs (a
    4 MiB patched image takes about 1.2 s to re-derive, P11-4). Negative
    control: the decision computed in ``action_save_project`` before
    ``push_screen`` → at the first call the screen is the main screen →
    RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)
    seen: list = []

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        original = app._decide_project_image

        def _spy():
            screen = app.screen
            field = screen.query("#project_name") if sd.is_save_dialog(screen) else []
            seen.append((sd.is_save_dialog(screen), getattr(screen, "is_mounted", False),
                         field.first().region.width if len(field) else 0))
            return original()

        app._decide_project_image = _spy
        await sd.open_save_dialog(pilot, app)
        return seen[:1]

    first = _run(base, scenario)
    assert first and first[0][0] is True and first[0][1] is True and first[0][2] > 0, first
    tree = ast.parse((ROOT / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "S19TuiApp")
    action = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "action_save_project")
    calls = {
        (n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", ""))
        for n in ast.walk(action) if isinstance(n, ast.Call)
    }
    assert not calls & {"_decide_project_image", "_save_session_inputs", "_prepare_project_save", "_file_digest"}, calls


def test_tc_b100_65_save_as_inventory_walked_once_per_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R2-02 / R3-01, B11-38 (S11-06): ``P`` open holding 60 files in
    ``reports/``; the prefilled update-the-open-project name walks the
    project 0 times; 20 keystrokes of a new name → ``inventory_project_tree``
    is called once in that dialog open, not per recompute.

    Why: a 2 000-file walk costs about 190 ms (p11b U8); per recompute it
    breaks the 300 ms final paint. Negative control: the walk per plan → ≥ 2
    walks → RED; the lazy fill writing back a session that is not the live
    one → stale state (R3-01) → RED."""
    import s19_app.tui.services.project_gather_service as gather

    base = tmp_path / "app"
    project = projects.save_case01_project(base, "P", files=("firmware.s19",))
    projects.bulk_files(project, "reports", 60)
    walks: list = []
    original = gather.inventory_project_tree

    def _walk(*args, **kwargs):
        walks.append(args[0] if args else kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(gather, "inventory_project_tree", _walk)
    monkeypatch.setattr(app_module, "inventory_project_tree", _walk, raising=False)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        walks.clear()
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project")
        prefilled = len(walks)
        app.screen.set_focus(sd.name_input(app.screen))
        await sd.clear_name(pilot, app)
        await sd.wait_recompute(pilot)
        for ch in "newname1234567890abc":
            app.post_message(events.Key(ch, ch))
            await asyncio.sleep(0.2)
        await sd.wait_painted(pilot, app, "newname1234567890abc", "new folder", "reports", timeout=10.0)
        return prefilled, len(walks)

    prefilled, total = _run(base, scenario, size=(220, 60))
    assert prefilled == 0, prefilled
    assert total == 1, total


def test_tc_b100_65_save_as_then_patch_then_direct_save_plans_fresh(tmp_path: Path) -> None:
    """R2-02, S11-10, B11-15, B11-89 (1 of 1): ``P`` open; a direct save as
    ``Q`` (which fills the lazy inventory); then 1 entry applied; then a
    direct save of ``R`` → the image decision runs again and ``R`` holds the
    patched image; after each router return the app holds no per-open Save
    state (``_save_session`` and ``_save_confirmed`` are ``None``).

    Why: a session written back after the router cleared it would plan the
    next save from stale, pre-patch inputs. Negative control: the fill
    writes ``self._save_session`` unconditionally → ``R`` is planned from
    the stale session and the patched image is not written → RED."""
    from s19_app.tui.screens import SaveProjectPayload
    from tests.support.independent_reader import read_s19

    base = tmp_path / "app"
    project = projects.save_case01_project(base, "P", files=("firmware.s19",))
    projects.write_tree(project, projects.AT09_FILES)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        decisions = _spy_method(app, "_decide_project_image")
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="Q"))
        await sd.wait_for(pilot, lambda: (app.workarea / "Q" / "project.json").is_file(), "the save as Q", 10.0)
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await _settle(pilot, 6)
        state_q = (getattr(app, "_save_session", "missing"), getattr(app, "_save_confirmed", "missing"))
        before = len(decisions)
        _add_direct(app, 0x8000007C, (0xDE, 0xAD, 0xBE, 0xEF))
        _apply_direct(app)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="R"))
        await sd.wait_for(pilot, lambda: (app.workarea / "R" / "project.json").is_file(), "the save of R", 10.0)
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await _settle(pilot, 6)
        state_r = (getattr(app, "_save_session", "missing"), getattr(app, "_save_confirmed", "missing"))
        images = sorted((app.workarea / "R").glob("*.s19"))
        return state_q, state_r, len(decisions) - before, images

    state_q, state_r, decisions_for_r, images = _run(base, scenario)
    assert state_q == (None, None) and state_r == (None, None), (state_q, state_r)
    assert decisions_for_r >= 1, decisions_for_r
    patched = [p for p in images if read_s19(p).data.get(0x8000007C) == 0xDE]
    assert patched, [p.name for p in images]


def test_tc_b100_65_document_digest_is_taken_in_each_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S11-05, B11-73: a file-backed change document (``P`` records
    ``patches/changes.json``, opened with the project) → every preview of a
    new name re-digests the document (the digest left the session): over 3
    recomputes, 1 ``_file_digest`` call for the document per preview.

    Why: a document edited while the dialog is open must be seen by the
    final check, or the written tree differs from the painted row. Negative
    control: the document digest cached in the session → 1 call for 3
    previews → RED."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True, exist_ok=True)
    project = projects.seed_document_project(_wa(base), "P", document="patches/changes.json")

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        document = os.path.normcase(str((project / "patches" / "changes.json").resolve()))
        await sd.open_save_dialog(pilot, app)
        previews = _spy_method(app, "_save_dialog_preview")
        digests = _spy_digest(monkeypatch)
        for name in ("Q1", "Q2", "Q3"):
            await sd.type_name(pilot, app, name)
            await sd.wait_painted(pilot, app, name, "new folder", timeout=10.0)
        named = [args for args, _kwargs in previews if args and str(args[0]).strip()]
        return len(named), digests.count(document)

    previews, doc_digests = _run(base, scenario, size=(220, 60))
    assert previews >= 3, previews
    assert doc_digests == previews, (previews, doc_digests)


def test_tc_b100_65_vanished_source_after_a_save_as_preview_copies_nothing(tmp_path: Path) -> None:
    """CR11-F1 (E5 corrective), LLR-171.1n / A11-16, LLR-171.1g, R3-01:
    ``P`` open holding 3 files in ``reports/``; the dialog previews ``Q``
    (a save as, which fills the session's inventory with ``P``'s tree);
    ``P`` is renamed outside the app; ``R`` typed → the summary names the
    vanished folder and lists 0 ``folder`` rows and no ``reports/`` file;
    Save → the dialog closes, the app keeps running, no ``R/reports`` is
    written and the moved folder is unchanged. (The loaded image lives in
    ``P``, so it moved too: the commit then refuses and rolls back, which
    is not under test here.)

    Why: a save-as inventory cached in the live session must never reach a
    plan that is not a save as. Otherwise the dialog paints copies the save
    cannot make and the commit copies from no source (``AttributeError``),
    which ends the app and loses the unsaved session. Negative control
    (051f586): ``folder reports/ (3 files) — new`` painted for ``R`` →
    RED."""
    base = tmp_path / "app"
    project = projects.save_case01_project(base, "P", files=("firmware.s19",))
    projects.bulk_files(project, "reports", 3)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project")
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "new folder", "reports", timeout=10.0)
        session = app._save_session
        assert session is not None and session.inventory is not None, "precondition: the save-as preview filled the inventory"
        moved = app.workarea / "P_moved"
        os.rename(app.workarea / "P", moved)
        moved_before = sd.tree_digests(moved)
        await sd.type_name(pilot, app, "R")
        await sd.wait_for(
            pilot,
            lambda: _where_line_for_text(sd.where_text(app.screen), "R", "new folder"),
            "the summary of R",
            10.0,
        )
        await sd.wait_recompute(pilot)
        rows = sd.summary_rows(app.screen)
        assert "P" in rows, rows
        assert not [r for r in rows if r.startswith("folder ") or "reports/" in r], rows
        for _attempt in range(2):
            if not sd.is_save_dialog(app.screen):
                break
            await pilot.press("alt+s")
            await _settle(pilot, 8)
        await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the dialog to close on Save", 10.0)
        await _settle(pilot, 6)
        return {
            "running": app.is_running,
            "dialog": sd.is_save_dialog(app.screen),
            "r_reports": (app.workarea / "R" / "reports").exists(),
            "moved_same": sd.tree_digests(moved) == moved_before,
        }

    out = _run(base, scenario, size=(220, 60))
    assert out == {"running": True, "dialog": False, "r_reports": False, "moved_same": True}, out


@pytest.mark.parametrize("layout", ["same_ranges", "other_ranges"])
def test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session(tmp_path: Path, layout: str) -> None:
    """SE5-11-1 (E5 corrective), LLR-175.5 / ruling Q-4, LLR-175.4b,
    HLR-175a: ``P`` open with ``firmware.s19`` + ``firmware.mac`` and 1
    entry applied (unsaved); the dialog painted for the open project; a
    load of ``other.s19`` (started before ``ctrl+s``) lands while the
    dialog is up; Save, and Save again after ``the summary changed``.

    same_ranges (case_01 with 1 data byte flipped): the image the save
    writes is derived from ``other.s19`` — its ``derived_from`` base is
    ``other.s19``, its bytes are ``other.s19``'s plus the entry, the
    manifest's ``active_variant`` names it, and the in-memory image equals
    it. other_ranges (case_02's image): the app keeps running and the save
    plans from the fresh session — the entry does not re-derive case_02,
    so ``other.s19`` is saved as an unchanged copy: no ``derived_from``
    record, ``active_variant`` ``other`` (what a dialog opened after the
    load paints).

    Why: the per-open session caches the image decision; a load under the
    modal makes it stale. A stale decision writes a patched copy of the
    previous file as the project's active variant and installs it into
    memory (same ranges), or renders it over the new file's ranges and
    ends the app with a ``KeyError`` (other ranges). Negative control
    (051f586): base ``firmware.s19`` → RED; other_ranges → the commit's
    ``KeyError`` → RED."""
    from tests.support.independent_reader import read_s19

    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.mac"))
    other = tmp_path / "other"
    other.mkdir()
    loaded = other / "other.s19"
    shutil.copyfile((CASE01_DIR if layout == "same_ranges" else CASE02_DIR) / "firmware.s19", loaded)
    if layout == "same_ranges":
        projects.flip_data_byte(loaded)
    other_data = dict(read_s19(loaded).data)
    patch = {0x8000007C + i: b for i, b in enumerate((0xDE, 0xAD, 0xBE, 0xEF))}

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        _add_direct(app)
        _apply_direct(app)
        await _settle(pilot, 4)
        await sd.open_save_dialog(pilot, app)
        await sd.wait_painted(pilot, app, "updates the open project", "firmware_1.s19")
        # Inc 12a re-pin (MERGE-12a-1): the worker takes the run's
        # generation (keyword-only ``gen``), so the load starts the way
        # ``load_from_path`` hands off to it — one begin through the 12a
        # seam, then the worker. The copy step is skipped, as before.
        gen = app._busy_begin_action("file_load", loaded.name)
        app._start_load_worker(loaded, gen=gen)
        await sd.wait_for(
            pilot,
            lambda: app.current_file is not None and app.current_file.path.name == "other.s19",
            "the load of other.s19 under the dialog",
            15.0,
        )
        await _settle(pilot, 10)
        assert sd.is_save_dialog(app.screen), "precondition: the load landed under the dialog"
        for _attempt in range(2):
            if not sd.is_save_dialog(app.screen):
                break
            await pilot.press("alt+s")
            await _settle(pilot, 8)
        out = {"painted": sd.painted(app.screen) if sd.is_save_dialog(app.screen) else None}
        if out["painted"] is not None:
            await pilot.press("escape")
            await sd.wait_for(pilot, lambda: not sd.is_save_dialog(app.screen), "the dialog to close on escape")
        await _settle(pilot, 6)
        manifest = json.loads((app.workarea / "P" / "project.json").read_text(encoding="utf-8"))
        out["derived"] = manifest.get("derived_from") or {}
        out["active_variant"] = manifest.get("active_variant")
        out["written"] = {name: dict(read_s19(app.workarea / "P" / name).data) for name in out["derived"]}
        out["memory"] = dict(app.current_file.mem_map)
        out["running"] = app.is_running
        return out

    out = _run(base, scenario, size=(220, 60))
    assert out["running"], out["painted"]
    assert all(rec.get("base") == "other.s19" for rec in out["derived"].values()), out["derived"]
    if layout == "same_ranges":
        assert out["painted"] is None, out["painted"]
        assert len(out["derived"]) == 1, out["derived"]
        name = next(iter(out["derived"]))
        assert out["written"][name] == {**other_data, **patch}, name
        assert out["active_variant"] == Path(name).stem, (out["active_variant"], name)
        assert out["memory"] == out["written"][name]
    else:
        assert out["painted"] is None, out["painted"]
        assert out["derived"] == {} and out["active_variant"] == "other", out["derived"]


def test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute(tmp_path: Path) -> None:
    """MUT11-M-09 (E5), LLR-175.5b, S4-1: the name field changes before the
    first preview has run (a late first frame, stood in for by deferring
    the first preview 500 ms) → ``preview`` is called once, by the first
    preview with the dialog live, never by a recompute timer started before
    it.

    Why: a recompute before the first frame computes a plan for a dialog
    that is not laid out yet (LLR-175.5b). Negative control: the change
    handler without the live gate → a recompute 150 ms after the change,
    before the first preview → 2 calls, the first one not live → RED."""
    from textual.widgets import Input

    from s19_app.tui.screens import SaveProjectScreen

    class _LateFirstFrame(SaveProjectScreen):
        def on_mount(self, event) -> None:
            event.prevent_default()
            self.set_timer(0.5, self._first_preview)
            self.query_one("#project_name", Input).value = "early"

    async def scenario(app, pilot, log):
        fakes = _Fakes(app.workarea)
        live_at_call: list = []
        original = fakes.preview

        def _preview(text):
            live_at_call.append(screen._live)
            return original(text)

        screen = _LateFirstFrame(preview=_preview, confirm=fakes.confirm)
        app.push_screen(screen)
        await sd.wait_for(pilot, lambda: len(fakes.preview_calls) >= 1, "the first preview", 3.0)
        await asyncio.sleep(0.6)
        await _settle(pilot, 4)
        return list(fakes.preview_calls), live_at_call

    calls, live = _run(tmp_path / "app", scenario)
    assert calls == ["early"] and live == [True], (calls, live)


def test_tc_b100_65_a_save_queued_before_a_repaint_is_shown_repaints(tmp_path: Path) -> None:
    """MUT11-M-14 (E5), S11-04, LLR-175.4b: the preview of ``one`` is painted
    and shown; ``two`` is typed and its preview queues a Save on the dialog
    before the frame that shows it → ``confirm`` gets ``("two", None)``, 0
    dismisses, ``the summary changed`` painted; a second ``alt+s`` → 1
    dismiss naming ``two``.

    Why: every repaint must be seen before it can be saved, not only the
    first one. Negative control: the shown mark not cleared by a repaint →
    ``confirm`` gets the unseen plan of ``two`` and the dialog dismisses →
    RED."""
    from s19_app.tui.screens import SaveProjectScreen

    async def scenario(app, pilot, log):
        cb: list = []
        queued: list = []
        fakes = _Fakes(app.workarea)
        original = fakes.preview

        def _preview(text):
            if text == "two" and not queued:
                queued.append(True)
                screen.call_next(screen.action_save)
            return original(text)

        screen = SaveProjectScreen(preview=_preview, confirm=fakes.confirm, initial_name="one")
        app.push_screen(screen, cb.append)
        await sd.wait_for(pilot, lambda: fakes.preview_calls == ["one"], "the first preview", 3.0)
        await _settle(pilot, 6)
        await sd.set_name(pilot, app, "two")
        await sd.wait_for(pilot, lambda: len(fakes.confirm_calls) >= 1, "the queued save", 3.0)
        await _settle(pilot, 4)
        first = (fakes.confirm_calls[0], list(cb), sd.where_text(screen))
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return first, list(cb)

    (call, cb_first, where), cb_after = _run(tmp_path / "app", scenario)
    assert call == ("two", None), call
    assert cb_first == [], cb_first
    assert all(t in where for t in CHANGED), where
    assert len(cb_after) == 1 and cb_after[0] is not None and cb_after[0].project_name == "two", cb_after


def test_tc_b100_65_dialog_save_as_leaves_no_session_for_the_next_direct_save(tmp_path: Path) -> None:
    """MUT11-M-42 (E5), S11-10, R3-01, B11-89: ``P`` open; save as ``Q``
    through the dialog (its live session holds the lazy inventory); after
    the router returns the app holds no per-open Save state; then 1 entry
    applied and a direct save of ``R`` → ``R`` holds the patched image.

    Why: the router drops the dialog's session on every route out; a
    session left behind would plan the next save from pre-patch inputs.
    Negative control: the router leaves ``_save_session`` set → it survives
    the save as, and ``R`` is planned with the unpatched image → RED."""
    from s19_app.tui.screens import SaveProjectPayload
    from tests.support.independent_reader import read_s19

    base = tmp_path / "app"
    project = projects.save_case01_project(base, "P", files=("firmware.s19",))
    projects.write_tree(project, projects.AT09_FILES)

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        await sd.save_through_dialog(pilot, app, "Q", confirm="alt+s")
        await sd.wait_for(pilot, lambda: (app.workarea / "Q" / "project.json").is_file(), "the save as Q", 10.0)
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await _settle(pilot, 6)
        state_q = (app._save_session, app._save_confirmed)
        _add_direct(app, 0x8000007C, (0xDE, 0xAD, 0xBE, 0xEF))
        _apply_direct(app)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="R"))
        await sd.wait_for(pilot, lambda: (app.workarea / "R" / "project.json").is_file(), "the save of R", 10.0)
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await _settle(pilot, 6)
        return state_q, sorted((app.workarea / "R").glob("*.s19"))

    state_q, images = _run(base, scenario, size=(220, 60))
    assert state_q == (None, None), state_q
    patched = [p for p in images if read_s19(p).data.get(0x8000007C) == 0xDE]
    assert patched, [p.name for p in images]


def test_tc_b100_65_confirm_is_not_reused_for_another_typed_name(tmp_path: Path) -> None:
    """MUT11-M-45 (E5), ruling Q-2, B11-14: ``confirm`` approved ``A`` (the
    prepared save the router may reuse), then the router gets a payload with
    that same plan object but the name ``B`` → the held save is not reused:
    the router prepares ``B`` afresh and saves it; no folder ``A`` is made.

    Why: the held save fixes its target folder; reusing it for another
    typed name writes to a folder the payload does not name. Negative
    control: the name clause dropped → the router commits the held save →
    folder ``A`` is made and no ``B`` → RED."""
    from s19_app.tui.screens import SaveProjectPayload

    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        painted = app._save_dialog_preview("A", app._current_save_session())
        verdict = app._confirm_project_save("A", painted.plan)
        held = app._save_confirmed is not None
        app._handle_save_dialog(
            SaveProjectPayload(parent_folder=str(app.workarea), project_name="B", plan=painted.plan)
        )
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await _settle(pilot, 8)
        return verdict, held, (app.workarea / "A").exists(), (app.workarea / "B" / "project.json").is_file()

    verdict, held, a_made, b_saved = _run(base, scenario)
    assert verdict is None and held, (verdict, held)
    assert a_made is False and b_saved is True, (a_made, b_saved)


def test_tc_b100_65_document_free_name_walk_folds_case(tmp_path: Path) -> None:
    """MUT11-M-96 (E5), ruling Q10, R3-02, A11-04: ``P`` holds
    ``patches/Changes.json`` (other bytes) and the change document
    ``notes/changes.json``, loaded from that file; save as ``Q`` → the
    document is placed into ``patches/`` beside the copied ``Changes.json``:
    the painted row and the plan name ``patches/changes_1.json`` ``new``,
    and ``Q`` holds ``patches/changes_1.json`` (the document's bytes) and
    ``patches/Changes.json`` (unchanged).

    Why: on a case-insensitive volume ``changes.json`` is taken by
    ``Changes.json``, so the plan must walk to the free name the save uses.
    Negative control: the free-name walk compares names without case
    folding → the plan says ``changes.json`` while the save writes
    ``changes_1.json`` → RED."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True, exist_ok=True)
    project = projects.seed_document_project(
        _wa(base), "P", document="notes/changes.json", record_document=False, active_document=None
    )
    (project / "patches").mkdir()
    sibling = b'{"other": 1}\n'
    (project / "patches" / "Changes.json").write_bytes(sibling)
    document_bytes = (project / "notes" / "changes.json").read_bytes()

    async def scenario(app, pilot, log):
        await _open_project_direct(pilot, app, "P")
        assert app._change_service.load(str(app.workarea / "P" / "notes" / "changes.json"), app.base_dir).ok
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "Q")
        await sd.wait_painted(pilot, app, "Q", "new folder", "project.json", timeout=10.0)
        rows = sd.summary_rows(app.screen)
        plan_doc = [(r.landing.name, r.action) for r in app.screen.plan.rows if r.role == "document"]
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: (app.workarea / "Q" / "project.json").is_file(), "the save as Q", 10.0)
        await _settle(pilot, 6)
        q = app.workarea / "Q" / "patches"
        return rows, plan_doc, {p.name: p.read_bytes() for p in q.iterdir()}

    rows, plan_doc, patches = _run(base, scenario, size=(220, 60))
    doc_rows = [r for r in rows if r.startswith("document")]
    assert doc_rows == ["document changes.json → patches/changes_1.json — new"], rows
    assert plan_doc == [("changes_1.json", "new")], plan_doc
    assert patches == {"Changes.json": sibling, "changes_1.json": document_bytes}, sorted(patches)


# ---------------------------------------------------------------------------
# TC-B100-66 — LLR-173.7 extended: the Save dialog paints no decision id
# ---------------------------------------------------------------------------


def test_tc_b100_66_save_dialog_paints_no_decision_id(tmp_path: Path) -> None:
    """LLR-173.7 (TC-B100-66 Inc 11 extension, B11-57, S2-4; 6 scenarios):
    the painted ``#save_where`` and summary text of the dialog in the fresh,
    open-project, merge, save-as, refused and empty-Save scenarios hold 0
    matches of ``\\bD\\d+\\b``, ``\\bO-\\d+``, ``VS-``, ``LLR-``, ``HLR-``; so
    does every string literal of the ``SaveProjectScreen`` class body.

    Why: painted strings are English and carry no internal decision id.
    Negative control: the pc_B hint ``Browse is gone (D7)`` shipped → 1
    match → RED. RED (base): no summary is painted."""
    texts = {}
    for key in ("fresh", "files", "merge", "saveas", "refused"):
        out = _scenario_paint(tmp_path / key, key)
        texts[key] = out["where"] + "\n" + "\n".join(out["rows"])
        assert out["rows"] or key == "refused", (key, out)
    base = tmp_path / "empty" / "app"
    src = _sources(tmp_path, folder="src_empty")

    async def empty(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await pilot.press("alt+s")
        await sd.wait_painted(pilot, app, *EMPTY)
        return sd.painted(app.screen)

    texts["empty"] = _run(base, empty)
    hits = {k: DECISION_ID.findall(v) for k, v in texts.items() if DECISION_ID.findall(v)}
    assert hits == {}, hits
    tree = ast.parse((ROOT / "s19_app" / "tui" / "screens.py").read_text(encoding="utf-8"))
    dialog = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "SaveProjectScreen")
    doc_nodes = set()
    for node in ast.walk(dialog):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                doc_nodes.add(id(first.value))
    literals = [
        n.value for n in ast.walk(dialog)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in doc_nodes
    ]
    assert [s for s in literals if DECISION_ID.search(s)] == [], literals


# ---------------------------------------------------------------------------
# AT-B100-16 — HLR-175f (open), HLR-175 (folder), HLR-175b (clash), HLR-175d
# (empty), HLR-175c (escape): one chain, black-box, keys and widget ids only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", SIZES)
def test_at_b100_16_save_dialog_open_folder_clash_empty_escape(tmp_path: Path, size: tuple) -> None:
    """AT-B100-16 (HLR-175f, HLR-175, HLR-175b, HLR-175d, HLR-175c), driven
    only through keys and the dialog's widget ids in a scratch work area,
    at both reference sizes:

      - open half: with ``firmware.s19`` loaded through the Load dialog,
        ``ctrl+s`` opens the dialog with the focus in ``#project_name``;
        typing ``s`` puts ``s`` in the field;
      - folder half: ``a b`` → ``#save_where`` names ``ab`` and ``new
        folder``;
      - escape half: after typing that valid name, ``escape`` closes the
        dialog and no folder ``ab`` appears;
      - clash half: with ``ab`` and ``P2`` saved through the dialog and
        ``P2`` opened through the Load dialog, ``a b`` → ``already a
        project`` and ``choose another name`` painted BEFORE Save;
      - empty half: the field emptied, ``alt+s`` → ``name is empty`` and
        ``type a project name``, and the dialog stays; ``escape`` closes
        it, and no folder appeared beyond ``ab`` and ``P2``.

    Why: the engineer sees the real folder and every refusal before Save,
    and can always leave by ``escape``. Negative control: executed on the
    9a tree (P11-2): ``#save_summary: 0 #save_where: 0``, ``focused at
    open: … project_parent_path``, ``typed 'a b' -> … 'ab' folder line?
    False``, ``escape -> stack: ['Screen', 'SaveProjectScreen']``, ``empty
    Save click -> … 'name is empty'? False`` → RED."""
    base = tmp_path / "app"
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        out = {}
        await _load_by_keys(pilot, app, src / "firmware.s19")
        await pilot.press("ctrl+s")
        await sd.wait_for(pilot, lambda: sd.is_save_dialog(app.screen), "the Save dialog")
        await sd.wait_recompute(pilot)
        out["open"] = (len(app.screen_stack), _focused_id(app))
        await pilot.press("s")
        await _settle(pilot, 4)
        out["s"] = sd.name_input(app.screen).value
        await sd.type_name(pilot, app, "a b")
        # E4 integration: wait for the line of ``ab`` itself; the stale
        # ``s — new folder`` line already holds ``new folder``.
        await sd.wait_for(
            pilot,
            lambda: _where_line_for_text(sd.where_text(app.screen), "ab", "new folder"),
            "the folder line naming ab",
        )
        await _settle(pilot, 4)
        out["folder"] = sd.where_text(app.screen)
        await pilot.press("escape")
        await _settle(pilot, 8)
        out["escape"] = (len(app.screen_stack), (app.workarea / "ab").exists())
        await sd.save_through_dialog(pilot, app, "ab", confirm="alt+s")
        await sd.wait_for(pilot, lambda: (app.workarea / "ab" / "project.json").is_file(), "ab saved")
        await settle_workers(pilot)  # Inc 12b re-pin: the save ends on its worker
        await sd.save_through_dialog(pilot, app, "P2", confirm="alt+s")
        await sd.wait_for(pilot, lambda: (app.workarea / "P2" / "project.json").is_file(), "P2 saved")
        await _settle(pilot, 6)
        await _open_project_by_keys(pilot, app, "P2")
        listing0 = sd.workarea_listing(app.workarea)
        await pilot.press("ctrl+s")
        await sd.wait_for(pilot, lambda: sd.is_save_dialog(app.screen), "the Save dialog over P2")
        await sd.wait_recompute(pilot)
        await sd.type_name(pilot, app, "a b")
        await sd.wait_painted(pilot, app, *CLASH)
        out["clash"] = (sd.where_text(app.screen), sd.is_save_dialog(app.screen))
        await sd.clear_name(pilot, app)
        await sd.wait_recompute(pilot)
        await pilot.press("alt+s")
        await sd.wait_painted(pilot, app, *EMPTY)
        out["empty"] = (sd.where_text(app.screen), sd.is_save_dialog(app.screen))
        await pilot.press("escape")
        await _settle(pilot, 8)
        out["closed"] = len(app.screen_stack)
        out["new"] = sorted(sd.workarea_listing(app.workarea) - listing0)
        out["folders"] = sorted(p.name for p in app.workarea.iterdir() if p.is_dir())
        return out

    out = _run(base, scenario, size=size, notifications=True)
    assert out["open"] == (2, "project_name"), out
    assert out["s"] == "s", out
    assert _where_line_for_text(out["folder"], "ab", "new folder"), out
    assert out["escape"] == (1, False), out
    clash, clash_open = out["clash"]
    assert all(t in clash for t in CLASH) and clash_open, out
    empty, empty_open = out["empty"]
    assert all(t in empty for t in EMPTY) and empty_open, out
    assert out["closed"] == 1 and out["new"] == [], out
    assert "ab" in out["folders"] and "P2" in out["folders"], out


# ---------------------------------------------------------------------------
# AT-B100-21 — HLR-175 (painted half) and HLR-175a (executed half): the 7
# scenarios, black-box
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", SCENARIOS)
def test_at_b100_21_painted_plan_is_the_saved_tree(tmp_path: Path, key: str) -> None:
    """AT-B100-21, both halves, per scenario (fresh, pending patch, refused,
    ``files``, document, merge, save-as), driven by keys and the dialog's
    widget ids (projects built by real saves; files loaded and projects
    opened through the Load dialog; the patch added and applied in the
    Patch Editor), at 220 columns:

      - painted half (HLR-175): each painted summary row that names a file,
        a folder or ``project.json`` matches its row of the dialog's plan
        (read from ``SaveProjectScreen.plan``, the declared exception) by
        landing name and action word, one for one (0 differences);
      - executed half (HLR-175a): ``alt+s``; then that same plan — never
        recomputed by the test — equals the tree written under its target
        by full path and action (the gather homes excluded by name); the
        refused scenario keeps the dialog open and writes 0 new paths.

    Why: R-PC — one plan, painted and executed; the operator's P-C note.
    Negative control: a handler that places a file the plan did not name →
    1 tree row without a plan row → RED; on the 9a tree the dialog paints
    no summary and holds no plan (P11-2) → RED."""
    out = _scenario_paint(tmp_path, key, by_keys=True, save=True)
    plan = out["painted_plan"]
    if key == "refused":
        assert any(t in out["where"] for t in SECOND_MAC), out["where"]
        assert out["rows"] == [] and out["still_open"] is True and out["new_paths"] == [], out
        return
    _assert_rows_equal_plan(out["rows"], plan)
    assert any(m.startswith("Saved project to") for m in out["messages"]), out["messages"]
    workarea = out["workarea"]
    _assert_tree_equals_plan(
        plan,
        _target_digests(out["before"], plan, workarea),
        _target_digests(out["after"], plan, workarea),
    )


# ---------------------------------------------------------------------------
# Late arms (E3 rulings A11-07, P-4 / B11-53; interfaces Q-2 / S-a values)
# ---------------------------------------------------------------------------


def test_tc_b100_65_payload_plan_field_and_preview_value_types(tmp_path: Path) -> None:
    """LLR-175.4l, LLR-175.4a, interfaces Q-2 and S-a (Y-1, Y-2, V-1):
    ``SaveProjectPayload(parent_folder, project_name)`` still builds with
    ``plan is None``, ``batch == ()`` and ``assignments == {}`` (the 56
    direct test calls); a payload carrying a plan equals one without
    (``compare=False``) and is frozen; ``SavePreview`` is a frozen value
    (assigning ``rows`` raises ``FrozenInstanceError``) and two equal-valued
    previews compare equal.

    Why: the router matches the dismissed payload to the confirmed save by
    the plan's identity, never by equality, and the direct callers must not
    change. Negative control: ``plan`` added without a default → every
    direct call raises ``TypeError`` → RED; ``compare=True`` → the two
    payloads differ → RED."""
    from s19_app.tui.screens import SavePreview, SaveProjectPayload
    from s19_app.tui.services.project_gather_service import SavePlan

    workarea = tmp_path / "wa"
    bare = SaveProjectPayload(parent_folder=str(workarea), project_name="P9")
    assert bare.plan is None and bare.batch == () and dict(bare.assignments) == {}
    plan = SavePlan(target=workarea / "ab", target_kind="new", rows=(), image="", manifest_keys=())
    with_plan = SaveProjectPayload(str(workarea), "ab", plan=plan)
    assert with_plan == SaveProjectPayload(str(workarea), "ab") and with_plan.plan is plan
    with pytest.raises(dataclasses.FrozenInstanceError):
        with_plan.plan = None
    preview = SavePreview(where=(("ab - new folder", "info"),), rows=("image firmware.s19 - new",), plan=None,
                          refused=False)
    assert preview.where[0][1] == "info"
    with pytest.raises(dataclasses.FrozenInstanceError):
        preview.rows = ()
    assert preview == SavePreview(where=(("ab - new folder", "info"),), rows=("image firmware.s19 - new",),
                                  plan=None, refused=False)


def test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog(tmp_path: Path) -> None:
    """LLR-175.1i, A11-07, B11-84 (1 of 1): target ``m2`` holds two MAC files
    (``other.mac``, ``third.mac``) and a ``project.json``; the session is
    S19-only, so the plan's second-file rule does not fire, but the
    project-files check does → the dialog paints ``more than one MAC file``
    before Save; ``alt+s`` keeps the dialog open; 0 new paths.

    The refusal carries the merge plan (with rows); the dialog paints 0
    summary rows (LLR-175.1i, MUT11-M-74).

    Why: the commit's "more than one MAC" refusal reached the engineer only
    after the dialog had said "merges". Negative control: the check's error
    discarded in the preparation (base) → the dialog paints ``merges into
    an existing project`` and the commit refuses after it closed → RED; a
    refused preview that keeps the plan's rows → rows painted → RED."""
    base = tmp_path / "app"
    m2 = projects.save_case01_project(base, "m2", files=("firmware.s19",))
    for name in ("other.mac", "third.mac"):
        (m2 / name).write_bytes((CASE01_DIR / "firmware.mac").read_bytes())
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        listing0 = sd.workarea_listing(app.workarea)
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "m2")
        await sd.wait_painted(pilot, app, "more than one MAC file")
        text = sd.where_text(app.screen)
        refused = (len(app.screen.plan.rows) if app.screen.plan is not None else 0, sd.summary_rows(app.screen))
        await pilot.press("alt+s")
        await _settle(pilot, 8)
        return text, refused, sd.is_save_dialog(app.screen), sorted(sd.workarea_listing(app.workarea) - listing0)

    text, (plan_rows, rows), still, new = _run(base, scenario)
    assert "merges into an existing project" not in text, text
    assert plan_rows >= 1 and rows == [], (plan_rows, rows)
    assert still is True and new == [], (still, new)


def test_tc_b100_65_active_variant_stem_collision_is_predicted_exactly(tmp_path: Path) -> None:
    """LLR-175.4f boundary, P-4, B11-53 (1 of 1): target ``ab`` holds
    ``firmware.hex``; the session image ``firmware.s19`` lands as
    ``firmware.s19`` and its stem collides with the HEX → the row names
    ``active variant firmware.s19``, and after ``alt+s`` ``ab/project.json``
    records ``active_variant == "firmware.s19"`` (the duplicate-id rule of
    the variant set).

    Negative control: a stem-only prediction → ``active variant firmware``
    → the after-save equality fails → RED."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True, exist_ok=True)
    hex_src = tmp_path / "hexsrc"
    hex_src.mkdir()
    (hex_src / "firmware.hex").write_bytes(_tiny_hex())
    _save_project_from(base, "ab", [hex_src / "firmware.hex"])
    src = _sources(tmp_path)

    async def scenario(app, pilot, log):
        await _load_direct(pilot, app, src / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "ab")
        await sd.wait_painted(pilot, app, "merges into an existing project", "active variant")
        rows = [r for r in sd.summary_rows(app.screen) if "active variant" in r]
        mark = len(log.messages)
        await pilot.press("alt+s")
        await sd.wait_for(pilot, lambda: any(m.startswith("Saved project to") for m in log.since(mark)),
                          "the merge", 10.0)
        await _settle(pilot, 6)
        return rows, projects.read_manifest(app.workarea / "ab").get("active_variant")

    rows, active = _run(base, scenario, size=(220, 60))
    assert len(rows) == 1 and "active variant firmware.s19" in rows[0], rows
    assert active == "firmware.s19", active
