"""Batch-100 increment 8b — save as copies the whole project, an A2L-only
project opens, and only folders of this work area are projects (HLR-171,
HLR-171a, HLR-171b).

Covers (E4 test design, written from the approved Code-Wire examples of
``inc-8b/codewire/proto-8b-app.md`` / ``proto-8b-gather.md``, the rulings
R1–R16 of ``inc-8b/E3-rulings.md`` and the thresholds and negative controls
of ``01-requirements.md``, independently of the implementation):

  - TC-B100-31 — LLR-171.1 (sub-folder and top-level copy, R3, R10),
    .1a/.1b/.1c (links never followed, named in one status line), .1d/.1e/.1i
    (the free-space total, R7), .1f (P unchanged), .1g (merge / into itself
    copy nothing), .1h (the carried records), .1j (the R1 / R13 ceilings),
    .1k (unreadable entries, R8), .1l (the session follows Q, R9), LLR-171.6 /
    .6a (R4: an empty selection never clears ``batch``), LLR-171.7 / .7a /
    .7b (painted names, R6; a failed copy rolls back in user terms).
  - TC-B100-32 — LLR-171.2, .2a–.2g (the A2L-only load, its refusals and
    the A2L guard, R5).
  - TC-B100-33 — LLR-171.3, .3a (the Save parent must be this work area).
  - TC-B100-62 — LLR-171.4c, .4e, .4f, .4g (listing, load and Save target
    refuse a link or junction and anything outside this work area).
  - AT-B100-09, AT-B100-10, AT-B100-11 — black-box through keys and dialogs
    at 118 and 220 columns.

New Inc 8b symbols (``painted_names``) are imported inside their node, so
every behavioural node still runs — and fails on its own assertion — at the
base. Oracles: digests with ``hashlib``; ``project.json`` with the stdlib;
status oracles read the full ``set_status`` message (``StatusLog``); the
free-space total is recomputed from the fixture's sizes (``save_as_total``).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
import time
import unicodedata
from pathlib import Path

import pytest

import s19_app.tui.app as app_module
import s19_app.tui.workspace as workspace_module
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_SUBDIR

from tests.support import b100_links
from tests.support import b100_projects as projects
from tests.support.b100_projects import LOAD_RESULT_CLOSE

AT_SIZES = [(118, 54), (220, 60)]
SAVED = "Saved project to"
LINK_LINE = "links or junctions not copied"
SCRUBBED_CATEGORIES = ("Cc", "Cf", "Zl", "Zp", "Cs")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _with(messages: list, *tokens: str) -> list:
    """The messages that hold every token."""
    return [m for m in messages if all(token in m for token in tokens)]


def _saved(messages: list) -> bool:
    return any(m.startswith(SAVED) for m in messages)


def _under(path: Path, root: Path) -> bool:
    a = os.path.normcase(os.path.abspath(str(path)))
    b = os.path.normcase(os.path.abspath(str(root)))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def _spy_mkdir(monkeypatch: pytest.MonkeyPatch, root: Path) -> list:
    """Every ``Path.mkdir`` call whose path is ``root`` or below it (made or
    refused): a check placed after ``mkdir`` shows here even when a
    rollback removed the folder again."""
    calls: list = []
    original = Path.mkdir

    def _mkdir(self, *args, **kwargs):
        if _under(self, root):
            calls.append(Path(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _mkdir)
    return calls


def _patch_free_space(monkeypatch: pytest.MonkeyPatch, free: int) -> None:
    def _usage(path):
        return shutil._ntuple_diskusage(free * 4, free * 3, free)

    monkeypatch.setattr(shutil, "disk_usage", _usage)


def _files_in(root: Path) -> list:
    """Relative names of every regular file under ``root``, links not
    followed."""
    return sorted(projects.tree_digests(root)) if root.exists() else []


def _a2l_tags(app) -> int:
    data = app.current_a2l_data
    return len(data.get("tags", [])) if isinstance(data, dict) else 0


def _temp_files(base: Path) -> list:
    temp = _workarea(base) / workspace_module.WORKAREA_TEMP
    if not temp.exists():
        return []
    return sorted(p.relative_to(temp).as_posix() for p in temp.rglob("*") if p.is_file())


async def _open_p(pilot, app, name: str = "P") -> None:
    await projects.load_project(pilot, app, name)


async def _save(pilot, app, log, name: str, parent=None) -> list:
    """Run the shipped Save project handler for ``name`` under ``parent``
    (default: the app's work area) and wait for its outcome line."""
    from s19_app.tui.screens import SaveProjectPayload

    mark = len(log.messages)
    app._handle_save_dialog(
        SaveProjectPayload(
            parent_folder=str(app.workarea if parent is None else parent),
            project_name=name,
        )
    )
    await _settle_outcome(pilot, log, mark)
    return log.since(mark)


#: Every outcome line a save or a refusal can paint (the base's own refusal
#: texts included, so a RED on the base is read from its line, not from a
#: wait that timed out).
OUTCOME_TOKENS = projects.SAVE_OUTCOMES + ("already has", "Nothing to save", "Parent folder", "Refusing")


async def _settle_outcome(pilot, log, mark: int, attempts: int = 200) -> None:
    """Poll until an outcome line is painted, then a few more frames. The
    handler runs synchronously, so when no known outcome appears the test
    goes on and its own assertion names what WAS painted."""
    for _ in range(attempts):
        if any(token in m for m in log.since(mark) for token in OUTCOME_TOKENS):
            break
        await pilot.pause()
    for _ in range(6):
        await pilot.pause()


def _save_as_from_p(base: Path, name: str = "Q", before=None) -> tuple:
    """Fresh app: open P, optionally run ``before(app)``, Save project as
    ``name``; returns (messages, current_project, app facts)."""

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        if before is not None:
            before(app)
        messages = await _save(pilot, app, log, name)
        return messages, app.current_project, app

    messages, current, app = projects.run_app(base, _scenario)
    return messages, current


def _rmdir_quiet(link: Path) -> None:
    try:
        os.rmdir(link)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# TC-B100-31 — LLR-171.1, .1f: every regular file is copied, P is unchanged
# ---------------------------------------------------------------------------


def test_tc_b100_31_save_as_copies_every_subfolder_file(tmp_path: Path) -> None:
    """LLR-171.1 (``p06`` C): P with one file in each of the 7 project homes
    and the nested ``reports/2026/r2.md``, saved as Q → 8 of 8 files in Q at
    the same relative path, 0 missing, 0 with a differing SHA-256; the open
    project becomes Q; P's (path, SHA-256) set is unchanged (LLR-171.1f);
    with 0 links, 0 lines hold "not copied" (LLR-171.1c empty arm).

    RED (base ebe6d0c, P-9): Q holds only the top-level files → 8 missing.
    Negative controls: a first-level-only copy → ``reports/2026/r2.md``
    missing; a move instead of a copy → P's set changes."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    before = projects.tree_digests(project_dir)

    messages, current = _save_as_from_p(base)

    assert _saved(messages), messages
    got = projects.tree_digests(_workarea(base) / "Q")
    expected = {rel: _sha(data) for rel, data in projects.SUBFOLDER_FILES.items()}
    missing = sorted(rel for rel in expected if rel not in got)
    differing = sorted(rel for rel in expected if rel in got and got[rel] != expected[rel])
    assert missing == [] and differing == [], (missing, differing, messages)
    assert current == "Q", messages
    assert projects.tree_digests(project_dir) == before, "save as changed the open project's files"
    assert _with(messages, "not copied") == [], messages


def test_tc_b100_31_save_as_copies_the_top_level_files_but_not_the_backups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.1 R3 + R10, R11: P's top-level ``a.json``, ``notes.txt`` and
    a second variant ``other.s19`` are in Q byte-equal at the same names;
    ``firmware.s19`` is written once by its row (no ``firmware_1.s19``),
    ``project.json`` is this save's, 0 files named ``a_1.json`` (the
    ``carried`` row is executed once: ``place_into_workarea`` is called once
    with source ``P/a.json``); 0 of the two ``project.json.previous-*``
    backups (one in other case, matched with ``normcase``); Q's ``files``
    keys hold ``other.s19`` and the variant set holds 2 variants (the
    top-level copy runs before the variant rebuild, R11).

    RED (base): ``Q/a.json`` absent, 0 placement calls from ``P/a.json``.
    Negative controls: the sub-folders-only copy → ``Q/a.json`` absent; no
    backup exclusion → a backup in Q; the rows loop not skipping carried
    rows → 2 calls; the top-level copy after the rebuild → 1 variant."""
    base = tmp_path / "app"
    other_bytes = (projects.CASE02_DIR / "firmware.s19").read_bytes()
    top = {
        "a.json": b'{"top": "a"}',
        "notes.txt": b"notes\n",
        "other.s19": other_bytes,
        "project.json.previous-20261030T000000Z": b'{"schema_version": 1}',
        "Project.JSON.previous-20261029T000000Z": b'{"schema_version": 1}',
    }
    project_dir = projects.build_save_as_project(base, sub_files={}, top_files=top)
    source_a = project_dir / "a.json"
    calls: list = []
    original = app_module.place_into_workarea

    def _spy(source, *args, **kwargs):
        if os.path.normcase(str(source)) == os.path.normcase(str(source_a)):
            calls.append(source)
        return original(source, *args, **kwargs)

    monkeypatch.setattr(app_module, "place_into_workarea", _spy)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        messages = await _save(pilot, app, log, "Q")
        variants = app._variant_set.variants if app._variant_set is not None else ()
        return messages, len(variants)

    messages, variant_count = projects.run_app(base, _scenario)

    target = _workarea(base) / "Q"
    assert _saved(messages), messages
    for name in ("a.json", "notes.txt", "other.s19"):
        assert (target / name).is_file(), (name, _files_in(target), messages)
        assert (target / name).read_bytes() == top[name], name
    names = _files_in(target)
    assert "a_1.json" not in names and "firmware_1.s19" not in names, names
    assert names.count("firmware.s19") == 1, names
    assert [n for n in names if os.path.normcase(n).startswith("project.json.previous-")] == [], names
    assert len(calls) == 1, f"place_into_workarea from P/a.json called {len(calls)} times"
    written = projects.read_manifest(target)
    assert "other.s19" in (written.get("files") or {}), written
    assert variant_count == 2, variant_count


def test_tc_b100_31_save_as_with_no_subfolder_copies_none(tmp_path: Path) -> None:
    """LLR-171.1 empty arm: P with no sub-folder and no other top-level
    file, saved as Q → 0 sub-folder files in Q, status holds "Saved project
    to" (holds at base; guards a copy that invents folders)."""
    base = tmp_path / "app"
    projects.build_save_as_project(base, sub_files={})
    messages, _ = _save_as_from_p(base)
    assert _saved(messages), messages
    assert [n for n in _files_in(_workarea(base) / "Q") if "/" in n] == []


# ---------------------------------------------------------------------------
# LLR-171.1a / .1b / .1c / LLR-167.6b — links are never followed, and named
# ---------------------------------------------------------------------------


def test_tc_b100_31_links_are_skipped_and_named(tmp_path: Path) -> None:
    """LLR-171.1a/b/c: P with the top-level junction ``linked`` and the
    nested junction ``reports/j`` (both to an outside folder holding
    ``secret.txt``) and the file symbolic link ``patches/l.json`` → 0 files
    named ``secret.*`` in Q, ``Q/linked`` and ``Q/patches/l.json`` do not
    exist, the outside folder is unchanged, and ONE status message holds
    "links or junctions not copied" with ``linked``, ``reports/j`` and
    ``patches/l.json`` (3 of 3); Q still holds ``flows/f1.json`` (the copy
    ran). Not run where the platform cannot create the links.

    RED (base): 0 lines name the links, and Q lacks ``flows/f1.json``.
    Negative controls: a plain ``os.walk`` copy → ``secret.txt`` in Q; a
    silent skip → 0 of 3 named."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    outside = projects.outside_folder(tmp_path)
    try:
        links = projects.add_three_links(project_dir, outside)
    except OSError as exc:
        pytest.skip(f"not run: a link could not be created here ({exc})")
    outside_before = projects.tree_digests(outside)

    messages, _ = _save_as_from_p(base)

    target = _workarea(base) / "Q"
    assert _saved(messages), messages
    names = _files_in(target)
    assert [n for n in names if Path(n).name.startswith("secret.")] == [], names
    assert not os.path.lexists(target / "linked")
    assert not os.path.lexists(target / "patches" / "l.json")
    assert "flows/f1.json" in names, names
    assert projects.tree_digests(outside) == outside_before
    lines = _with(messages, LINK_LINE)
    assert len(lines) == 1, messages
    assert all(link in lines[0] for link in links), lines


def test_tc_b100_31_junction_cycle_ends(tmp_path: Path) -> None:
    """LLR-171.1a cycle: P with the junction ``flows/loop`` → P, saved as Q
    → the save completes in under 5 s, 0 entries under ``Q/flows/loop``,
    ``Q/flows/f1.json`` present.

    RED (base): ``Q/flows/f1.json`` absent. Negative control: a walk that
    follows the junction never ends or copies P into Q again."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    loop = project_dir / "flows" / "loop"
    b100_links.create_junction(loop, project_dir)
    try:

        async def _scenario(app, pilot, log):
            await _open_p(pilot, app)
            start = time.perf_counter()
            messages = await _save(pilot, app, log, "Q")
            return messages, time.perf_counter() - start

        messages, elapsed = projects.run_app(base, _scenario)
    finally:
        _rmdir_quiet(loop)
    target = _workarea(base) / "Q"
    print(f"[timing] save as with a junction cycle: {elapsed:.2f} s")
    assert _saved(messages), messages
    assert elapsed < 5.0, elapsed
    assert not os.path.lexists(target / "flows" / "loop")
    assert (target / "flows" / "f1.json").is_file(), _files_in(target)


def test_tc_b100_31_link_line_names_at_most_ten(tmp_path: Path) -> None:
    """LLR-171.7a (R6): 25 junctions in ``P/reports`` → 1 status message
    holding "links or junctions not copied", exactly 10 of the 25 link
    names and "and 15 more".

    RED (base): no such line. Negative control: painting every name → 25
    names in the line."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    outside = projects.outside_folder(tmp_path)
    names = projects.add_junctions(
        project_dir, outside, [f"reports/l{i:02d}" for i in range(25)]
    )

    messages, _ = _save_as_from_p(base)

    lines = _with(messages, LINK_LINE)
    assert len(lines) == 1, messages
    shown = [name for name in names if name in lines[0]]
    assert len(shown) == 10, (shown, lines[0])
    assert "and 15 more" in lines[0], lines[0]


def test_tc_b100_31_link_names_are_scrubbed(tmp_path: Path) -> None:
    """LLR-171.7 (R6, S3R2-4): junctions named ``patches/<U+202E>osj.exe.json``,
    ``patches/a<U+061C>b`` and ``patches/c<U+2028>d`` → the link line holds
    ``patches/osj.exe.json``, ``patches/ab`` and ``patches/cd`` and 0
    characters of Unicode category Cc, Cf, Zl, Zp or Cs.

    RED (base): no link line. Negative controls: no scrub → U+202E painted;
    round 1's fixed list instead of the categories → U+061C painted."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    outside = projects.outside_folder(tmp_path)
    raw = ["patches/‮osj.exe.json", "patches/a؜b", "patches/c d"]
    try:
        projects.add_junctions(project_dir, outside, raw)
    except OSError as exc:
        pytest.skip(f"not run: the platform refused a name ({exc})")

    messages, _ = _save_as_from_p(base)

    lines = _with(messages, LINK_LINE)
    assert len(lines) == 1, messages
    for painted in ("patches/osj.exe.json", "patches/ab", "patches/cd"):
        assert painted in lines[0], (painted, lines[0])
    bad = [c for c in lines[0] if unicodedata.category(c) in SCRUBBED_CATEGORIES]
    assert bad == [], [hex(ord(c)) for c in bad]


def test_tc_b100_31_painted_names_clip_scrub_and_count() -> None:
    """LLR-171.7 / .7a (R6, S3R2-4), the shared name painter: 25 names → 10
    names and "and 15 more"; 3 names → the 3, no "more"; 0 names → "";
    a 300-character name → 120 characters ending "…"; U+202E, U+200B, ESC,
    U+061C, U+2028 removed; an unpaired surrogate becomes U+FFFD and the
    text encodes as UTF-8.

    RED (base): ``painted_names`` does not exist (new symbol)."""
    from s19_app.tui.services.project_gather_service import painted_names

    many = [f"reports/l{i:02d}" for i in range(25)]
    text = painted_names(many)
    assert sum(1 for name in many if name in text) == 10, text
    assert "and 15 more" in text, text
    three = painted_names(["a", "bb", "ccc"])
    assert all(name in three for name in ("a", "bb", "ccc")) and "more" not in three, three
    assert painted_names([]) == ""
    long_name = "x" * 300
    clipped = painted_names([long_name])
    assert clipped.endswith("…") and len(clipped) == 120, (len(clipped), clipped[-5:])
    scrubbed = painted_names(
        ["patches/‮osj.exe.json", "a​b\x1bc", "a؜b", "c d", "e\udc80f"]
    )
    for expected in ("patches/osj.exe.json", "abc", "ab", "cd", "e�f"):
        assert expected in scrubbed, (expected, scrubbed)
    assert [c for c in scrubbed if unicodedata.category(c) in SCRUBBED_CATEGORIES] == []
    scrubbed.encode("utf-8")


# ---------------------------------------------------------------------------
# LLR-171.1d / .1e / .1i — the free-space total (R7)
# ---------------------------------------------------------------------------


def _free_space_project(tmp_path: Path) -> tuple:
    """P with the 8 sub-folder files and the junction ``linked`` reaching a
    10 MiB outside file; returns (base, T) where T is R7's total over the
    bytes the save writes (image row + 8 copies; the 10 MiB not counted)."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    outside = projects.outside_folder(tmp_path)
    (outside / "big.bin").write_bytes(b"\0" * (10 * 1024 * 1024))
    projects.add_junctions(project_dir, outside, ["linked"])
    sizes = [
        (project_dir / rel).stat().st_size
        for rel in projects.tree_digests(project_dir)
        if rel != "project.json"
    ]
    return base, projects.save_as_total(sizes)


@pytest.mark.parametrize("arm", ["T-1 refused", "T saved"])
def test_tc_b100_31_free_space_is_checked_before_any_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-171.1e / .1i / .1d (R7): T = every written file rounded up to
    4 KiB plus 64 KiB, the 10 MiB behind the junction not counted. Free
    space T − 1 → 1 status message holding "not enough free space" and
    "free disk space or remove files from the project", 0 ``mkdir`` calls
    at or below Q (spy), Q absent; free space exactly T → saved.

    RED (base): no free-space check → the T − 1 arm saves. Negative
    controls: a check after ``mkdir`` → 1 call; ``>=`` → the T arm refused;
    the junction's bytes counted → the T arm refused; no rounding or no
    margin → the T − 1 arm saves."""
    b100_links.require_junctions()
    base, total = _free_space_project(tmp_path)
    target = _workarea(base) / "Q"
    free = total - 1 if arm == "T-1 refused" else total
    _patch_free_space(monkeypatch, free)
    calls = _spy_mkdir(monkeypatch, target)

    messages, _ = _save_as_from_p(base)

    if arm == "T-1 refused":
        lines = _with(messages, "not enough free space", "free disk space or remove files from the project")
        assert len(lines) == 1, (total, messages)
        assert calls == [], calls
        assert not target.exists()
    else:
        assert _saved(messages), (total, messages)
        assert _with(messages, "not enough free space") == [], messages


# ---------------------------------------------------------------------------
# LLR-171.1g — an existing target copies no sub-folder
# ---------------------------------------------------------------------------


def test_tc_b100_31_merge_and_save_into_itself_copy_no_subfolder(tmp_path: Path) -> None:
    """LLR-171.1g (ruling Q2): P open with the 7 sub-folders, saved into the
    existing project R (merge) → 0 files at ``R/flows/f1.json`` (0 of P's
    sub-folder files in R); P saved into itself → P's sub-folder files
    unchanged. Holds at base; guards a copy run for an existing target."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    projects.save_case01_project(base, "R", files=("firmware.s19",))
    sub_before = {k: v for k, v in projects.tree_digests(project_dir).items() if "/" in k}

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        merge = await _save(pilot, app, log, "R")
        return merge

    merge = projects.run_app(base, _scenario)
    r_dir = _workarea(base) / "R"
    assert _saved(merge), merge
    assert [n for n in _files_in(r_dir) if n in projects.SUBFOLDER_FILES] == []

    async def _into_itself(app, pilot, log):
        await _open_p(pilot, app)
        return await _save(pilot, app, log, "P")

    itself = projects.run_app(base, _into_itself)
    assert _saved(itself), itself
    sub_after = {k: v for k, v in projects.tree_digests(project_dir).items() if "/" in k}
    assert sub_after == sub_before


# ---------------------------------------------------------------------------
# LLR-171.1h, LLR-171.6 / .6a — the carried records (R4)
# ---------------------------------------------------------------------------


def test_tc_b100_31_save_as_carries_the_open_projects_records(tmp_path: Path) -> None:
    """LLR-171.1h (ruling Q7): P's ``project.json`` sets ``batch``,
    ``assignments``, ``declared_regions`` and ``gathered``; saved as Q with
    nothing selected → Q's ``project.json`` holds the same 4 records as
    project-relative text (0 absolute strings), ``gathered`` holds P's rows,
    and Q holds the two named files.

    RED (base): a fresh manifest → Q's ``batch`` is empty. Negative
    controls: a fresh manifest → ``batch`` 0 entries; absolute paths →
    "project.json was not written"."""
    base = tmp_path / "app"
    projects.seed_project_with_every_key(_workarea(base))
    seeded = projects.seeded_keys()

    messages, _ = _save_as_from_p(base)

    target = _workarea(base) / "Q"
    assert _saved(messages), messages
    written = projects.read_manifest(target)
    assert written.get("batch") == seeded["batch"], written
    assert written.get("assignments") == seeded["assignments"], written
    assert written.get("declared_regions") == seeded["declared_regions"], written
    for home, rows in seeded["gathered"].items():
        assert set(rows) <= set((written.get("gathered") or {}).get(home, [])), written
    assert projects.absolute_strings(written) == [], written
    for relative in (projects.SEEDED_PATCH, projects.SEEDED_CHECK):
        assert (target / relative).is_file(), (relative, _files_in(target))


def test_tc_b100_31_empty_selection_keeps_batch_for_every_target(tmp_path: Path) -> None:
    """LLR-171.6 / .6a (R4, C-7 confirmed): Load P (``batch`` and
    ``assignments`` seeded), Save project into P with nothing selected →
    P's ``batch`` and ``assignments`` unchanged; then Save project as Q with
    nothing selected → Q's ``batch`` and ``assignments`` equal P's.

    RED (base, C-7): the save into P writes an empty ``batch``. Negative
    control: writing ``payload.batch`` only → P's ``batch`` 0 entries."""
    base = tmp_path / "app"
    project_dir = projects.seed_project_with_every_key(_workarea(base))
    seeded = projects.seeded_keys()

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        into_p = await _save(pilot, app, log, "P")
        after_p = projects.read_manifest(project_dir)
        as_q = await _save(pilot, app, log, "Q")
        return into_p, after_p, as_q

    into_p, after_p, as_q = projects.run_app(base, _scenario)
    assert _saved(into_p), into_p
    assert after_p.get("batch") == seeded["batch"], after_p
    assert after_p.get("assignments") == seeded["assignments"], after_p
    assert _saved(as_q), as_q
    q_manifest = projects.read_manifest(_workarea(base) / "Q")
    assert q_manifest.get("batch") == seeded["batch"], q_manifest
    assert q_manifest.get("assignments") == seeded["assignments"], q_manifest


def test_tc_b100_31_gather_takes_names_from_the_recorded_batch_and_assignments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.6b (R4, A3R2-3, A3R2-4): P records ``batch`` ``["a.json"]``
    and ``assignments`` ``{"firmware": ["c.json"]}``; P holds neither
    ``a.json`` / ``c.json`` at the top level nor ``patches/a.json`` /
    ``patches/c.json``; the common library (``W/patches``) holds both.
    Save project into P with nothing selected → the ``composition_names``
    passed to the gather hold ``a.json`` and ``c.json`` (spy), and
    ``P/patches/a.json`` and ``P/patches/c.json`` are present (gathered by
    this save).

    RED (base): the list is built from the dialog's selection → 0 names,
    both files absent. Negative control: the gather fed from the recorded
    ``batch`` only → ``c.json`` absent."""
    base = tmp_path / "app"
    project_dir = projects.save_case01_project(base, "P", files=("firmware.s19",))
    manifest = projects.read_manifest(project_dir)
    manifest["batch"] = ["a.json"]
    manifest["assignments"] = {"firmware": ["c.json"]}
    (project_dir / "project.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    common = _workarea(base) / "patches"
    common.mkdir(parents=True, exist_ok=True)
    payloads = {"a.json": b'{"entries": [], "tag": "a"}', "c.json": b'{"entries": [], "tag": "c"}'}
    for name, payload in payloads.items():
        (common / name).write_bytes(payload)
    names_seen: list = []
    original = app_module.gather_project_artifacts

    def _spy(*args, **kwargs):
        names_seen.append(tuple(kwargs.get("composition_names", args[1] if len(args) > 1 else ())))
        return original(*args, **kwargs)

    monkeypatch.setattr(app_module, "gather_project_artifacts", _spy)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        return await _save(pilot, app, log, "P")

    messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert names_seen, "the gather was not called"
    assert {"a.json", "c.json"} <= {Path(n).name for n in names_seen[-1]}, names_seen
    for name, payload in payloads.items():
        landed = project_dir / "patches" / name
        assert landed.is_file() and landed.read_bytes() == payload, (name, _files_in(project_dir))


# ---------------------------------------------------------------------------
# LLR-171.1j — the copy ceilings (R1, R12, R13, R16)
# ---------------------------------------------------------------------------


def test_tc_b100_31_copy_ceiling_2000_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.1j (R1, R12): P with ``project.json``, the session image, the
    top-level ``a.json`` and 2 000 one-byte files under ``reports`` — copy
    list 2 001 → 1 status message holding "too many files to copy" and
    "move files out of the project, then save again", 0 ``mkdir`` calls at
    or below Q1, Q1 absent. One file removed (copy list exactly 2 000) →
    saved as Q2 with 2 000 copied files; the wall time of that save is
    printed (R12 records it; not gated — the background copy is Inc 12a).

    RED (base): no ceiling → the 2 001 arm saves. Negative controls: the
    ceiling removed → 2 001 saves; ``>=`` → the 2 000 arm refused."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(
        base, sub_files={}, top_files={"a.json": b'{"top": "a"}'}
    )
    names = projects.bulk_files(project_dir, "reports", 2000)
    q1 = _workarea(base) / "Q1"
    calls = _spy_mkdir(monkeypatch, q1)

    refused, _ = _save_as_from_p(base, "Q1")
    lines = _with(refused, "too many files to copy", "move files out of the project, then save again")
    assert len(lines) == 1, refused[-3:]
    assert calls == [] and not q1.exists(), calls

    (project_dir / names[-1]).unlink()

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        start = time.perf_counter()
        messages = await _save(pilot, app, log, "Q2")
        return messages, time.perf_counter() - start

    saved, elapsed = projects.run_app(base, _scenario)
    print(f"[timing] save as with a 2 000-file copy list: {elapsed:.2f} s")
    q2 = _workarea(base) / "Q2"
    assert _saved(saved), saved[-3:]
    copied = [n for n in _files_in(q2) if n not in ("project.json", "firmware.s19")]
    assert len(copied) == 2000, len(copied)


@pytest.mark.parametrize("components", [32, 33])
def test_tc_b100_31_depth_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, components: int
) -> None:
    """LLR-171.1j depth (R1): a file at 32 path components → saved and in
    Q at the same path; at 33 components → 1 status message holding
    "nested too deep", 0 ``mkdir`` calls at or below Q, Q absent.

    RED (base): the 33 arm saves (no depth check); the 32 arm's file is not
    copied. Negative control: the depth check removed → 33 saves."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files={})
    relative = projects.deep_file(project_dir, components)
    target = _workarea(base) / "Q"
    calls = _spy_mkdir(monkeypatch, target)

    messages, _ = _save_as_from_p(base)

    if components == 32:
        assert _saved(messages), messages
        assert relative in _files_in(target), _files_in(target)
    else:
        assert len(_with(messages, "nested too deep")) == 1, messages
        assert calls == [] and not target.exists(), calls


@pytest.mark.parametrize("arm", ["10000 saved", "10001 refused"])
def test_tc_b100_31_entry_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-171.1j entries (R13, R16): P whose walk yields exactly 10 000
    entries (its top-level files, the folder ``reports`` and empty folders
    nested two levels under it, so the walk OPENS folders) → saved; one
    more empty folder (10 001 entries, 0 files to copy) → 1 status message
    holding "too many files to copy", "over 10 000 entries" and "move files
    out of the project, then save again", 0 ``mkdir`` calls at or below Q,
    Q absent, and the save call returns in under 5 s on the main thread
    (R16; the time is printed).

    RED (base): no entry count → the 10 001 arm saves. Negative control:
    counting regular files only → the 10 001 arm passes the plan."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files={})
    wanted = 10000 if arm == "10000 saved" else 10001
    present = projects.walked_entries(project_dir)
    projects.nested_empty_folders(project_dir, wanted - present - 1)
    assert projects.walked_entries(project_dir) == wanted, "fixture: wrong entry count"
    target = _workarea(base) / "Q"
    calls = _spy_mkdir(monkeypatch, target)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        start = time.perf_counter()
        messages = await _save(pilot, app, log, "Q")
        return messages, time.perf_counter() - start

    messages, elapsed = projects.run_app(base, _scenario)
    print(f"[timing] save as over a {wanted}-entry tree: {elapsed:.2f} s")
    if arm == "10000 saved":
        assert _saved(messages), messages
    else:
        lines = _with(
            messages,
            "too many files to copy",
            "over 10 000 entries",
            "move files out of the project, then save again",
        )
        assert len(lines) == 1, messages
        assert calls == [] and not target.exists(), calls
        assert elapsed < 5.0, elapsed


# ---------------------------------------------------------------------------
# LLR-171.1k — unreadable entries are a refusal (R8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 12])
def test_tc_b100_31_unreadable_entries_refuse_the_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    """LLR-171.1k (R8, S3-2): ``P/flows/x.json.`` (a trailing dot, made
    through the extended-length form) → 1 status message naming
    ``flows/x.json.``, holding "could not be read" and "check that they can
    be opened, then save again", 0 ``mkdir`` calls at or below Q, Q absent;
    12 such entries → 10 named and "and 2 more" (R6).

    RED (base): saved, the entry silently left out. Negative control: an
    unreadable entry dropped silently → saved."""
    if sys.platform != "win32":
        pytest.skip("trailing-dot names are a Windows-only arm")
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    made = []
    try:
        for index in range(count):
            name = "x.json." if index == 0 else f"x{index:02d}.json."
            path = project_dir / "flows" / name
            try:
                projects.write_unnormalised(path)
            except OSError as exc:
                pytest.skip(f"not run: the platform refused a trailing-dot name ({exc})")
            made.append(path)
        target = _workarea(base) / "Q"
        calls = _spy_mkdir(monkeypatch, target)

        messages, _ = _save_as_from_p(base)

        lines = _with(messages, "could not be read", "check that they can be opened, then save again")
        assert len(lines) == 1, messages
        assert "flows/x.json." in lines[0], lines[0]
        if count == 12:
            assert "and 2 more" in lines[0], lines[0]
        assert calls == [] and not target.exists(), calls
    finally:
        for path in made:
            projects.remove_unnormalised(path)
        target = _workarea(base) / "Q"
        for path in made:
            projects.remove_unnormalised(target / "flows" / path.name)


# ---------------------------------------------------------------------------
# LLR-171.7b — a failed copy rolls back in user terms (R6)
# ---------------------------------------------------------------------------


def test_tc_b100_31_failed_copy_rolls_back_in_user_terms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.7b (R6): the 4th of the 8 sub-folder copies raises
    ``PermissionError`` → a status message holding "could not save" and
    "check the folder", 0 messages holding "WinError" or "Refusing", Q
    absent (every copied file and created sub-folder removed), P's files
    unchanged, the open project still P.

    RED (base): no sub-folder copy → saved, Q exists. Negative control:
    the exception text painted → "WinError" in the status."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    before = projects.tree_digests(project_dir)
    original = app_module.place_into_workarea
    seen: list = []

    def _failing(source, *args, **kwargs):
        source_path = Path(source)
        if _under(source_path, project_dir) and source_path.parent != project_dir:
            seen.append(source_path)
            if len(seen) == 4:
                raise PermissionError(13, "[WinError 5] Access is denied", str(source_path))
        return original(source, *args, **kwargs)

    monkeypatch.setattr(app_module, "place_into_workarea", _failing)

    messages, current = _save_as_from_p(base)

    assert _with(messages, "could not save", "check the folder"), messages
    assert _with(messages, "WinError") == [] and _with(messages, "Refusing") == [], messages
    assert not (_workarea(base) / "Q").exists(), _files_in(_workarea(base) / "Q")
    assert projects.tree_digests(project_dir) == before
    assert current == "P", current


# ---------------------------------------------------------------------------
# LLR-171.1l — the session follows Q (R9)
# ---------------------------------------------------------------------------


def test_tc_b100_31_flow_session_folder_follows_q(tmp_path: Path) -> None:
    """LLR-171.1l (R9): after a save as, the Flow panels' painted session
    strip names ``W/Q`` (and no longer ``W/P``).

    RED (base, F-5): the strip still names P. Negative control: no
    republish → the strip names P."""
    base = tmp_path / "app"
    projects.build_save_as_project(base)
    workarea = _workarea(base)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        messages = await _save(pilot, app, log, "Q")
        strip = str(app.query_one("#flow_ext_session").render())
        return messages, strip

    messages, strip = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert str(workarea / "Q") in strip, strip
    assert str(workarea / "P") not in strip.replace(str(workarea / "Q"), ""), strip


# ---------------------------------------------------------------------------
# TC-B100-32 — LLR-171.2, .2a–.2g: the A2L-only load
# ---------------------------------------------------------------------------


def _a2l_only_project(base: Path, name: str = "P") -> Path:
    """An A2L-only project saved by the shipped Save project (``p04`` 10)."""
    return projects.save_case01_project(base, name, files=("firmware.a2l",))


async def _load_by_name(pilot, app, log, name: str) -> list:
    """Run the shipped project load for ``name``; wait until the A2L is
    attached, a data file is open, or a load outcome line is painted."""
    mark = len(log.messages)
    app._handle_load_project(name)
    await projects.wait_for(
        pilot,
        lambda: app.current_project == name
        or any(
            token in m
            for m in log.since(mark)
            for token in ("NOT loaded", "No supported files", "not found", "Project validation")
        ),
        f"the project load of {name}",
    )
    for _ in range(8):
        await pilot.pause()
    return log.since(mark)


def _spy_resets(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    original = app_module.S19TuiApp._reset_project_session

    def _reset(self, *args, **kwargs):
        calls.append(1)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(app_module.S19TuiApp, "_reset_project_session", _reset)
    return calls


def test_tc_b100_32_a2l_only_project_opens_with_its_own_a2l(tmp_path: Path) -> None:
    """LLR-171.2, .2b (HLR-171a, ruling Q4, ``p04`` 10): an A2L-only project
    P → 3 A2L tags, the open project is P with ``current_project_dir``
    equal to ``W/P`` textually, ``current_a2l_path`` equal to
    ``W/P/firmware.a2l`` textually (the project's own file), 0 new files
    under ``W/temp``, 0 lines holding "No supported files".

    RED (base, P-12): "No supported files in project: P". Negative control:
    attaching through ``load_a2l_from_path`` → a ``W/temp`` copy."""
    base = tmp_path / "app"
    _a2l_only_project(base)
    workarea = _workarea(base)

    async def _scenario(app, pilot, log):
        temp_before = _temp_files(base)
        messages = await _load_by_name(pilot, app, log, "P")
        return (
            messages,
            _a2l_tags(app),
            app.current_project,
            str(app.current_project_dir),
            str(app.current_a2l_path),
            temp_before,
            _temp_files(base),
        )

    messages, tags, project, project_dir, a2l_path, temp_before, temp_after = projects.run_app(
        base, _scenario
    )
    assert _with(messages, "No supported files") == [], messages
    assert tags == 3, (tags, messages)
    assert project == "P" and project_dir == str(workarea / "P"), (project, project_dir)
    assert a2l_path == str(workarea / "P" / "firmware.a2l"), a2l_path
    assert temp_after == temp_before, (temp_before, temp_after)


def test_tc_b100_32_a2l_only_load_clears_the_previous_data_file(tmp_path: Path) -> None:
    """LLR-171.2a: ``other.s19`` loaded, then the A2L-only P loaded →
    ``current_file`` is None.

    RED (base): P is refused, ``other.s19`` stays loaded. Negative control:
    skipping the reset → ``other.s19`` stays."""
    base = tmp_path / "app"
    _a2l_only_project(base)
    src = projects.copy_sources(tmp_path / "src", projects.CASE02_DIR, "firmware.s19")
    other = src / "other.s19"
    (src / "firmware.s19").rename(other)

    async def _scenario(app, pilot, log):
        await projects.load_image(pilot, app, other)
        messages = await _load_by_name(pilot, app, log, "P")
        return messages, app.current_file, app.current_project

    messages, current_file, project = projects.run_app(base, _scenario)
    assert project == "P", messages
    assert current_file is None, current_file


def test_tc_b100_32_data_file_loaded_into_a2l_only_project_is_recorded(tmp_path: Path) -> None:
    """LLR-171.2c: the A2L-only P open, then Load file ``firmware.s19`` →
    P's ``project.json`` is rewritten with ``active_variant`` "firmware".

    RED (base): P never opens. Negative control: the variant set left None
    on the A2L-only arm → ``project.json`` not rewritten."""
    base = tmp_path / "app"
    project_dir = _a2l_only_project(base)
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        opened = await _load_by_name(pilot, app, log, "P")
        if app.current_project != "P":
            return opened, app.current_project
        app.load_from_path(src / "firmware.s19")
        for _ in range(300):
            if (project_dir / "firmware.s19").exists() and projects.read_manifest(
                project_dir
            ).get("active_variant") == "firmware":
                break
            await pilot.pause()
        return opened, app.current_project

    opened, project = projects.run_app(base, _scenario)
    assert project == "P", ("the A2L-only project did not open", opened)
    manifest = projects.read_manifest(project_dir)
    assert manifest.get("active_variant") == "firmware", manifest
    assert "firmware.s19" in (manifest.get("files") or {}), manifest


@pytest.mark.parametrize("case", ["no data or A2L file", "no project.json"])
def test_tc_b100_32_empty_folder_is_refused_before_any_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """LLR-171.2d / .2e: a folder E holding only ``project.json`` (recording
    an absent ``firmware.s19``) → 1 status message holding "no data or A2L
    file" and "load a file and Save project"; an empty folder E → 1 message
    holding "no project.json" and "load a file and Save project"; in both,
    0 session resets and the open project N stays open.

    RED (base): "No supported files in project: E". Negative controls:
    the old line; the ``no data or A2L file`` branch reached for 2e."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "N", files=("firmware.s19",))
    empty = _workarea(base) / "E"
    empty.mkdir(parents=True)
    if case == "no data or A2L file":
        (empty / "project.json").write_text(
            json.dumps({"schema_version": 1, "active_variant": "firmware",
                        "files": {"firmware.s19": {"size": 1, "sha256": "0" * 64}}}),
            encoding="utf-8",
        )

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app, "N")
        resets = _spy_resets(monkeypatch)
        messages = await _load_by_name(pilot, app, log, "E")
        return messages, len(resets), app.current_project

    messages, resets, project = projects.run_app(base, _scenario)
    assert len(_with(messages, case, "load a file and Save project")) == 1, messages
    assert resets == 0, resets
    assert project == "N", project


@pytest.mark.parametrize("arm", ["link", "over cap", "at cap"])
def test_tc_b100_32_a2l_guard_of_an_a2l_only_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-171.2f (R5, S3-3): ``P/firmware.a2l`` a file symbolic link to an
    outside A2L, no data file → 1 status message holding "link or junction"
    and "replace the A2L file, then Load again", 0 resets, no A2L attached;
    the cap lowered to the A2L's size − 1 → 1 message holding "too large to
    open", 0 resets; the cap at exactly the A2L's size → attached, 3 tags.

    RED (base): "No supported files" for all three (the at-cap arm never
    attaches). Negative controls: no guard → the link's target attached;
    ``>=`` → the at-cap arm refused."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    project_dir = workarea / "P"
    project_dir.mkdir(parents=True)
    (project_dir / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": None}), encoding="utf-8"
    )
    a2l_source = projects.CASE01_DIR / "firmware.a2l"
    size = a2l_source.stat().st_size
    if arm == "link":
        outside = projects.copy_sources(tmp_path / "outside", projects.CASE01_DIR, "firmware.a2l")
        try:
            os.symlink(outside / "firmware.a2l", project_dir / "firmware.a2l")
        except OSError as exc:
            pytest.skip(f"not run: a file link could not be created ({exc})")
    else:
        shutil.copyfile(a2l_source, project_dir / "firmware.a2l")
        cap = size - 1 if arm == "over cap" else size
        monkeypatch.setattr(workspace_module, "DEFAULT_COPY_SIZE_CAP_BYTES", cap)

    async def _scenario(app, pilot, log):
        resets = _spy_resets(monkeypatch)
        messages = await _load_by_name(pilot, app, log, "P")
        return messages, len(resets), app.current_a2l_path, _a2l_tags(app)

    messages, resets, a2l_path, tags = projects.run_app(base, _scenario)
    if arm == "at cap":
        assert tags == 3 and a2l_path is not None, messages
        return
    reason = "link or junction" if arm == "link" else "too large to open"
    assert len(_with(messages, reason, "replace the A2L file, then Load again")) == 1, messages
    assert resets == 0 and a2l_path is None, (resets, a2l_path)


def test_tc_b100_32_over_cap_a2l_beside_a_data_file_is_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.2g (R5): ``firmware.s19`` and an over-cap ``firmware.a2l``
    (cap lowered between the two sizes) → the project opens with the image,
    0 A2L tags, ``current_a2l_path`` None, and the Load-result panel lists
    a "not readable" problem naming ``firmware.a2l`` with "too large to
    open".

    RED (base): the A2L is attached. Negative control: no guard → attached."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.a2l"))
    a2l_size = (projects.CASE01_DIR / "firmware.a2l").stat().st_size
    s19_size = (projects.CASE01_DIR / "firmware.s19").stat().st_size
    assert s19_size < a2l_size - 1, "fixture: the cap must sit between the two sizes"
    monkeypatch.setattr(workspace_module, "DEFAULT_COPY_SIZE_CAP_BYTES", a2l_size - 1)

    async def _scenario(app, pilot, log):
        # The Load project dialog's router: it opens the Load-result panel.
        app._route_load_project("P")
        await projects.wait_for(
            pilot, lambda: app.current_project == "P" and app.current_file is not None,
            "the project load of P",
        )
        facts = (app.current_a2l_path, _a2l_tags(app))
        try:
            panel = await projects.read_load_result_panel(pilot, app)
        except AssertionError as exc:
            panel = f"<{exc}>"
        return facts, panel

    (a2l_path, tags), panel = projects.run_app(base, _scenario)
    assert a2l_path is None and tags == 0, (a2l_path, tags)
    flat = projects.flat(panel)
    assert "not readable" in flat and "firmware.a2l" in flat and "too large to open" in flat, panel


def test_tc_b100_32_unreadable_a2l_row_paints_the_true_next_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.2g / §3 token row (E5 F2, ruling D-3 reversed; probe P-1):
    ``firmware.s19`` and an over-cap ``firmware.a2l`` → the Load-result
    panel's ``not readable`` row for ``firmware.a2l`` paints "replace the
    A2L file, then Load again" and never "Save project to drop it" (Save
    project does not drop the A2L: P-1 loads, saves and loads again and the
    same row is listed). Negative control: the document-record rows keep
    the composer's step (``tests/test_b100_document.py``).

    RED (pre snapshot): "replace the file, or Save project to drop it".
    Mutant: no ``STEP_REPLACE_A2L`` mark on the A2L problem → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19", "firmware.a2l"))
    a2l_size = (projects.CASE01_DIR / "firmware.a2l").stat().st_size
    monkeypatch.setattr(workspace_module, "DEFAULT_COPY_SIZE_CAP_BYTES", a2l_size - 1)

    async def _scenario(app, pilot, log):
        app._route_load_project("P")
        await projects.wait_for(
            pilot, lambda: app.current_project == "P" and app.current_file is not None,
            "the project load of P",
        )
        return await projects.read_load_result_panel(pilot, app)

    flat = projects.flat(projects.run_app(base, _scenario))
    assert "not readable" in flat and "firmware.a2l" in flat, flat
    assert "replace the A2L file, then Load again" in flat, flat
    assert "Save project to drop it" not in flat, flat


# ---------------------------------------------------------------------------
# TC-B100-33 — LLR-171.3, .3a: the Save parent must be this work area
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parent_kind", ["other work area", "outside", "W/patches"])
def test_tc_b100_33_foreign_parent_is_refused_before_any_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_kind: str
) -> None:
    """LLR-171.3: a fresh session with ``firmware.s19`` loaded, Save project
    P under another work area, under a plain outside folder, or under
    ``W/patches`` → 1 status message starting "Project NOT saved", 0
    ``mkdir`` calls at or below the parent (spy), no P there.

    RED (base, C2): the foreign parent is refused after ``mkdir`` (spy 1
    call); ``W/patches/P`` is created. Negative controls: the check after
    ``mkdir``; ``is_relative_to`` → ``W/patches/P`` created."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    if parent_kind == "other work area":
        parent = tmp_path / "other" / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    elif parent_kind == "outside":
        parent = tmp_path / "plain"
    else:
        parent = workarea / "patches"
    parent.mkdir(parents=True, exist_ok=True)
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    calls = _spy_mkdir(monkeypatch, parent)

    async def _scenario(app, pilot, log):
        await projects.load_image(pilot, app, src / "firmware.s19")
        calls.clear()
        return await _save(pilot, app, log, "P", parent=parent)

    messages = projects.run_app(base, _scenario)
    assert [m for m in messages if m.startswith("Project NOT saved")], messages
    assert calls == [], calls
    assert not (parent / "P").exists()


@pytest.mark.parametrize("spelling", ["trailing separator", "upper case", "dot-dot segment", "junction alias"])
def test_tc_b100_33_work_area_under_another_spelling_saves_there(
    tmp_path: Path, spelling: str
) -> None:
    """LLR-171.3a (S3-10): the parent typed as the work area with a trailing
    separator, in upper case, through a ``..`` segment, or as a directory
    junction ``alias`` to it → saved, ``list_projects`` names P exactly
    once, and ``current_project_dir`` equals ``W/P`` textually (never
    ``alias/P``).

    RED (base): the save keeps the typed spelling for ``project_dir``.
    Negative control: a text comparison refuses these spellings."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    workarea.mkdir(parents=True, exist_ok=True)
    if spelling == "trailing separator":
        parent = str(workarea) + os.sep
    elif spelling == "upper case":
        parent = str(workarea).upper()
    elif spelling == "dot-dot segment":
        (workarea / "patches").mkdir(exist_ok=True)
        parent = str(workarea / "patches" / "..")
    else:
        b100_links.require_junctions()
        alias = tmp_path / "alias"
        b100_links.create_junction(alias, workarea)
        parent = str(alias)
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        await projects.load_image(pilot, app, src / "firmware.s19")
        messages = await _save(pilot, app, log, "P", parent=parent)
        return messages, app.list_projects(), str(app.current_project_dir)

    messages, listed, project_dir = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert listed.count("P") == 1, listed
    assert project_dir == str(workarea / "P"), project_dir


# ---------------------------------------------------------------------------
# TC-B100-62 — LLR-171.4c, .4e, .4f, .4g
# ---------------------------------------------------------------------------


def _junction_work_area(tmp_path: Path) -> tuple:
    """This work area with P and P2 (plain projects), ``evil`` (a junction
    into another work area's project R), ``alias`` (a junction to ``W/P``)
    and ``out`` (a junction to a plain outside folder). Returns (base, R)."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    other_r = projects.other_work_area_project(tmp_path / "other", "R")
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    projects.save_case01_project(base, "P2", files=("firmware.s19",))
    workarea = _workarea(base)
    outside = projects.outside_folder(tmp_path)
    b100_links.create_junction(workarea / "evil", other_r)
    b100_links.create_junction(workarea / "alias", workarea / "P")
    b100_links.create_junction(workarea / "out", outside)
    return base, other_r


def test_tc_b100_62_listing_leaves_out_links_and_junctions(tmp_path: Path) -> None:
    """LLR-171.4c: ``evil``, ``alias`` and ``out`` (junctions) → 0 rows;
    the plain projects P and P2 → 1 row each.

    RED (base): the junctions are listed. Negative control: no link check
    → ``alias`` listed."""
    base, _ = _junction_work_area(tmp_path)

    async def _scenario(app, pilot, log):
        return app.list_projects()

    listed = projects.run_app(base, _scenario)
    assert [name for name in listed if name in ("evil", "alias", "out")] == [], listed
    assert listed.count("P") == 1 and listed.count("P2") == 1, listed


@pytest.mark.parametrize("name", ["evil", "alias"])
def test_tc_b100_62_load_refuses_a_junction_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """LLR-171.4e: ``evil`` and ``alias`` picked from a list built before
    the junctions appeared → 0 loads, 0 resets, 1 status message holding
    "link or junction" and "pick a project in the list".

    RED (base): the junction project loads. Negative control: no link
    check → ``alias`` loads."""
    base, _ = _junction_work_area(tmp_path)

    async def _scenario(app, pilot, log):
        resets = _spy_resets(monkeypatch)
        messages = await _load_by_name(pilot, app, log, name)
        return messages, len(resets), app.current_project

    messages, resets, project = projects.run_app(base, _scenario)
    assert len(_with(messages, "link or junction", "pick a project in the list")) == 1, messages
    assert resets == 0 and project is None, (resets, project)


@pytest.mark.parametrize("arm", ["dot-dot name", "two-part name"])
def test_tc_b100_62_load_refuses_a_folder_outside_the_work_area(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-171.4f (S3-7): the picked name ``../../../other/.s19tool/workarea/R``
    (no link), and ``sub/P`` with ``W/sub`` a junction to ``W`` → 0 loads,
    0 resets, 1 status message holding "outside the work area".

    RED (base): both names load. Negative control: no one-component name
    check → both load."""
    base, other_r = _junction_work_area(tmp_path)
    workarea = _workarea(base)
    if arm == "dot-dot name":
        name = os.path.relpath(other_r, workarea)
        assert (workarea / name).exists(), "fixture: the dot-dot name must reach R"
    else:
        b100_links.create_junction(workarea / "sub", workarea)
        name = "sub/P"

    async def _scenario(app, pilot, log):
        resets = _spy_resets(monkeypatch)
        mark = len(log.messages)
        app._handle_load_project(name)
        for _ in range(40):
            await pilot.pause()
        return log.since(mark), len(resets), app.current_project

    messages, resets, project = projects.run_app(base, _scenario)
    assert len(_with(messages, "outside the work area")) == 1, messages
    assert resets == 0 and project is None, (resets, project)


@pytest.mark.parametrize("target_kind", ["new name", "merge target"])
def test_tc_b100_62_save_target_junction_is_refused(tmp_path: Path, target_kind: str) -> None:
    """LLR-171.4g (holds at base, kept through the shared check): ``W/evil``
    typed as the Save project name in a fresh session, and again with
    project P open → 1 status message holding "link or junction" and
    "choose another name", the other work area's project unchanged."""
    base, other_r = _junction_work_area(tmp_path)
    before = projects.tree_digests(other_r)
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scenario(app, pilot, log):
        if target_kind == "merge target":
            await _open_p(pilot, app)
        else:
            await projects.load_image(pilot, app, src / "firmware.s19")
        return await _save(pilot, app, log, "evil")

    messages = projects.run_app(base, _scenario)
    assert len(_with(messages, "link or junction", "choose another name")) == 1, messages
    assert projects.tree_digests(other_r) == before


# ---------------------------------------------------------------------------
# Acceptance — AT-B100-09 / 10 / 11 through keys and dialogs
# ---------------------------------------------------------------------------


async def _at_open_project(pilot, app, name: str) -> None:
    """``1`` (home), ``p`` (Load project dialog), click the project's row,
    click OK; close a Load-result panel if one opens."""
    from textual.widgets import Label

    from s19_app.tui.screens import LoadProjectScreen

    await pilot.press("1")
    for _ in range(4):
        await pilot.pause()
    await pilot.press("p")
    await projects.wait_for(
        pilot, lambda: isinstance(app.screen, LoadProjectScreen), "the Load project dialog"
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    await pilot.pause()
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await projects.wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog to close",
    )
    for _ in range(60):
        if len(app.screen.query(LOAD_RESULT_CLOSE)) > 0:
            await projects.dismiss_load_result_panel(pilot, app)
            break
        await pilot.pause()


async def _at_listed_projects(pilot, app) -> list:
    """Open the Load project dialog by keys, read its rows, cancel it."""
    from textual.widgets import Label

    from s19_app.tui.screens import LoadProjectScreen

    await pilot.press("1")
    for _ in range(4):
        await pilot.pause()
    await pilot.press("p")
    await projects.wait_for(
        pilot, lambda: isinstance(app.screen, LoadProjectScreen), "the Load project dialog"
    )
    rows = [str(item.query_one(Label).render()) for item in app.screen.query("#project_list ListItem")]
    assert await pilot.click("#project_cancel"), "click missed #project_cancel"
    await projects.wait_for(
        pilot, lambda: not isinstance(app.screen, LoadProjectScreen), "the Load project dialog to close"
    )
    return rows


async def _at_save_through_dialog(pilot, app, log, name: str) -> list:
    """``ctrl+s``, type ``name`` into the project name field, click Save;
    wait for the outcome line."""
    from s19_app.tui.screens import SaveProjectScreen

    mark = len(log.messages)
    await pilot.press("ctrl+s")
    await projects.wait_for(
        pilot, lambda: isinstance(app.screen, SaveProjectScreen), "the Save project dialog"
    )
    assert await pilot.click("#project_name"), "click missed #project_name"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*name)
    assert await pilot.click("#save_ok"), "click missed #save_ok"
    await _settle_outcome(pilot, log, mark)
    return log.since(mark)


async def _at_load_file(pilot, app, path: Path) -> None:
    from s19_app.tui.screens import LoadFileScreen

    await pilot.press("l")
    await projects.wait_for(pilot, lambda: isinstance(app.screen, LoadFileScreen), "the Load file dialog")
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(path))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await projects.wait_for(
        pilot, lambda: not isinstance(app.screen, LoadFileScreen), "the Load file dialog to close"
    )


async def _at_flow_picker_rows(pilot, app) -> list:
    """Open Flow Execution and its Import picker through the shipped
    controls; return the picker's rows, then cancel it."""
    from textual.widgets import Button

    app.action_show_screen("flow_execution")
    panel = app.query_one("#fx_panel")
    await projects.wait_for(pilot, lambda: panel.region.height > 0, "the Flow Execution panel")
    panel.query_one("#fx_import", Button).press()
    await projects.wait_for(
        pilot, lambda: len(app.screen.query("#flow_load_cancel")) > 0, "the flow picker"
    )
    rows = [item.name for item in app.screen.query("#flow_list ListItem")]
    app.screen.query_one("#flow_load_cancel", Button).press()
    for _ in range(6):
        await pilot.pause()
    return rows


@pytest.mark.parametrize("size", AT_SIZES)
def test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-171's acceptance scene by keys and dialogs: open P (``1``, ``p``)
    holding ``flows/f1.json``, ``patches/boost.json`` and ``reports/r.md``;
    Save project (``ctrl+s``) typed ``Q`` → Q's folder holds the three files
    byte-equal and the open project is Q; then ``P/flows/f1.json`` is
    removed through the filesystem (A3-10) and the Flow Execution Import
    picker (read from the open project's folder) still lists ``f1``. Both
    reference sizes.

    RED (base ebe6d0c, P-9): Q holds only the top-level files and the
    picker lists nothing."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files=projects.AT09_FILES)
    target = _workarea(base) / "Q"

    async def _scene():
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _at_open_project(pilot, app, "P")
            await projects.wait_for(pilot, lambda: app.current_project == "P", "P open")
            messages = await _at_save_through_dialog(pilot, app, log, "Q")
            (project_dir / "flows" / "f1.json").unlink()
            rows = await _at_flow_picker_rows(pilot, app)
            return messages, app.current_project, rows

    messages, current, rows = asyncio.run(_scene())
    assert _saved(messages), messages
    for relative, payload in projects.AT09_FILES.items():
        assert (target / relative).is_file(), (relative, _files_in(target))
        assert (target / relative).read_bytes() == payload, relative
    assert current == "Q", current
    assert not (project_dir / "flows" / "f1.json").exists()
    assert rows == ["f1"], rows


@pytest.mark.parametrize("size", AT_SIZES)
def test_at_b100_10_a2l_only_project_saves_and_reopens(tmp_path: Path, size: tuple) -> None:
    """HLR-171a's acceptance scene by keys and dialogs: Load file (``l``)
    case_01 ``firmware.a2l`` only; Save project (``ctrl+s``) typed ``P`` →
    P holds ``firmware.a2l`` and ``project.json``. A FRESH app opens P
    through the Load project dialog (``1``, ``p``): 0 lines holding "No
    supported files", 3 A2L tags, the painted Loaded panel names
    ``firmware.a2l``, the session A2L is ``W/P/firmware.a2l`` (the
    project's own file). Then Save project P twice more (LLR-167.6f) → 2
    "Saved project to" lines, 0 holding "already has an A2L file", 1 A2L
    file in P, no ``firmware_1.a2l``. Both reference sizes.

    RED (base, P-12): the reopen paints "No supported files in project: P"."""
    base = tmp_path / "app"
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.a2l")
    workarea = _workarea(base)
    project_dir = workarea / "P"

    async def _save_scene() -> list:
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _at_load_file(pilot, app, src / "firmware.a2l")
            await projects.wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L load")
            return await _at_save_through_dialog(pilot, app, log, "P")

    async def _reopen_scene() -> tuple:
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _at_open_project(pilot, app, "P")
            for _ in range(20):
                await pilot.pause()
            # RP-4 (E4 integration): the panel's own strips are only its
            # background; the slot rows are its child cells, read painted.
            loaded = "\n".join(
                line
                for cell in app.query_one("#loaded_panel").query("Static")
                for line in projects.painted_lines(cell)
            )
            facts = (list(log.messages), _a2l_tags(app), str(app.current_a2l_path), loaded)
            again = []
            if app.current_project == "P":
                again += await _at_save_through_dialog(pilot, app, log, "P")
                again += await _at_save_through_dialog(pilot, app, log, "P")
            return facts, again

    first = asyncio.run(_save_scene())
    assert _saved(first), first
    assert sorted(_files_in(project_dir)) == ["firmware.a2l", "project.json"], _files_in(project_dir)

    (reopen_log, tags, a2l_path, loaded), again = asyncio.run(_reopen_scene())
    assert _with(reopen_log, "No supported files") == [], reopen_log
    assert tags == 3, (tags, reopen_log)
    assert "firmware.a2l" in loaded, loaded
    assert a2l_path == str(project_dir / "firmware.a2l"), a2l_path
    assert sum(1 for m in again if m.startswith(SAVED)) == 2, again
    assert _with(again, "already has an A2L file") == [], again
    names = _files_in(project_dir)
    assert [n for n in names if n.lower().endswith(".a2l")] == ["firmware.a2l"], names


@pytest.mark.parametrize("size", AT_SIZES)
def test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-171b's acceptance scene by keys and dialogs: ``W/evil`` is a
    junction into another work area's project R. Load file (``l``)
    ``firmware.s19``; Save project (``ctrl+s``) typed ``Q`` → saved; the
    Load project dialog (``1``, ``p``) lists ``Q`` once and 0 rows named
    ``evil``; Save project typed ``evil`` → 1 status message holding "link
    or junction", R's files unchanged (0 bytes written outside this work
    area). Both reference sizes.

    RED (base, S-02): ``evil`` is listed."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    other_r = projects.other_work_area_project(tmp_path / "other", "R")
    workarea = _workarea(base)
    workarea.mkdir(parents=True, exist_ok=True)
    b100_links.create_junction(workarea / "evil", other_r)
    before = projects.tree_digests(other_r)
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")

    async def _scene() -> tuple:
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _at_load_file(pilot, app, src / "firmware.s19")
            await projects.wait_for(pilot, lambda: app.current_file is not None, "the image load")
            saved = await _at_save_through_dialog(pilot, app, log, "Q")
            rows = await _at_listed_projects(pilot, app)
            refused = await _at_save_through_dialog(pilot, app, log, "evil")
            return saved, rows, refused

    saved, rows, refused = asyncio.run(_scene())
    assert _saved(saved), saved
    assert rows.count("Q") == 1, rows
    assert "evil" not in rows, rows
    assert len(_with(refused, "link or junction")) == 1, refused
    assert projects.tree_digests(other_r) == before

# ---------------------------------------------------------------------------
# E4 integration — the tester's named gaps, filled (inc-8b/E4-integration-notes.md)
# ---------------------------------------------------------------------------


def _add_pasted_entry(app, address: int = 0x8000007C, run=(0xDE, 0xAD, 0xBE, 0xEF)) -> None:
    """One entry in the session's pasted document (no file behind it)."""
    app._change_service.add_entry(f"0x{address:08X}", "", " ".join(f"{b:02X}" for b in run))


def test_e4_r2_r11_call_order_of_a_save_as(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R2 / R11 (A3R2-1, ``proto-8b-app`` order example): a save as with 2
    sub-folder copies, 1 top-level copy ``a.json`` and a pasted document →
    call order: the sub-folder copy, the document write, the top-level copy,
    the gather, the manifest write (spy); each copy call once.

    Mutant M76: the sub-folder copy moved after the rows loop → ``document``
    precedes ``copy:sub`` → RED; the top-level copy moved before the rows
    loop → ``copy:top`` precedes ``document`` → RED."""
    base = tmp_path / "app"
    projects.build_save_as_project(
        base,
        sub_files={"flows/f1.json": b'{"f": 1}', "reports/r.md": b"r\n"},
        top_files={"a.json": b'{"top": "a"}'},
    )
    events: list = []
    cls = app_module.S19TuiApp
    original_copy = cls._copy_project_subfolders
    original_write = cls._write_editor_document
    original_gather = app_module.gather_project_artifacts
    original_manifest = app_module.write_project_manifest

    def _copy(self, source_dir, project_dir, copies, *args, **kwargs):
        part = "top" if all("/" not in c.relative for c in copies) else "sub"
        events.append(f"copy:{part}:{len(copies)}")
        return original_copy(self, source_dir, project_dir, copies, *args, **kwargs)

    def _write(self, *args, **kwargs):
        events.append("document")
        return original_write(self, *args, **kwargs)

    def _gather(*args, **kwargs):
        events.append("gather")
        return original_gather(*args, **kwargs)

    def _manifest(*args, **kwargs):
        events.append("manifest")
        return original_manifest(*args, **kwargs)

    monkeypatch.setattr(cls, "_copy_project_subfolders", _copy)
    monkeypatch.setattr(cls, "_write_editor_document", _write)
    monkeypatch.setattr(app_module, "gather_project_artifacts", _gather)
    monkeypatch.setattr(app_module, "write_project_manifest", _manifest)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        events.clear()
        _add_pasted_entry(app)
        return await _save(pilot, app, log, "Q")

    messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert events[:5] == ["copy:sub:2", "document", "copy:top:1", "gather", "manifest"], events
    assert (_workarea(base) / "Q" / "patches" / "changes.json").is_file(), _files_in(_workarea(base) / "Q")


def test_e4_r2_pasted_document_beside_a_different_p_file_lands_changes_1(tmp_path: Path) -> None:
    """R2 / LLR-167.6e (pre-ruling 3, ``proto-8b-app`` example): P holds
    ``patches/changes.json`` (other bytes) and the session a pasted
    document, save as Q → Q holds P's file byte-equal at
    ``patches/changes.json`` and the pasted one at
    ``patches/changes_1.json``; 0 lines hold "the plan named".

    Mutant M77: the sub-folder copy after the rows loop → the pasted
    document takes ``changes.json`` and the copy's landing no longer
    matches → the save aborts → RED."""
    base = tmp_path / "app"
    p_changes = projects.change_document_bytes([projects.address_entry(0x80000020, (1, 2))])
    projects.build_save_as_project(base, sub_files={"patches/changes.json": p_changes})

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        _add_pasted_entry(app)
        return await _save(pilot, app, log, "Q")

    messages = projects.run_app(base, _scenario)
    target = _workarea(base) / "Q" / "patches"
    assert _saved(messages), messages
    assert _with(messages, "the plan named") == [], messages
    assert (target / "changes.json").read_bytes() == p_changes
    assert (target / "changes_1.json").is_file(), _files_in(target.parent)
    assert (target / "changes_1.json").read_bytes() != p_changes


def test_e4_r11_f8_identical_firmware_1_in_p_is_copied_not_reused(tmp_path: Path) -> None:
    """R11 / F-8 (``proto-8b-app`` example): P holds ``firmware.s19`` (the
    session image) and ``firmware_1.s19`` byte-identical to the image this
    save emits (a pending patch) → saved, Q holds ``firmware.s19`` (the
    image row) and ``firmware_1.s19`` (the top-level copy), both the
    emitted bytes; 0 lines hold "the plan named".

    Mutant M78: the top-level copy before the rows loop → the image row
    reuses ``Q/firmware_1.s19`` and the save aborts → RED."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files={})

    async def _emit_once(app, pilot, log):
        await _open_p(pilot, app)
        _add_pasted_entry(app)
        return await _save(pilot, app, log, "Q1")

    first = projects.run_app(base, _emit_once)
    assert _saved(first), first
    emitted = (_workarea(base) / "Q1" / "firmware.s19").read_bytes()
    assert emitted != (project_dir / "firmware.s19").read_bytes(), "fixture: the save must emit"
    (project_dir / "firmware_1.s19").write_bytes(emitted)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        _add_pasted_entry(app)
        return await _save(pilot, app, log, "Q")

    messages = projects.run_app(base, _scenario)
    target = _workarea(base) / "Q"
    assert _saved(messages), messages
    assert _with(messages, "the plan named") == [], messages
    assert (target / "firmware.s19").read_bytes() == emitted
    assert (target / "firmware_1.s19").read_bytes() == emitted


def test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts(tmp_path: Path) -> None:
    """R11 / A3R2-5 (``proto-8b-app`` mismatch example, R15): the session
    image is P's ``fw_2.s19`` (image row landing ``Q/fw_2.s19``) and P also
    holds ``fw.s19`` with the same bytes → the top-level copy of ``fw.s19``
    reuses ``Q/fw_2.s19``; the mismatch check aborts: 1 status line holding
    "the plan named" with ``fw.s19`` and ``fw_2.s19``, Q absent after the
    rollback, P's files unchanged.

    Mutant M79: no ``_plan_row_mismatch`` in the top-level copy → saved
    with Q lacking ``fw.s19`` → RED."""
    base = tmp_path / "app"
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    (src / "firmware.s19").rename(src / "fw_2.s19")

    async def _first(app, pilot, log):
        await projects.load_image(pilot, app, src / "fw_2.s19")
        return await _save(pilot, app, log, "P")

    assert _saved(projects.run_app(base, _first))
    project_dir = _workarea(base) / "P"
    shutil.copyfile(project_dir / "fw_2.s19", project_dir / "fw.s19")
    before = projects.tree_digests(project_dir)

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        loaded_name = app.current_file.path.name
        return loaded_name, await _save(pilot, app, log, "Q")

    loaded_name, messages = projects.run_app(base, _scenario)
    assert loaded_name == "fw_2.s19", loaded_name
    lines = _with(messages, "the plan named", "fw.s19", "fw_2.s19")
    assert len(lines) == 1, messages
    assert not _saved(messages), messages
    assert not (_workarea(base) / "Q").exists(), _files_in(_workarea(base) / "Q")
    assert projects.tree_digests(project_dir) == before


def test_e4_r14_top_level_copy_counted_once_in_the_plan_total(tmp_path: Path) -> None:
    """R14 (A3R3-1) through the planner: image row 5 000 bytes, P's
    top-level ``notes.bin`` (5 000 bytes: one ``carried`` row and one copy)
    and ``flows/f.json`` (10 bytes) → ``total_bytes`` 8 192 + 8 192 +
    4 096 + 65 536 = 86 016.

    Mutant M22: the carried row counted in the row sum AND in ``copies`` →
    94 208 → RED."""
    from s19_app.tui.services.project_gather_service import PlannedFile
    from s19_app.tui.services.project_gather_service import inventory_project_tree
    from s19_app.tui.services.project_gather_service import plan_project_save

    project_dir = tmp_path / "r14" / "P"
    projects.write_tree(
        project_dir,
        {"firmware.s19": b"s" * 4000, "notes.bin": b"n" * 5000, "flows/f.json": b"f" * 10},
    )
    image = PlannedFile(role="image", source=project_dir / "firmware.s19",
                        name="firmware.s19", digest="0" * 64, size=5000)
    plan = plan_project_save(
        tmp_path / "r14" / "Q", target_kind="new", files=[image], image="x",
        manifest_keys=(), inventory=inventory_project_tree(project_dir),
    )
    assert plan.refusal is None, plan.refusal
    assert sorted(c.relative for c in plan.copies) == ["flows/f.json", "notes.bin"]
    assert [r.landing.name for r in plan.rows if r.role == "carried"] == ["notes.bin"], plan.rows
    assert plan.total_bytes == 86016, plan.total_bytes


def test_e4_r14_top_level_copy_at_the_free_space_boundary_saves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R14 / LLR-171.1e at the app: P with a top-level ``notes.bin`` of
    100 000 bytes; free space exactly T (the image and ``notes.bin``, each
    rounded up, plus 64 KiB) → saved, Q holds ``notes.bin``.

    Mutant M22: the top-level copy counted twice → T is short by 102 400
    bytes → "not enough free space" → RED."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(
        base, sub_files={}, top_files={"notes.bin": b"n" * 100000}
    )
    total = projects.save_as_total([(project_dir / "firmware.s19").stat().st_size, 100000])
    _patch_free_space(monkeypatch, total)
    messages, _ = _save_as_from_p(base)
    assert _saved(messages), (total, messages)
    assert (_workarea(base) / "Q" / "notes.bin").is_file()


@pytest.mark.parametrize("count", [1, 12])
def test_e4_llr_171_5_unrecorded_gathered_rows_are_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    """LLR-171.5 / LLR-171.7a / M75 (the painting side): the gather reports
    ``count`` copied rows ``project.json`` cannot record (device stems,
    ``GatherOutcome.unrecorded``; injected on the real outcome) → the save
    completes; 1 row → 1 status line naming ``patches/con.json`` with
    "copied but not recorded", "Windows reserves that name" and "rename it
    in the common folder, select the new name, then Save project"; 12 rows
    → 10 such lines and 1 line holding "and 2 more".

    The end-to-end example is the active CRC template named ``con.json``
    (``test_tc_b100_31_crc_template_named_con_json_is_named_unrecorded``,
    E5 F4); a dialog ``batch`` of ``con.json`` cannot reach this line: the
    manifest writer refuses the device-stem ``batch`` entry first
    ("project.json was not written"), see ``E4-integration-notes.md`` I-1.

    Mutant M75: ``unrecorded`` not reported → 0 lines → RED; every row
    painted (no cap) → 12 lines → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    stems = ["con", "prn", "aux", "nul"] + [f"com{i}" for i in range(1, 9)]
    rows = tuple(f"patches/{stem}.json" for stem in stems[:count])
    original = app_module.gather_project_artifacts

    def _gather(*args, **kwargs):
        outcome = original(*args, **kwargs)
        outcome.unrecorded = rows
        return outcome

    monkeypatch.setattr(app_module, "gather_project_artifacts", _gather)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        return await _save(pilot, app, log, "P")

    messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    step = "rename it in the common folder, select the new name, then Save project"
    lines = _with(messages, "copied but not recorded", "Windows reserves that name", step)
    if count == 1:
        assert len(lines) == 1 and "patches/con.json" in lines[0], messages
        assert _with(messages, "more files not recorded") == [], messages
    else:
        assert len(lines) == 10, messages
        assert len(_with(messages, "and 2 more")) == 1, messages


def test_e4_llr_171_2g_linked_a2l_beside_a_mac_is_never_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.2g (S3R2-3) MAC arm / M54: P holds ``firmware.mac`` and a
    ``firmware.a2l`` that is a file symbolic link to an outside A2L → the
    project opens with the MAC, 0 calls of ``_load_a2l_data_with_cache``
    and ``parse_a2l_file`` with a path named ``firmware.a2l`` (spy), the
    session holds no A2L, and the Load-result panel names ``firmware.a2l``
    as "not readable" with "link or junction".

    Mutant M54: the A2L list cleared only for ``choose_install_set`` → the
    MAC load parses the A2L → 1+ spy calls → RED."""
    base = tmp_path / "app"
    project_dir = projects.save_case01_project(base, "P", files=("firmware.mac",))
    outside = projects.copy_sources(tmp_path / "outside", projects.CASE01_DIR, "firmware.a2l")
    try:
        os.symlink(outside / "firmware.a2l", project_dir / "firmware.a2l")
    except OSError as exc:
        pytest.skip(f"not run: a file symbolic link could not be created here ({exc})")
    parsed: list = []
    cls = app_module.S19TuiApp
    original_cache = cls._load_a2l_data_with_cache
    original_parse = app_module.parse_a2l_file

    def _cache(self, path, *args, **kwargs):
        if path is not None and Path(path).name == "firmware.a2l":
            parsed.append(("cache", str(path)))
        return original_cache(self, path, *args, **kwargs)

    def _parse(path, *args, **kwargs):
        if Path(path).name == "firmware.a2l":
            parsed.append(("parse", str(path)))
        return original_parse(path, *args, **kwargs)

    monkeypatch.setattr(cls, "_load_a2l_data_with_cache", _cache)
    monkeypatch.setattr(app_module, "parse_a2l_file", _parse)

    async def _scenario(app, pilot, log):
        parsed.clear()
        app._route_load_project("P")
        await projects.wait_for(
            pilot, lambda: app.current_project == "P" and app.current_file is not None,
            "the project load of P",
        )
        facts = (app.current_a2l_path, _a2l_tags(app), bool(app.current_file.mac_records))
        panel = await projects.read_load_result_panel(pilot, app)
        return facts, panel

    (a2l_path, tags, has_mac), panel = projects.run_app(base, _scenario)
    assert parsed == [], parsed
    assert a2l_path is None and tags == 0 and has_mac, (a2l_path, tags, has_mac)
    flat = projects.flat(panel)
    assert "not readable" in flat and "firmware.a2l" in flat and "link or junction" in flat, panel


def test_e4_llr_171_1m_document_inside_p_follows_its_copy(tmp_path: Path) -> None:
    """LLR-171.1m (R9) / M41: P records the document ``patches/boost.json``
    (bound to ``W/P/patches/boost.json`` after the load), save as Q → the
    Patch Editor document's ``source_path`` is ``W/Q/patches/boost.json``
    (textually) and that file holds P's bytes.

    Mutant M41: no rebind → ``source_path`` stays under P → RED."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    workarea.mkdir(parents=True, exist_ok=True)
    project_dir = projects.seed_document_project(workarea, "P")
    p_bytes = (project_dir / "patches" / "boost.json").read_bytes()

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        bound = app._change_service.document.source_path
        messages = await _save(pilot, app, log, "Q")
        return bound, app._change_service.document.source_path, messages

    bound, rebound, messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert os.path.normcase(str(bound)) == os.path.normcase(
        str(workarea / "P" / "patches" / "boost.json")
    ), bound
    assert os.path.normcase(str(rebound)) == os.path.normcase(
        str(workarea / "Q" / "patches" / "boost.json")
    ), rebound
    assert Path(rebound).read_bytes() == p_bytes


@pytest.mark.parametrize("arm", ["skipped junction", "dot-dot"])
def test_e4_llr_171_1m_rebind_only_to_a_plan_entry(tmp_path: Path, arm: str) -> None:
    """LLR-171.1m (S3R2-5): a document whose ``source_path`` is under P only
    through a skipped junction (``P/linked/x.json``) or through a ``..``
    part (``P/../elsewhere/x.json``) keeps its binding after a save as.

    Mutant M80: a rebind by text, without the plan-entry / ``..`` checks →
    ``source_path`` moves under Q → RED."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files={})
    if arm == "skipped junction":
        b100_links.require_junctions()
        outside = projects.outside_folder(tmp_path / "o")
        (outside / "x.json").write_bytes(projects.change_document_bytes())
        projects.add_junctions(project_dir, outside, ["linked"])
        planted = project_dir / "linked" / "x.json"
    else:
        elsewhere = _workarea(base) / "elsewhere"
        elsewhere.mkdir(parents=True)
        (elsewhere / "x.json").write_bytes(projects.change_document_bytes())
        planted = project_dir / ".." / "elsewhere" / "x.json"

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        app._change_service.document.source_path = planted
        messages = await _save(pilot, app, log, "Q")
        return app._change_service.document.source_path, messages

    after, messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert str(after) == str(planted), after


def test_e4_llr_171_1k_unlistable_folder_refuses_the_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-171.1k (R8, DR-5): ``P/reports/locked`` cannot be listed
    (``os.scandir`` raises ``PermissionError`` for that one folder) → 1
    status line naming ``reports/locked`` with "could not be read" and
    "check that they can be opened, then save again", 0 ``mkdir`` calls at
    or below Q.

    Mutant M81: an unlistable folder skipped silently (the walker's
    ``unreadable`` list ignored) → saved → RED."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files={"reports/locked/r.md": b"r"})
    locked = os.path.normcase(str(project_dir / "reports" / "locked"))
    original = os.scandir

    def _scandir(path="."):
        if os.path.normcase(str(path)) == locked:
            raise PermissionError(13, "Access is denied", str(path))
        return original(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    target = _workarea(base) / "Q"
    calls = _spy_mkdir(monkeypatch, target)
    messages, _ = _save_as_from_p(base)
    lines = _with(messages, "could not be read", "check that they can be opened, then save again")
    assert len(lines) == 1 and "reports/locked" in lines[0], messages
    assert calls == [] and not target.exists(), calls


@pytest.mark.parametrize("name", ["CON.txt", "lpt1.json", "CONOUT$.md"])
def test_e4_llr_171_1k_reserved_device_names_refuse_the_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """LLR-171.1k (S3R2-6): ``P/flows/<device stem>`` (made through the
    extended-length form) → 1 status line naming ``flows/<name>`` with
    "could not be read", 0 ``mkdir`` calls at or below Q.

    Mutant M82: reserved stems not classified unreadable → the copy reads
    the device or saves without the file → RED."""
    if sys.platform != "win32":
        pytest.skip("reserved device names are a Windows-only arm")
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    path = project_dir / "flows" / name
    try:
        try:
            projects.write_unnormalised(path)
        except OSError as exc:
            pytest.skip(f"not run: the platform refused the name ({exc})")
        target = _workarea(base) / "Q"
        calls = _spy_mkdir(monkeypatch, target)
        messages, _ = _save_as_from_p(base)
        lines = _with(messages, "could not be read")
        assert len(lines) == 1 and f"flows/{name}" in lines[0], messages
        assert calls == [] and not target.exists(), calls
    finally:
        projects.remove_unnormalised(path)


def test_e4_a3_13_refusal_precedence_in_the_plan(tmp_path: Path) -> None:
    """A3-13 through the planner: a tree that is too deep (33 parts), holds
    an unreadable top-level entry (a trailing dot, classified before the
    walk reaches the deep folder) and a file over the cap → the
    passed refusal wins first; without it the depth refusal; with the deep
    file removed the unreadable refusal; with the unreadable entry removed
    the cap refusal.

    Mutant M83: the cap checked before the walk refusals → "too large to
    copy" on the earlier arms → RED."""
    if sys.platform != "win32":
        pytest.skip("trailing-dot names are a Windows-only arm")
    from s19_app.tui.services.project_gather_service import inventory_project_tree
    from s19_app.tui.services.project_gather_service import plan_project_save

    project_dir = tmp_path / "prec" / "P"
    projects.write_tree(project_dir, {"splits/big.bin": b"b" * 2048})
    deep = projects.deep_file(project_dir, 33)
    odd = project_dir / "x.json."
    odd.parent.mkdir(parents=True, exist_ok=True)
    try:
        projects.write_unnormalised(odd)
    except OSError as exc:
        pytest.skip(f"not run: the platform refused a trailing-dot name ({exc})")

    def _refusal(passed=None) -> str:
        return plan_project_save(
            tmp_path / "prec" / "Q", target_kind="new", files=[], image="none",
            manifest_keys=(), refusal=passed,
            inventory=inventory_project_tree(project_dir), size_cap=1024,
        ).refusal or ""

    try:
        assert _refusal("first refusal") == "first refusal"
        assert "nested too deep" in _refusal(), _refusal()
        project_dir.joinpath(*deep.split("/")).unlink()
        assert "could not be read" in _refusal(), _refusal()
        projects.remove_unnormalised(odd)
        last = _refusal()
        assert "splits/big.bin" in last and "too large to copy" in last, last
    finally:
        projects.remove_unnormalised(odd)


def test_e4_token_row_9_open_project_swapped_for_a_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Token row 9 (S3-6): P open, then ``W/P`` swapped for a junction to a
    copy of P outside the work area, save as Q → 1 status line holding
    "the open project folder" with ``'P'``, "is a link or junction" and
    "pick a project in the list"; 0 ``mkdir`` calls at or below Q; the
    outside copy unchanged.

    Mutant M84: no source check before the walk → the junction's target is
    walked and copied into Q → saved → RED."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    outside = tmp_path / "outside-P"
    shutil.copytree(project_dir, outside)
    outside_before = projects.tree_digests(outside)
    target = _workarea(base) / "Q"

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        project_dir.rename(project_dir.with_name("P-moved"))
        b100_links.create_junction(project_dir, outside)
        calls = _spy_mkdir(monkeypatch, target)
        messages = await _save(pilot, app, log, "Q")
        return messages, list(calls)

    try:
        messages, calls = projects.run_app(base, _scenario)
    finally:
        _rmdir_quiet(project_dir)
    lines = _with(
        messages, "the open project folder", "'P'", "is a link or junction",
        "pick a project in the list",
    )
    assert len(lines) == 1, messages
    assert calls == [] and not target.exists(), calls
    assert projects.tree_digests(outside) == outside_before


# ---------------------------------------------------------------------------
# E5 corrective pass 1 (LED .80): F1, F3, F4, F5, F7(a), SEC8b-1..3, M24, M35
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arm", ["gone, save as P", "gone, save as Q", "present, save as Q"])
def test_tc_b100_31_open_project_folder_gone_saves_without_a_copy(
    tmp_path: Path, arm: str
) -> None:
    """LLR-171.1n (F1, probe P-4): P open, the session image loaded from
    outside P, then ``W/P`` moved away outside the app; Save project under
    P's own name or as Q → "Saved project to", the target holds the
    session image byte-equal, the open project is the target, and exactly 1
    line holds "The open project folder 'P' was not found", "its other files
    were not copied" and "copy them into '<target>'"; 0 lines hold "could
    not be read". Negative control: P still present, save as Q → 0 such
    lines (a save as copies P).

    RED (pre snapshot): "'P' could not be read — check that they can be
    opened, then save again", no folder. Mutant: the helper ignores whether
    P's folder exists → the same refusal → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    gone = arm.startswith("gone")
    name = "P" if arm.endswith("P") else "Q"

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        await projects.load_image(pilot, app, src / "firmware.s19")
        if gone:
            shutil.move(str(_workarea(base) / "P"), str(tmp_path / "P_moved"))
        messages = await _save(pilot, app, log, name)
        return messages, app.current_project

    messages, current = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    assert current == name, (current, messages)
    saved = _workarea(base) / name / "firmware.s19"
    assert saved.read_bytes() == (src / "firmware.s19").read_bytes()
    lines = _with(
        messages, "The open project folder 'P' was not found",
        "its other files were not copied", f"copy them into '{name}'",
    )
    assert len(lines) == (1 if gone else 0), messages
    assert _with(messages, "could not be read") == [], messages


def test_tc_b100_32_unload_of_an_a2l_only_session_clears_the_a2l(tmp_path: Path) -> None:
    """F3 (I-2, probe P-3): an A2L-only project P open (3 tags, no image);
    the A2L slot's unload → ``current_a2l_path`` None, 0 tags, the status
    "Unloaded A2L.", 0 lines "Nothing to unload.".

    RED (pre snapshot): "Nothing to unload.", the A2L stays attached.
    Mutant: no A2L-only branch → RED."""
    base = tmp_path / "app"
    _a2l_only_project(base)

    async def _scenario(app, pilot, log):
        app._handle_load_project("P")
        await projects.wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L")
        tags_before = _a2l_tags(app)
        mark = len(log.messages)
        app._apply_unload("a2l")
        await pilot.pause()
        return tags_before, app.current_a2l_path, _a2l_tags(app), log.since(mark)

    tags_before, after, tags_after, lines = projects.run_app(base, _scenario)
    assert tags_before == 3, tags_before
    assert after is None and tags_after == 0, (after, tags_after, lines)
    assert "Unloaded A2L." in lines and "Nothing to unload." not in lines, lines


@pytest.mark.skipif(
    sys.platform != "win32", reason="not run: a con.json file needs the Windows extended spelling"
)
def test_tc_b100_31_crc_template_named_con_json_is_named_unrecorded(tmp_path: Path) -> None:
    """LLR-171.5 end-to-end example (F4, probe P-2): the active CRC template
    is an outside file named ``con.json`` → saved, exactly 1 line naming
    ``templates/con.json`` with "copied but not recorded", "Windows reserves
    that name" and "rename it in the common folder, select the new name,
    then Save project"; 0 raises. Negative control: no template → 0 such
    lines (every other save node)."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    outside = tmp_path / "tpl"
    outside.mkdir()
    template = outside / "con.json"
    with open(projects.EXTENDED_PREFIX + str(template), "wb") as handle:
        handle.write(b'{"crc": 1}\n')

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        app._last_template_path = template
        return await _save(pilot, app, log, "P")

    try:
        messages = projects.run_app(base, _scenario)
    finally:
        projects.remove_unnormalised(template)
    step = "rename it in the common folder, select the new name, then Save project"
    lines = _with(messages, "copied but not recorded", "Windows reserves that name", step)
    assert _saved(messages), messages
    assert len(lines) == 1 and "templates/con.json" in lines[0], messages


def test_tc_b100_31_unrecorded_name_reason_is_not_too_long(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Token row 8 (F4 b): a gathered row ``project.json`` cannot record for
    a reason other than a reserved device name (injected on the real
    outcome) → 1 line holding "copied but not recorded" and "the name is not
    one project.json records"; 0 lines hold "too long" (no length rule
    exists)."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    original = app_module.gather_project_artifacts

    def _gather(*args, **kwargs):
        outcome = original(*args, **kwargs)
        outcome.unrecorded = ("templates/trailing .json",)
        return outcome

    monkeypatch.setattr(app_module, "gather_project_artifacts", _gather)

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        return await _save(pilot, app, log, "P")

    messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    lines = _with(messages, "copied but not recorded", "the name is not one project.json records")
    assert len(lines) == 1, messages
    assert _with(messages, "too long") == [], messages


def test_tc_b100_31_identical_copy_mismatch_names_a_true_step(tmp_path: Path) -> None:
    """F5 (a) (A3R2-5 example): the session image is P's ``fw_2.s19`` and P
    also holds ``fw.s19`` with the same bytes → refused with 1 line holding
    "the plan named", "fw_2.s19 already holds the same bytes as fw.s19" and
    "remove the duplicate copy from the open project folder 'P', then save
    again"; it does not end with "— save again." (that step repeats the
    refusal). Q absent.

    RED (pre snapshot): the line ends "— save again."."""
    base = tmp_path / "app"
    src = projects.copy_sources(tmp_path / "src", projects.CASE01_DIR, "firmware.s19")
    (src / "firmware.s19").rename(src / "fw_2.s19")

    async def _first(app, pilot, log):
        await projects.load_image(pilot, app, src / "fw_2.s19")
        return await _save(pilot, app, log, "P")

    assert _saved(projects.run_app(base, _first))
    project_dir = _workarea(base) / "P"
    shutil.copyfile(project_dir / "fw_2.s19", project_dir / "fw.s19")

    async def _scenario(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        return await _save(pilot, app, log, "Q")

    messages = projects.run_app(base, _scenario)
    lines = _with(
        messages, "the plan named", "fw_2.s19 already holds the same bytes as fw.s19",
        "remove the duplicate copy from the open project folder 'P', then save again",
    )
    assert len(lines) == 1, messages
    assert not lines[0].endswith("— save again."), lines
    assert not (_workarea(base) / "Q").exists()


def test_tc_b100_31_document_with_an_identical_sibling_follows_its_landing(
    tmp_path: Path,
) -> None:
    """F5 (b) / LLR-171.1m: P records the document ``patches/changes.json``
    and also holds ``patches/changes_1.json`` with the same bytes; save as Q
    → saved; Q's ``active_document`` names a file Q holds; the Patch
    Editor's ``source_path`` is that file in Q (it exists and holds the
    document's bytes) — never the planned name the gather did not write.

    RED (pre snapshot): ``source_path`` is ``W/Q/patches/changes.json``,
    which does not exist (the gather reused ``changes_1.json``)."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    workarea.mkdir(parents=True, exist_ok=True)
    project_dir = projects.seed_document_project(workarea, "P", document="patches/changes.json")
    document_bytes = (project_dir / "patches" / "changes.json").read_bytes()
    shutil.copyfile(
        project_dir / "patches" / "changes.json", project_dir / "patches" / "changes_1.json"
    )

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        messages = await _save(pilot, app, log, "Q")
        return app._change_service.document.source_path, messages

    rebound, messages = projects.run_app(base, _scenario)
    assert _saved(messages), messages
    recorded = projects.read_manifest(workarea / "Q").get("active_document")
    assert recorded and (workarea / "Q" / recorded).is_file(), (recorded, _files_in(workarea / "Q"))
    assert Path(rebound).is_file(), rebound
    assert os.path.normcase(str(rebound)) == os.path.normcase(str(workarea / "Q" / recorded)), rebound
    assert Path(rebound).read_bytes() == document_bytes


@pytest.mark.parametrize("side", ["load", "save target"])
def test_tc_b100_62_folder_check_permission_error_has_its_own_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: str
) -> None:
    """F7 (a): ``lstat`` of ``W/P`` raises ``PermissionError`` → the load
    paints "'P' could not be read — check that the folder can be opened,
    then load again"; the Save project target paints "'P' could not be read
    — check that the folder can be opened, then save again"; 0 lines hold
    "outside the work area" or "is not the work area folder"; nothing
    loaded, nothing saved.

    RED (pre snapshot): the "outside" texts. Mutant: the OSError mapped to
    "outside" again → RED."""
    from s19_app.tui.screens import SaveProjectPayload

    base = tmp_path / "app"
    projects.save_case01_project(base, "P", files=("firmware.s19",))
    denied = os.path.normcase(str(_workarea(base) / "P"))
    original = os.lstat

    def _lstat(path, *args, **kwargs):
        if os.path.normcase(str(path)) == denied:
            raise PermissionError(13, "denied", str(path))
        return original(path, *args, **kwargs)

    async def _scenario(app, pilot, log):
        if side == "save target":
            await projects.load_image(pilot, app, projects.CASE01_DIR / "firmware.s19")
        mark = len(log.messages)
        monkeypatch.setattr(app_module.os, "lstat", _lstat)
        try:
            if side == "load":
                app._handle_load_project("P")
            else:
                app._handle_save_dialog(
                    SaveProjectPayload(parent_folder=str(app.workarea), project_name="P")
                )
        finally:
            monkeypatch.setattr(app_module.os, "lstat", original)
        for _ in range(6):
            await pilot.pause()
        return log.since(mark), app.current_project

    messages, current = projects.run_app(base, _scenario)
    verb = "load again" if side == "load" else "save again"
    lines = _with(messages, "'P' could not be read", f"check that the folder can be opened, then {verb}")
    assert len(lines) == 1, messages
    assert _with(messages, "outside the work area") == [], messages
    assert _with(messages, "is not the work area folder") == [], messages
    assert not _saved(messages) and current is None, (current, messages)


def _rollback_swap_scenario(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str) -> tuple:
    """SEC8b-1 fixture (probe B3): P holds ``reports/z0..z5.md`` beside the
    reference files; right after the last ``reports`` placement lands,
    ``swap`` happens and that call fails. Returns (messages, R's reports
    digests before, R's reports folder, swap state, the report names)."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    for i in range(6):
        (project_dir / "reports" / f"z{i}.md").write_bytes(f"report {i}".encode())
    names = sorted(p.name for p in (project_dir / "reports").iterdir() if p.is_file())
    other = _workarea(base) / "R" / "reports"
    other.mkdir(parents=True)
    for n in names:
        (other / n).write_bytes(b"R_USER_FILE")
    before = projects.tree_digests(other)
    original = app_module.place_into_workarea
    state: dict = {}

    def _swap(source, destination, *args, **kwargs):
        placed = original(source, destination, *args, **kwargs)
        if Path(destination).name == "reports" and Path(source).name == names[-1] and not state:
            q_reports = Path(destination)
            moved = q_reports.parent / "reports_old"
            state["moved"] = moved
            if swap == "junction to R":
                os.rename(q_reports, moved)
                b100_links.create_junction(q_reports, other)
                state["link"] = q_reports
            elif swap == "junction to itself":
                os.rename(q_reports, moved)
                b100_links.create_junction(q_reports, moved)
                state["link"] = q_reports
            else:  # a user's file of the same name moved in over Q's copy
                os.replace(other / names[0], q_reports / names[0])
            raise PermissionError(13, "injected failure after the swap")
        return placed

    monkeypatch.setattr(app_module, "place_into_workarea", _swap)
    try:
        messages, _current = _save_as_from_p(base)
    finally:
        if "link" in state:
            _rmdir_quiet(state["link"])
    return messages, before, other, state, names


@pytest.mark.parametrize("swap", ["junction to R", "junction to itself", "replaced file"])
def test_tc_b100_31_rollback_never_deletes_through_a_swapped_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str
) -> None:
    """SEC8b-1 (probe B3): a save as fails after ``Q/reports`` changed.
    (a) ``Q/reports`` → a junction to another project's ``R/reports`` →
    R's files unchanged; (b) → a junction to Q's own moved folder → the
    copies kept under ``reports_old``; (c) a user's file moved over
    ``Q/reports/<first>`` → that file kept with its bytes. Each arm: 1 line
    holding "Not removed after the failed save" and "a folder changed while
    saving"; 0 "WinError".

    RED (pre snapshot): (a) R's files deleted; (b) the copies deleted
    through the junction; (c) the user's file deleted. Mutants: the reparse
    check removed → (b) RED; the identity check removed → (c) RED; both →
    (a) RED."""
    b100_links.require_junctions()
    messages, before, other, state, names = _rollback_swap_scenario(tmp_path, monkeypatch, swap)
    assert not _saved(messages), messages
    if swap == "junction to R":
        assert projects.tree_digests(other) == before, "another project's files were deleted"
    elif swap == "junction to itself":
        kept = sorted(p.name for p in state["moved"].iterdir() if p.is_file())
        assert kept == names, kept
    else:
        q_file = state["moved"].parent / "reports" / names[0]
        assert q_file.is_file(), "the user's moved-in file was deleted"
        assert q_file.read_bytes() == b"R_USER_FILE", q_file.read_bytes()
    assert _with(messages, "Not removed after the failed save", "a folder changed while saving"), messages
    assert _with(messages, "WinError") == [], messages


def test_tc_b100_31_copy_refuses_when_p_itself_becomes_a_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC8b-2 (probe B7): between the plan and the copy, ``W/P`` is moved
    away and replaced by a junction to a look-alike folder outside every
    work area (same names, other bytes) → refused with "changed while
    saving"; Q absent.

    RED (pre snapshot): saved, Q holds the look-alike's bytes. Mutant: the
    source check back to ``contained_in_workarea(source, source_dir)`` only
    → saved → RED."""
    b100_links.require_junctions()
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base)
    look = tmp_path / "lookalike"
    shutil.copytree(project_dir, look)
    for item in look.rglob("*"):
        if item.is_file():
            item.write_bytes(b"OUTSIDE_MARKER")
    original = app_module.S19TuiApp._copy_project_subfolders
    state: dict = {}

    def _swap(self, source_dir, *args, **kwargs):
        if not state:
            state["done"] = True
            os.rename(project_dir, project_dir.with_name("P_moved"))
            b100_links.create_junction(project_dir, look)
        return original(self, source_dir, *args, **kwargs)

    monkeypatch.setattr(app_module.S19TuiApp, "_copy_project_subfolders", _swap)
    try:
        messages, _current = _save_as_from_p(base)
    finally:
        _rmdir_quiet(project_dir)
    target = _workarea(base) / "Q"
    assert not _saved(messages), messages
    assert _with(messages, "changed while saving"), messages
    assert not target.exists(), _files_in(target)


def test_tc_b100_31_linked_project_json_is_not_carried(tmp_path: Path) -> None:
    """SEC8b-3 (probe E1): after the load, ``P/project.json`` is replaced by
    a file link to an outside manifest whose ``batch`` is
    ``["OUTSIDE_BATCH_NAME.s19"]`` → save as Q saves; Q's ``batch`` does not
    hold the outside name; 1 line names ``project.json`` as a link not
    copied.

    RED (pre snapshot): Q's ``batch`` = the outside value. Mutant: the
    ``lstat`` check removed → RED."""
    base = tmp_path / "app"
    project_dir = projects.build_save_as_project(base, sub_files={})
    manifest = json.loads((project_dir / "project.json").read_text(encoding="utf-8"))
    manifest["batch"] = ["OUTSIDE_BATCH_NAME.s19"]
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    link = project_dir / "project.json"

    async def _scenario(app, pilot, log):
        await _open_p(pilot, app)
        os.rename(link, project_dir / "project.json.orig")
        try:
            os.symlink(outside / "project.json", link)
        except OSError as exc:
            return None, str(exc)
        return await _save(pilot, app, log, "Q"), None

    messages, skipped = projects.run_app(base, _scenario)
    if skipped is not None:
        pytest.skip(f"not run: a file link could not be created ({skipped})")
    assert _saved(messages), messages
    written = projects.read_manifest(_workarea(base) / "Q")
    assert "OUTSIDE_BATCH_NAME.s19" not in (written.get("batch") or []), written
    assert _with(messages, LINK_LINE, "project.json"), messages


def test_tc_b100_59_merge_and_open_targets_plan_no_copy(tmp_path: Path) -> None:
    """LLR-171.1g through the planner (M24 isolated): the same inventory
    with no file row (so no second-companion refusal can mask the arm) →
    for a ``merge`` and an ``open project`` target: refusal None, 0
    folders, 0 copies; for a ``new`` target the copies are listed.

    Mutant M24 (``copying = inventory is not None``) → merge copies ≠ () →
    RED."""
    from s19_app.tui.services.project_gather_service import PLAN_TARGET_MERGE
    from s19_app.tui.services.project_gather_service import PLAN_TARGET_NEW
    from s19_app.tui.services.project_gather_service import PLAN_TARGET_OPEN
    from s19_app.tui.services.project_gather_service import inventory_project_tree
    from s19_app.tui.services.project_gather_service import plan_project_save

    project_dir = tmp_path / "m24" / "P"
    projects.write_tree(project_dir, {"flows/f.json": b"{}", "patches/a.json": b"{}"})
    inventory = inventory_project_tree(project_dir)
    new = plan_project_save(
        tmp_path / "m24" / "Q", target_kind=PLAN_TARGET_NEW, files=[], image="none",
        manifest_keys=(), inventory=inventory,
    )
    assert sorted(c.relative for c in new.copies) == ["flows/f.json", "patches/a.json"]
    for kind in (PLAN_TARGET_MERGE, PLAN_TARGET_OPEN):
        plan = plan_project_save(
            project_dir, target_kind=kind, files=[], image="none",
            manifest_keys=(), inventory=inventory,
        )
        assert plan.refusal is None, (kind, plan.refusal)
        assert plan.folders == () and plan.copies == (), (kind, plan.folders, plan.copies)


def test_tc_b100_31_walker_stops_before_sorting_a_huge_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R16 / R13 (M35, G-5): one folder of 1 050 files walked with
    ``max_entries=1 000`` → the walker sorts at most 1 001 entries (a spy on
    the module's ``sorted``) and yields at most 1 001 paths — it never reads
    and sorts the whole folder.

    Mutant M35 (no early stop) → ``sorted`` receives 1 050 entries → RED."""
    folder = tmp_path / "huge"
    folder.mkdir()
    for i in range(1050):
        (folder / f"f{i:04d}.txt").write_bytes(b"")
    sizes: list = []

    def _sorted(items, *args, **kwargs):
        items = list(items)
        sizes.append(len(items))
        return sorted(items, *args, **kwargs)

    monkeypatch.setattr(workspace_module, "sorted", _sorted, raising=False)
    walked = list(workspace_module.walk_tree_no_links(folder, max_entries=1000))
    assert sizes and max(sizes) <= 1001, sizes
    assert len(walked) <= 1001, len(walked)
